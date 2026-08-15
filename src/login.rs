//! Headless OIDC PKCE login against an MCPG federation (or any
//! RFC-conformant OIDC provider), plus the credentials file it maintains.
//!
//! Mirrors the browser-driven flow in the CP UI but runs from a
//! terminal: opens a browser, listens on `localhost:0` for the
//! redirect, exchanges the code for tokens, verifies the
//! id_token under the federation's JWKS, and stores the tokens +
//! `mcpg_license_jwt` in `<state_dir>/credentials.json`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::oidc::{OidcClient, PkcePair, random_state};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::info;
use url::Url;

/// Persisted credentials. Written to `<state_dir>/credentials.json`
/// with `0600` perms on Unix.
#[derive(Serialize, Deserialize, Debug)]
pub struct StoredCredentials {
    pub issuer: String,
    pub client_id: String,
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub license_jwt: Option<String>,
    pub email: Option<String>,
    pub stored_at: chrono::DateTime<chrono::Utc>,
}

pub async fn run(
    state_dir: &Path,
    issuer_url: &str,
    client_id: &str,
    no_browser: bool,
) -> anyhow::Result<()> {
    let issuer: Url = issuer_url.parse()?;
    println!("{} login", crate::client::program_invocation());
    println!("  issuer:    {}", issuer);
    println!("  client_id: {client_id}");

    // ─── 1. Bind a one-shot listener for the OIDC callback. ───
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    let redirect_uri = format!("http://{local_addr}/callback");

    // ─── 2. Generate PKCE + state. ───
    let pkce = PkcePair::generate();
    let state = random_state();

    // ─── 3. Build the OIDC client and the authorize URL. ───
    let client = OidcClient::new(
        issuer.clone(),
        client_id.to_owned(),
        None, // public client; no secret
        redirect_uri.clone(),
    );
    let authorize_url = client
        .authorize_url(&pkce, &state, &["openid", "email", "profile"])
        .await?;

    // ─── 4. Open the browser (or print). ───
    if no_browser {
        println!("\n  → Open this URL to sign in:\n    {authorize_url}\n");
    } else {
        println!("\n  → Opening browser…");
        if let Err(e) = webbrowser::open(authorize_url.as_str()) {
            eprintln!("  ! browser open failed: {e}");
            println!("    paste this URL manually:\n    {authorize_url}");
        }
    }

    // ─── 5. Wait for the callback. ───
    let (tx, rx) = oneshot::channel::<CallbackParams>();
    let listener_task = tokio::spawn(serve_callback(listener, local_addr, tx));

    let cb = tokio::time::timeout(Duration::from_secs(300), rx).await??;
    listener_task.abort();
    let _ = listener_task.await; // best-effort cleanup

    if cb.state != state {
        anyhow::bail!("OIDC state mismatch — possible CSRF, bailing");
    }
    let code = cb
        .code
        .ok_or_else(|| anyhow::anyhow!("no code in callback"))?;

    // ─── 6. Exchange code for tokens. ───
    let tokens = client.exchange_code(&code, &pkce.verifier).await?;

    // ─── 7. Verify the id_token against the federation JWKS. ───
    let id_claims = client.verify_id_token(&tokens.id_token).await?;
    let email = id_claims.email.clone();
    info!(?email, sub = %id_claims.sub, "id_token verified");

    // License JWT verification (optional — vanilla OIDC providers
    // omit it). Display-only decode of plan + tenant: full entitlement
    // enforcement (including the lic_ver schema gate) is the CP's job;
    // the CLI just shows the operator what they signed in as.
    if let Some(license) = tokens.mcpg_license_jwt.as_deref() {
        #[derive(Deserialize)]
        struct LicensePreview {
            plan: String,
            tenant_slug: String,
        }
        match client
            .verify_signed_claims::<LicensePreview>(license, &["mcpg-cp"], true)
            .await
        {
            Ok(c) => {
                println!("  ✓ license:   plan={} tenant={}", c.plan, c.tenant_slug);
            }
            Err(e) => {
                eprintln!("  ! license verify failed: {e}");
            }
        }
    } else {
        println!("  · provider returned no MCPG license — using id_token only");
    }

    // ─── 8. Persist. ───
    let creds = StoredCredentials {
        issuer: issuer.to_string(),
        client_id: client_id.to_owned(),
        id_token: tokens.id_token.clone(),
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        license_jwt: tokens.mcpg_license_jwt.clone(),
        email,
        stored_at: chrono::Utc::now(),
    };
    let path = state_dir.join("credentials.json");
    let bytes = serde_json::to_vec_pretty(&creds)?;
    // Atomic + 0600-from-creation (shared with the refresh path) — closes the
    // create-with-umask-then-chmod window the initial login used to have.
    write_credentials_file(&path, &bytes)?;

    println!("  ✓ Signed in. Credentials written to {}", path.display());
    Ok(())
}

pub fn logout(state_dir: &Path) -> anyhow::Result<()> {
    let path = state_dir.join("credentials.json");
    if path.exists() {
        std::fs::remove_file(&path)?;
        println!("✓ Removed {}", path.display());
    } else {
        println!("· No stored credentials at {}", path.display());
    }
    Ok(())
}

#[derive(Debug, Default)]
struct CallbackParams {
    code: Option<String>,
    state: String,
    /// Populated when the IdP returns `?error=…`. Surfaced to the
    /// CLI in a future revision; for now the missing-code branch
    /// covers the failure path.
    #[allow(dead_code)]
    error: Option<String>,
}

async fn serve_callback(
    listener: TcpListener,
    addr: SocketAddr,
    tx: oneshot::Sender<CallbackParams>,
) -> anyhow::Result<()> {
    use axum::{Router, extract::Query, response::Html, routing::get};
    use std::collections::HashMap;

    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
    let app = Router::new().route(
        "/callback",
        get({
            let tx = tx.clone();
            move |Query(q): Query<HashMap<String, String>>| async move {
                let params = CallbackParams {
                    code: q.get("code").cloned(),
                    state: q.get("state").cloned().unwrap_or_default(),
                    error: q.get("error").cloned(),
                };
                if let Some(sender) = tx.lock().await.take() {
                    let _ = sender.send(params);
                }
                Html(SUCCESS_HTML)
            }
        }),
    );

    info!(%addr, "listening for OIDC callback");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

const SUCCESS_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Signed in</title>
<style>
  body { font-family: system-ui; max-width: 400px; margin: 5rem auto; text-align: center; }
  .ok  { color: #0a8; font-size: 3rem; }
</style></head>
<body>
  <div class="ok">✓</div>
  <h1>Signed in</h1>
  <p>You can close this tab and return to your terminal.</p>
</body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_is_idempotent_when_no_creds_present() {
        let dir = tempfile::tempdir().unwrap();
        // First call on an empty dir prints "no creds" and returns Ok.
        logout(dir.path()).unwrap();
        // Second call still returns Ok (still no file).
        logout(dir.path()).unwrap();
    }

    #[test]
    fn logout_removes_existing_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        std::fs::write(&path, "{}").unwrap();
        assert!(path.exists());
        logout(dir.path()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn stored_credentials_round_trip_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let creds = StoredCredentials {
            issuer: "https://auth.example".into(),
            client_id: "test-cp".into(),
            id_token: "eyJ.id".into(),
            access_token: "tok".into(),
            refresh_token: Some("rt".into()),
            license_jwt: Some("eyJ.lic".into()),
            email: Some("alice@example.com".into()),
            stored_at: chrono::Utc::now(),
        };
        let path = dir.path().join("credentials.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&creds).unwrap()).unwrap();
        let loaded: StoredCredentials =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(loaded.issuer, creds.issuer);
        assert_eq!(loaded.email.as_deref(), Some("alice@example.com"));
        assert!(loaded.license_jwt.is_some());
    }
}

/// Decode a JWT's `exp` claim WITHOUT verifying — used only on our own
/// stored id_token to decide whether a refresh is due; the CP remains the
/// authoritative verifier of whatever we send.
pub(crate) fn id_token_expiry(token: &str) -> Option<i64> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let exp = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("exp")?
        .clone();
    // `exp` is a JSON NumericDate — usually an integer, but the RFC permits a
    // float. Accept both so a float doesn't read as "no exp" → refresh-on-
    // every-call.
    exp.as_i64().or_else(|| exp.as_f64().map(|f| f as i64))
}

/// Refresh window: renew when the id_token has less than this long to live
/// (covers clock skew + the request's own flight time).
const REFRESH_SKEW_SECS: i64 = 60;

/// Best-effort credential refresh before a CP call: when the stored
/// id_token is expired (or about to) and a `refresh_token` exists, redeem
/// it at the issuer's token endpoint and persist the rotated credentials.
/// Returns `Ok(true)` if refreshed, `Ok(false)` when no refresh was needed
/// or possible (no creds / no refresh_token / provider returned no
/// id_token — the caller proceeds with what it has and the CP's 401 is the
/// authoritative outcome).
pub async fn ensure_fresh(state_dir: &Path) -> anyhow::Result<bool> {
    let path = state_dir.join("credentials.json");
    let Ok(raw) = std::fs::read(&path) else {
        return Ok(false); // not logged in — loopback CPs need no token
    };
    let mut creds: StoredCredentials = match serde_json::from_slice(&raw) {
        Ok(c) => c,
        Err(_) => return Ok(false), // unreadable file — let the CP 401 path speak
    };
    let now = chrono::Utc::now().timestamp();
    match id_token_expiry(&creds.id_token) {
        Some(exp) if exp - now > REFRESH_SKEW_SECS => return Ok(false), // still fresh
        // Expired/near-expiry (or undecodable) → try to refresh.
        _ => {}
    }
    let Some(refresh_token) = creds.refresh_token.clone() else {
        return Ok(false); // nothing to redeem — re-login is the only path
    };

    // Resolve the token endpoint via discovery (issuers can host it anywhere).
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let disc: serde_json::Value = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            creds.issuer.trim_end_matches('/')
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let token_endpoint = disc
        .get("token_endpoint")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("issuer discovery has no token_endpoint"))?;

    // Transport floor: a refresh_token is a long-lived bearer credential —
    // never POST it over plaintext http to a non-loopback host. (A dev
    // issuer on localhost is fine.) Visible warn + skip rather than a silent
    // (debug-swallowed) error; the stored token stays and the CP's 401 +
    // re-login hint is the outcome.
    if let Ok(u) = Url::parse(token_endpoint) {
        let loopback = matches!(
            u.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("::1")
        );
        if u.scheme() != "https" && !loopback {
            tracing::warn!(
                token_endpoint,
                "refusing to send the refresh token over insecure (non-https) transport; \
                 skipping refresh — re-run login"
            );
            return Ok(false);
        }
    }

    let resp = http
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", creds.client_id.as_str()),
        ])
        .send()
        .await?;
    if !resp.status().is_success() {
        // A revoked/expired refresh token isn't an error to propagate — the
        // stored id_token stays and the CP's 401 (with its re-login hint)
        // tells the user what to do.
        tracing::debug!(status = %resp.status(), "token refresh rejected by issuer");
        return Ok(false);
    }
    let tokens: serde_json::Value = resp.json().await?;
    let Some(new_id) = tokens.get("id_token").and_then(|t| t.as_str()) else {
        return Ok(false); // provider refreshed only the access_token — keep ours
    };
    creds.id_token = new_id.to_owned();
    if let Some(at) = tokens.get("access_token").and_then(|t| t.as_str()) {
        creds.access_token = at.to_owned();
    }
    if let Some(rt) = tokens.get("refresh_token").and_then(|t| t.as_str()) {
        creds.refresh_token = Some(rt.to_owned()); // rotation
    }
    creds.stored_at = chrono::Utc::now();
    let bytes = serde_json::to_vec_pretty(&creds)?;
    write_credentials_file(&path, &bytes)?;
    Ok(true)
}

/// Write the credentials file ATOMICALLY with 0600 perms: write a sibling
/// tempfile (created 0600 from the start — no chmod-after race), then rename
/// over the target (atomic on the same filesystem). A crash mid-write can no
/// longer leave a truncated/empty credentials.json after the IdP has already
/// rotated the refresh token (which would mean permanent re-login).
fn write_credentials_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("json.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod refresh_tests {
    use super::*;
    use base64::Engine as _;

    fn fake_jwt(exp: i64) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({ "exp": exp }).to_string());
        format!("{header}.{payload}.sig")
    }

    #[test]
    fn expiry_decodes_without_verification() {
        assert_eq!(
            id_token_expiry(&fake_jwt(1_700_000_000)),
            Some(1_700_000_000)
        );
        assert_eq!(id_token_expiry("not-a-jwt"), None);
        assert_eq!(id_token_expiry("a.!!!.c"), None);
        // A float NumericDate (RFC-permitted) decodes, not refresh-on-every-call.
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({ "exp": 1_700_000_000.5 }).to_string());
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
        assert_eq!(
            id_token_expiry(&format!("{header}.{payload}.s")),
            Some(1_700_000_000)
        );
    }

    #[tokio::test]
    async fn ensure_fresh_is_a_noop_without_creds_or_when_fresh() {
        let dir = tempfile::tempdir().unwrap();
        // No credentials file → Ok(false), no error.
        assert!(!ensure_fresh(dir.path()).await.unwrap());

        // Fresh token (1h left) → no refresh attempted (no network needed).
        let creds = StoredCredentials {
            issuer: "http://127.0.0.1:1".into(), // unroutable — must not be hit
            client_id: "mcpg-ctl".into(),
            id_token: fake_jwt(chrono::Utc::now().timestamp() + 3600),
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            license_jwt: None,
            email: None,
            stored_at: chrono::Utc::now(),
        };
        std::fs::write(
            dir.path().join("credentials.json"),
            serde_json::to_vec(&creds).unwrap(),
        )
        .unwrap();
        assert!(!ensure_fresh(dir.path()).await.unwrap());
    }

    #[tokio::test]
    async fn ensure_fresh_redeems_an_expired_token_and_persists_rotation() {
        // A minimal one-shot OIDC stub: discovery + token endpoint.
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let issuer_for_thread = issuer.clone();
        let handle = std::thread::spawn(move || {
            // Read a full HTTP request: headers up to \r\n\r\n, then any
            // Content-Length body. A single read() could split a request and
            // flake (the finding); this is robust to chunking.
            fn read_request(sock: &mut std::net::TcpStream) -> String {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let n = sock.read(&mut chunk).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..hdr_end]).to_lowercase();
                        let want = head
                            .split("content-length:")
                            .nth(1)
                            .and_then(|s| s.split("\r\n").next())
                            .and_then(|s| s.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buf.len() >= hdr_end + 4 + want {
                            break;
                        }
                    }
                }
                String::from_utf8_lossy(&buf).to_string()
            }

            // Serve exactly two requests: discovery, then the refresh grant.
            for i in 0..2 {
                let (mut sock, _) = listener.accept().unwrap();
                let req = read_request(&mut sock);
                let body = if i == 0 {
                    assert!(
                        req.contains("openid-configuration"),
                        "first call is discovery"
                    );
                    format!("{{\"token_endpoint\":\"{issuer_for_thread}/oauth/token\"}}")
                } else {
                    assert!(
                        req.contains("grant_type=refresh_token"),
                        "refresh grant: {req}"
                    );
                    assert!(req.contains("refresh_token=rt-1"));
                    "{\"id_token\":\"new.id.token\",\"access_token\":\"new-at\",\"refresh_token\":\"rt-2\"}"
                        .to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).unwrap();
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let creds = StoredCredentials {
            issuer,
            client_id: "mcpg-ctl".into(),
            id_token: fake_jwt(chrono::Utc::now().timestamp() - 10), // expired
            access_token: "old-at".into(),
            refresh_token: Some("rt-1".into()),
            license_jwt: Some("lic.jwt".into()),
            email: Some("a@b.c".into()),
            stored_at: chrono::Utc::now(),
        };
        std::fs::write(
            dir.path().join("credentials.json"),
            serde_json::to_vec(&creds).unwrap(),
        )
        .unwrap();

        assert!(ensure_fresh(dir.path()).await.unwrap(), "refresh performed");
        handle.join().unwrap();

        let after: StoredCredentials =
            serde_json::from_slice(&std::fs::read(dir.path().join("credentials.json")).unwrap())
                .unwrap();
        assert_eq!(after.id_token, "new.id.token");
        assert_eq!(after.access_token, "new-at");
        assert_eq!(after.refresh_token.as_deref(), Some("rt-2"), "rotated");
        assert_eq!(
            after.license_jwt.as_deref(),
            Some("lic.jwt"),
            "license preserved"
        );
    }
}
