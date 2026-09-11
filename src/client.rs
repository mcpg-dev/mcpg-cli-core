//! Bearer-authenticated HTTP client for control-plane calls + shared error
//! rendering.
//!
//! CLI commands that talk to the CP authenticate with the OIDC id_token
//! stored by `login` (`<state_dir>/credentials.json`), attached as
//! `Authorization: Bearer`. A non-interactive caller — CI, an operator's
//! script — sets [`TOKEN_ENV`] to a service token instead; it takes
//! precedence over the stored login and skips the refresh step, which has
//! nothing to refresh. Against a loopback CP (`auth_mode=none`) no token
//! exists and no header is attached — commands still work.

use std::path::Path;

use anyhow::Context;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};

/// Header carrying the stored federation license JWT to the CP. Kept
/// in sync with the CP's `auth_ctx::LICENSE_HEADER`. The raw id_token
/// (the Bearer credential) can't carry the license, so the CP uses
/// this on a CLI user's first contact to resolve their real tenant org
/// rather than the shared `default`.
pub const LICENSE_HEADER: &str = "x-mcpg-license";

/// Environment variable carrying a bearer credential for non-interactive
/// use — a control-plane service token (`mcpg cloud service-token create`),
/// or any token the CP accepts. Wins over the stored login.
pub const TOKEN_ENV: &str = "MCPG_CLOUD_TOKEN";

/// The bearer supplied through the environment, when set and non-empty.
pub fn env_token() -> Option<String> {
    std::env::var(TOKEN_ENV)
        .ok()
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
}

/// Read a non-empty string field from `login`'s credentials file.
pub fn cred_field(state_dir: &Path, field: &str) -> Option<String> {
    let raw = std::fs::read(state_dir.join("credentials.json")).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.get(field)
        .and_then(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

/// The bearer to present: the environment token when set, else the OIDC
/// id_token from the credentials file. Absent is fine — a loopback CP
/// needs no token.
pub fn bearer_token(state_dir: &Path) -> Option<String> {
    env_token().or_else(|| cred_field(state_dir, "id_token"))
}

/// Build a reqwest client that attaches the bearer token (when we have one) on
/// every request. Long timeout — provisioning can take minutes.
///
/// Best-effort TOKEN REFRESH first: if the stored id_token is expired and a
/// refresh_token exists, redeem it so the command just works instead of
/// 401ing an hour after login. A failed refresh is non-fatal — the CP's 401
/// (with its re-login hint) stays the authoritative outcome.
pub async fn bearer_client(state_dir: &Path) -> anyhow::Result<reqwest::Client> {
    // An environment token is not a login: there is no refresh token behind
    // it, and a stale stored login must not be renewed and then ignored.
    if env_token().is_none()
        && let Err(e) = crate::login::ensure_fresh(state_dir).await
    {
        tracing::debug!(error = %e, "token refresh attempt failed; proceeding with stored token");
    }
    bearer_client_unrefreshed(state_dir)
}

fn bearer_client_unrefreshed(state_dir: &Path) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(600));
    if let Some(headers) = auth_headers(state_dir)? {
        builder = builder.default_headers(headers);
    }
    Ok(builder.build()?)
}

/// The headers every CP call carries: the bearer, plus — for a stored
/// login only — the license JWT so the CP can resolve the real tenant org
/// on first contact (the id_token alone can't carry it). A service token is
/// already org-scoped, so it carries none. `None` when there is no
/// credential at all (a loopback CP).
fn auth_headers(state_dir: &Path) -> anyhow::Result<Option<HeaderMap>> {
    let Some(token) = bearer_token(state_dir) else {
        return Ok(None);
    };
    let mut headers = HeaderMap::new();
    let mut val = HeaderValue::from_str(&format!("Bearer {token}"))
        .context("bearer token has invalid header chars")?;
    val.set_sensitive(true);
    headers.insert(AUTHORIZATION, val);
    if env_token().is_none()
        && let Some(license) = cred_field(state_dir, "license_jwt")
    {
        let mut lic =
            HeaderValue::from_str(&license).context("license jwt has invalid header chars")?;
        lic.set_sensitive(true);
        headers.insert(HeaderName::from_static(LICENSE_HEADER), lic);
    }
    Ok(Some(headers))
}

/// The canonical invocation of the running binary, for hint strings:
/// `mcpg-cloud` → `mcpg cloud`, `mcpg-admin` → `mcpg admin`, anything else
/// its plain basename. The dispatcher form is what the docs teach, so hints
/// teach it too.
pub fn program_invocation() -> String {
    let bin = std::env::args().next().unwrap_or_default();
    let base = std::path::Path::new(&bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("mcpg")
        .to_string();
    match base.strip_prefix("mcpg-") {
        Some(rest) if !rest.is_empty() => format!("mcpg {rest}"),
        _ => base,
    }
}

/// Build an error for a failed CP response, appending a re-login hint on a
/// 401 — the CLI's most common failure once a stored token expires (and the
/// auto-refresh couldn't renew it). Shared by every CP command so the hint
/// isn't `whoami`-only.
pub async fn cp_error(action: &str, resp: reqwest::Response) -> anyhow::Error {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let hint = if status != reqwest::StatusCode::UNAUTHORIZED {
        String::new()
    } else if env_token().is_some() {
        format!(
            "\n  hint: the {TOKEN_ENV} token was refused — it may be expired or revoked \
             (an org owner lists them with `{} service-token list`)",
            program_invocation()
        )
    } else {
        format!(
            "\n  hint: your session may have expired — re-run `{} login --issuer <url>`",
            program_invocation()
        )
    };
    anyhow::anyhow!("{action} \u{2192} {status}: {body}{hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The environment token and the stored login are read by different
    /// tests in one process, so the variable is set and cleared under a lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env_token<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: the lock serialises every writer of this variable in the
        // test binary, and nothing reads it concurrently.
        unsafe {
            match value {
                Some(v) => std::env::set_var(TOKEN_ENV, v),
                None => std::env::remove_var(TOKEN_ENV),
            }
        }
        let out = f();
        unsafe { std::env::remove_var(TOKEN_ENV) };
        out
    }

    fn login_dir(id_token: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.json"),
            serde_json::json!({ "id_token": id_token, "license_jwt": "lic" }).to_string(),
        )
        .unwrap();
        dir
    }

    #[test]
    fn the_environment_token_wins_over_the_stored_login() {
        let dir = login_dir("stored");
        with_env_token(Some("svc-token"), || {
            assert_eq!(bearer_token(dir.path()).as_deref(), Some("svc-token"));
        });
        with_env_token(None, || {
            assert_eq!(bearer_token(dir.path()).as_deref(), Some("stored"));
        });
    }

    #[test]
    fn a_blank_environment_token_is_absent() {
        let dir = login_dir("stored");
        with_env_token(Some("   "), || {
            assert_eq!(env_token(), None);
            assert_eq!(bearer_token(dir.path()).as_deref(), Some("stored"));
        });
    }

    /// A service token is org-scoped already; the stored license JWT belongs
    /// to a different login and must not ride along with it.
    #[test]
    fn the_license_header_rides_only_with_a_stored_login() {
        let dir = login_dir("stored");
        with_env_token(Some("svc-token"), || {
            let headers = auth_headers(dir.path()).unwrap().expect("a bearer");
            assert_eq!(
                headers.get(AUTHORIZATION).unwrap().to_str().unwrap(),
                "Bearer svc-token"
            );
            assert!(headers.get(AUTHORIZATION).unwrap().is_sensitive());
            assert!(!headers.contains_key(LICENSE_HEADER));
        });
        with_env_token(None, || {
            let headers = auth_headers(dir.path()).unwrap().expect("a bearer");
            assert_eq!(
                headers.get(AUTHORIZATION).unwrap().to_str().unwrap(),
                "Bearer stored"
            );
            assert_eq!(
                headers.get(LICENSE_HEADER).unwrap().to_str().unwrap(),
                "lic"
            );
        });
        let empty = tempfile::tempdir().unwrap();
        with_env_token(None, || {
            assert!(
                auth_headers(empty.path()).unwrap().is_none(),
                "no login, no header"
            );
        });
    }
}
