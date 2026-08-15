//! Bearer-authenticated HTTP client for control-plane calls + shared error
//! rendering.
//!
//! CLI commands that talk to the CP authenticate with the OIDC id_token
//! stored by `login` (`<state_dir>/credentials.json`), attached as
//! `Authorization: Bearer`. Against a loopback CP (`auth_mode=none`) no
//! token exists and no header is attached — commands still work.

use std::path::Path;

use anyhow::Context;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};

/// Header carrying the stored federation license JWT to the CP. Kept
/// in sync with the CP's `auth_ctx::LICENSE_HEADER`. The raw id_token
/// (the Bearer credential) can't carry the license, so the CP uses
/// this on a CLI user's first contact to resolve their real tenant org
/// rather than the shared `default`.
pub const LICENSE_HEADER: &str = "x-mcpg-license";

/// Read a non-empty string field from `login`'s credentials file.
pub fn cred_field(state_dir: &Path, field: &str) -> Option<String> {
    let raw = std::fs::read(state_dir.join("credentials.json")).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.get(field)
        .and_then(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

/// Read the OIDC id_token from the credentials file, if present.
/// Absent is fine — a loopback CP needs no token.
pub fn bearer_token(state_dir: &Path) -> Option<String> {
    cred_field(state_dir, "id_token")
}

/// Build a reqwest client that attaches the bearer token (when we have one) on
/// every request. Long timeout — provisioning can take minutes.
///
/// Best-effort TOKEN REFRESH first: if the stored id_token is expired and a
/// refresh_token exists, redeem it so the command just works instead of
/// 401ing an hour after login. A failed refresh is non-fatal — the CP's 401
/// (with its re-login hint) stays the authoritative outcome.
pub async fn bearer_client(state_dir: &Path) -> anyhow::Result<reqwest::Client> {
    if let Err(e) = crate::login::ensure_fresh(state_dir).await {
        tracing::debug!(error = %e, "token refresh attempt failed; proceeding with stored token");
    }
    bearer_client_unrefreshed(state_dir)
}

fn bearer_client_unrefreshed(state_dir: &Path) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(600));
    if let Some(token) = bearer_token(state_dir) {
        let mut headers = HeaderMap::new();
        let mut val = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("bearer token has invalid header chars")?;
        val.set_sensitive(true);
        headers.insert(AUTHORIZATION, val);
        // Forward the stored license JWT so the CP can resolve our real
        // tenant org on first contact (the id_token alone can't carry it).
        if let Some(license) = cred_field(state_dir, "license_jwt") {
            let mut lic =
                HeaderValue::from_str(&license).context("license jwt has invalid header chars")?;
            lic.set_sensitive(true);
            headers.insert(HeaderName::from_static(LICENSE_HEADER), lic);
        }
        builder = builder.default_headers(headers);
    }
    Ok(builder.build()?)
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
    let hint = if status == reqwest::StatusCode::UNAUTHORIZED {
        format!(
            "\n  hint: your session may have expired — re-run `{} login --issuer <url>`",
            program_invocation()
        )
    } else {
        String::new()
    };
    anyhow::anyhow!("{action} \u{2192} {status}: {body}{hint}")
}
