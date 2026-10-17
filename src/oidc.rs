//! OIDC client — discovery, PKCE, token exchange, JWKS-backed verify.
//!
//! Supports any RFC 8414-conformant provider: federation
//! (auth.mcpg.dev), customer Okta / AAD / Google / Keycloak /
//! self-hosted IdPs. Consumers don't care which one issued the
//! token as long as discovery + JWKS verify succeed.
//!
//! Shared by the CLI login flow (`crate::login`) and the control-plane
//! server's browser login + Bearer verification — which is why it lives in
//! `mcpg-cli-core` rather than the server crate: the CLIs must not link the
//! server's dependency tree to sign a user in.
//!
//! We deliberately keep this thin: PKCE only (no client_secret in
//! browser-driven flows), no nonce binding (we use HTTP `state`
//! for CSRF + signed cookie for verifier replay protection),
//! no id_token re-validation after the initial exchange (session
//! cookie is the only thing that matters per-request).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use jsonwebtoken::{DecodingKey, Validation};
use rand::{TryRng, rngs::SysRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;

/// The JOSE `typ` of an MCPG licence (`mcpg_control_plane_license::trust::
/// LICENSE_JWT_TYP`). A federation licence names the federation as issuer and
/// `mcpg-cp` as an audience, like an id_token for the `mcpg-cp` client, so its
/// `typ` is what keeps it from signing anyone in.
const LICENSE_JWT_TYP: &str = "mcpg-license+jwt";

#[derive(Clone, Debug, Deserialize)]
pub struct DiscoveryDoc {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// Non-standard MCPG extension — federation-issued license
    /// JWT scoped to the user's tenant Org. Returned alongside
    /// `id_token` when the CP is wired against
    /// `auth.mcpg.dev` (or any RFC-conformant issuer that opts
    /// into the extension). Generic OIDC providers omit it.
    #[serde(default)]
    pub mcpg_license_jwt: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: serde_json::Value, // can be string or string[]
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    /// Every claim not captured by a named field above. Lets the CP
    /// read a deployment-configured tenant claim
    /// (`MCPG_CP_OIDC_TENANT_CLAIM`) by name without baking each
    /// provider's tenant attribute (`tenant`, `org_id`, `hd`, `tid`,
    /// …) into this struct.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl IdTokenClaims {
    /// Best-effort account identifier: `email`, else `preferred_username`
    /// (some IdPs only populate that), else the opaque `sub`. Shared by the
    /// browser login callback and the Bearer auth path so both resolve the
    /// same user row.
    pub fn resolved_email(&self) -> String {
        self.email
            .clone()
            .or_else(|| self.preferred_username.clone())
            .unwrap_or_else(|| self.sub.clone())
    }

    /// Look up a named claim as a string, used to resolve the tenant
    /// org for generic OIDC providers. Works for ANY claim — a named
    /// struct field (so `MCPG_CP_OIDC_TENANT_CLAIM=sub` / `=email`
    /// gives per-user / per-account tenancy) or a flattened extra
    /// claim (`tenant`, `org_id`, `hd`, `tid`, …) — by serialising
    /// self once and looking the wire name up uniformly, rather than a
    /// hand-maintained match that drifts from the struct.
    ///
    /// Strings are trimmed (blank → `None`). A numeric claim is coerced
    /// to its decimal form ONLY when it is an exact integer; a
    /// fractional / scientific value (`is_f64`) is rejected, because
    /// `to_string` on an f64 is lossy and could fold two distinct large
    /// tenant ids onto one slug (a cross-tenant merge). Returns `None`
    /// when the claim is absent, blank, or not a scalar string/integer.
    pub fn string_claim(&self, name: &str) -> Option<String> {
        let v = serde_json::to_value(self).ok()?;
        match v.get(name)? {
            serde_json::Value::String(s) => {
                let t = s.trim();
                (!t.is_empty()).then(|| t.to_string())
            }
            serde_json::Value::Number(n) if n.is_i64() || n.is_u64() => Some(n.to_string()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl PkcePair {
    /// Generate an S256 PKCE pair: 32 random bytes → base64url
    /// verifier; SHA-256(verifier) → base64url challenge.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut bytes)
            .expect("OS randomness unavailable");
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize());
        Self {
            verifier,
            challenge,
        }
    }
}

/// Random URL-safe state parameter for CSRF protection.
pub fn random_state() -> String {
    let mut bytes = [0u8; 24];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS randomness unavailable");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Minimum spacing between forced JWKS refetches (a kid-miss or bad-signature
/// storm — e.g. a flood of forged tokens — must not become a request
/// amplifier against the IdP).
const JWKS_REFETCH_COOLDOWN: Duration = Duration::from_secs(30);

/// How long a fetched JWKS is used before the next verify refetches it, so a
/// key the issuer has withdrawn stops verifying without a restart.
const JWKS_MAX_AGE: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
struct CachedJwks {
    set: jsonwebtoken::jwk::JwkSet,
    /// When the next verify refetches the set.
    refresh_at: std::time::Instant,
}

/// OIDC client — caches the discovery doc and JWKS.
#[derive(Clone)]
pub struct OidcClient {
    issuer: Url,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    http: reqwest::Client,
    discovery: Arc<RwLock<Option<DiscoveryDoc>>>,
    jwks: Arc<RwLock<Option<CachedJwks>>>,
    /// Last forced (kid-miss or bad-signature) JWKS refetch, for the cooldown.
    jwks_refetched_at: Arc<RwLock<Option<std::time::Instant>>>,
}

/// Why no key in a JWKS verified a token.
enum KeyMismatch {
    /// No key under the token's kid checks its signature — the issuer may
    /// have re-keyed, so a refetch can help.
    Signature(anyhow::Error),
    /// A key checked the signature and the claims failed, or the token is
    /// malformed; a refetch cannot help.
    Rejected(anyhow::Error),
}

/// Every key the set publishes under `kid`. An issuer mid-rotation can
/// publish the outgoing and incoming keys under one kid.
fn keys_for_kid<'a>(
    set: &'a jsonwebtoken::jwk::JwkSet,
    kid: &str,
) -> Vec<&'a jsonwebtoken::jwk::Jwk> {
    set.keys
        .iter()
        .filter(|k| k.common.key_id.as_deref() == Some(kid))
        .collect()
}

impl OidcClient {
    pub fn new(
        issuer: Url,
        client_id: String,
        client_secret: Option<String>,
        redirect_uri: String,
    ) -> Self {
        Self {
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            discovery: Arc::new(RwLock::new(None)),
            jwks: Arc::new(RwLock::new(None)),
            jwks_refetched_at: Arc::new(RwLock::new(None)),
        }
    }

    /// The issuer this client is pinned to.
    pub fn issuer(&self) -> &Url {
        &self.issuer
    }

    pub async fn discovery(&self) -> anyhow::Result<DiscoveryDoc> {
        if let Some(d) = self.discovery.read().await.clone() {
            return Ok(d);
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.as_str().trim_end_matches('/')
        );
        let doc: DiscoveryDoc = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        *self.discovery.write().await = Some(doc.clone());
        Ok(doc)
    }

    /// The cached JWKS, refetched once it is older than [`JWKS_MAX_AGE`]. An
    /// issuer that cannot be reached then keeps the cached set in use for
    /// another max-age rather than failing every verify.
    ///
    /// One verify refreshes; the rest keep using the cached set meanwhile.
    /// `refresh_at` moves ahead under the write lock BEFORE the fetch, so the
    /// verifies that arrive during a slow fetch (reachable unauthenticated)
    /// do not each start their own.
    async fn jwks(&self) -> anyhow::Result<jsonwebtoken::jwk::JwkSet> {
        if let Some(c) = self.jwks.read().await.as_ref()
            && std::time::Instant::now() < c.refresh_at
        {
            return Ok(c.set.clone());
        }
        let stale = {
            let mut cached = self.jwks.write().await;
            match cached.as_mut() {
                Some(c) if std::time::Instant::now() < c.refresh_at => return Ok(c.set.clone()),
                Some(c) => {
                    c.refresh_at = std::time::Instant::now() + JWKS_MAX_AGE;
                    Some(c.set.clone())
                }
                None => None,
            }
        };
        let Some(stale) = stale else {
            return self.fetch_jwks().await;
        };
        match self.fetch_jwks().await {
            Ok(set) => Ok(set),
            Err(e) => {
                tracing::warn!(
                    error = %e, issuer = %self.issuer,
                    "JWKS refresh failed; keeping the cached keys"
                );
                Ok(stale)
            }
        }
    }

    /// Fetch the JWKS from the issuer and replace the cache.
    async fn fetch_jwks(&self) -> anyhow::Result<jsonwebtoken::jwk::JwkSet> {
        let d = self.discovery().await?;
        let set: jsonwebtoken::jwk::JwkSet = self
            .http
            .get(&d.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        *self.jwks.write().await = Some(CachedJwks {
            set: set.clone(),
            refresh_at: std::time::Instant::now() + JWKS_MAX_AGE,
        });
        Ok(set)
    }

    /// Refetch the JWKS ahead of its max age, at most once per
    /// [`JWKS_REFETCH_COOLDOWN`]. `Ok(None)` when the cooldown holds it back.
    ///
    /// Both triggers — an unknown kid and a known kid whose keys do not check
    /// the signature — are reachable unauthenticated via stateless Bearer
    /// verify, so the check-and-set is ATOMIC under the write lock: a
    /// read-then-write gap would let a flood of concurrent forged tokens each
    /// pass the check and each fire a fetch. Set-before-fetch is deliberate —
    /// a failed fetch burning the window is the correct fail-safe under a flood.
    async fn forced_refetch(
        &self,
        kid: &str,
        why: &str,
    ) -> anyhow::Result<Option<jsonwebtoken::jwk::JwkSet>> {
        let allow = {
            let mut last = self.jwks_refetched_at.write().await;
            let ok = last
                .map(|t| t.elapsed() >= JWKS_REFETCH_COOLDOWN)
                .unwrap_or(true);
            if ok {
                *last = Some(std::time::Instant::now());
            }
            ok
        };
        if !allow {
            return Ok(None);
        }
        tracing::info!(%kid, issuer = %self.issuer, reason = why, "refetching JWKS (possible key rotation)");
        self.fetch_jwks().await.map(Some)
    }

    /// Verify `token` with the first of `keys` whose signature checks.
    fn decode_with_any<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        alg: jsonwebtoken::Algorithm,
        keys: &[&jsonwebtoken::jwk::Jwk],
        audience: &[&str],
        validate_nbf: bool,
    ) -> Result<T, KeyMismatch> {
        use jsonwebtoken::errors::ErrorKind;
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[self.issuer.as_str().trim_end_matches('/')]);
        validation.set_audience(audience);
        validation.leeway = 60;
        validation.validate_nbf = validate_nbf;
        let mut last = anyhow::anyhow!("no key in the issuer's JWKS for this token");
        for jwk in keys {
            let key = match DecodingKey::from_jwk(jwk) {
                Ok(k) => k,
                Err(e) => {
                    last = anyhow::anyhow!("build decoding key: {e}");
                    continue;
                }
            };
            match jsonwebtoken::decode::<T>(token, &key, &validation) {
                Ok(data) => return Ok(data.claims),
                // This key is not the one that signed the token; another
                // under the same kid may be.
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::InvalidSignature
                            | ErrorKind::InvalidAlgorithm
                            | ErrorKind::InvalidKeyFormat
                            | ErrorKind::InvalidEcdsaKey
                            | ErrorKind::InvalidEddsaKey
                            | ErrorKind::InvalidRsaKey(_)
                    ) =>
                {
                    last = anyhow::anyhow!("verify claims: {e}");
                }
                Err(e) => return Err(KeyMismatch::Rejected(anyhow::anyhow!("verify claims: {e}"))),
            }
        }
        Err(KeyMismatch::Signature(last))
    }

    /// Build the `/authorize` URL the browser should be redirected
    /// to. Caller is responsible for storing `pkce.verifier` +
    /// `state` in a transient signed cookie.
    pub async fn authorize_url(
        &self,
        pkce: &PkcePair,
        state: &str,
        scopes: &[&str],
    ) -> anyhow::Result<Url> {
        let d = self.discovery().await?;
        let mut url = Url::parse(&d.authorization_endpoint)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", state)
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url)
    }

    /// Exchange the authorization `code` for tokens. Sends the
    /// PKCE verifier in the body as required by RFC 7636.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> anyhow::Result<TokenResponse> {
        let d = self.discovery().await?;
        let mut form: HashMap<&str, &str> = HashMap::new();
        form.insert("grant_type", "authorization_code");
        form.insert("code", code);
        form.insert("redirect_uri", &self.redirect_uri);
        form.insert("client_id", &self.client_id);
        form.insert("code_verifier", pkce_verifier);
        if let Some(secret) = self.client_secret.as_deref() {
            form.insert("client_secret", secret);
        }
        let resp = self.http.post(&d.token_endpoint).form(&form).send().await?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("token endpoint: {body}");
        }
        Ok(resp.json().await?)
    }

    /// Verify any JWT signed by this issuer's JWKS and deserialize its
    /// claims into `T`.
    ///
    /// The shared core under [`verify_id_token`](Self::verify_id_token) and
    /// the server's license verification: issuer is pinned to this client's
    /// issuer, `audience` and `validate_nbf` are the caller's contract,
    /// leeway is 60s. Every key the JWKS publishes under the token's `kid` is
    /// tried. An unknown `kid`, or a known one whose keys all fail the
    /// signature, triggers one cooldown-guarded JWKS refetch: an issuer that
    /// rotates its key — under a new kid or the same one — is followed without
    /// a restart. Generic so callers with richer claims types (the server's
    /// `LicenseClaims` lives in a crate this one deliberately doesn't depend
    /// on) can layer on top.
    pub async fn verify_signed_claims<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        audience: &[&str],
        validate_nbf: bool,
    ) -> anyhow::Result<T> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| anyhow::anyhow!("decode jwt header: {e}"))?;
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("token missing kid header"))?;
        let set = self.jwks().await?;
        let keys = keys_for_kid(&set, kid);
        let outcome = if keys.is_empty() {
            None
        } else {
            match self.decode_with_any::<T>(token, header.alg, &keys, audience, validate_nbf) {
                Ok(claims) => return Ok(claims),
                Err(KeyMismatch::Rejected(e)) => return Err(e),
                Err(KeyMismatch::Signature(e)) => Some(e),
            }
        };
        let why = if outcome.is_some() {
            "signature does not match the cached keys"
        } else {
            "unknown kid"
        };
        let Some(fresh) = self.forced_refetch(kid, why).await? else {
            return Err(
                outcome.unwrap_or_else(|| anyhow::anyhow!("kid {kid} not in the issuer's JWKS"))
            );
        };
        let keys = keys_for_kid(&fresh, kid);
        if keys.is_empty() {
            anyhow::bail!("kid {kid} not in the issuer's JWKS");
        }
        self.decode_with_any::<T>(token, header.alg, &keys, audience, validate_nbf)
            .map_err(|m| match m {
                KeyMismatch::Signature(e) | KeyMismatch::Rejected(e) => e,
            })
    }

    /// Verify the id_token and return its claims. Trusts the
    /// JWKS endpoint's published keys; checks issuer + audience
    /// (this client's `client_id`), and refuses an MCPG licence.
    pub async fn verify_id_token(&self, id_token: &str) -> anyhow::Result<IdTokenClaims> {
        let is_license = jsonwebtoken::decode_header(id_token).is_ok_and(|h| {
            h.typ
                .is_some_and(|typ| typ.eq_ignore_ascii_case(LICENSE_JWT_TYP))
        });
        if is_license {
            anyhow::bail!("verify id_token: the token is an MCPG licence, not an id_token");
        }
        self.verify_signed_claims(id_token, &[&self.client_id], false)
            .await
            .map_err(|e| anyhow::anyhow!("verify id_token: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(extra: serde_json::Value) -> IdTokenClaims {
        let mut base = serde_json::json!({
            "iss": "https://idp.example",
            "sub": "user-1",
            "aud": "mcpg-cp",
            "exp": 9_999_999_999i64,
            "iat": 1_700_000_000i64,
            "email": "alice@example.com",
        });
        if let (Some(o), serde_json::Value::Object(ex)) = (base.as_object_mut(), extra) {
            for (k, v) in ex {
                o.insert(k, v);
            }
        }
        serde_json::from_value(base).expect("deserialize IdTokenClaims")
    }

    #[test]
    fn string_claim_reads_a_custom_string_claim() {
        let c = claims(serde_json::json!({ "tenant": "acme" }));
        assert_eq!(c.string_claim("tenant").as_deref(), Some("acme"));
    }

    #[test]
    fn string_claim_coerces_an_integer_claim() {
        // Some IdPs (e.g. a numeric org id) emit the tenant as an integer.
        let c = claims(serde_json::json!({ "org_id": 42 }));
        assert_eq!(c.string_claim("org_id").as_deref(), Some("42"));
        // Large 64-bit integers stay exact.
        let big = claims(serde_json::json!({ "org_id": 9_007_199_254_740_993i64 }));
        assert_eq!(
            big.string_claim("org_id").as_deref(),
            Some("9007199254740993")
        );
    }

    #[test]
    fn string_claim_rejects_non_integer_numbers() {
        // Fractional / scientific values are lossy via f64 and could fold two
        // distinct tenant ids onto one slug — reject (fail closed) instead.
        let frac = claims(serde_json::json!({ "org_id": 1000.5 }));
        assert_eq!(frac.string_claim("org_id"), None);
        let sci = claims(serde_json::json!({ "org_id": 1e20 }));
        assert_eq!(sci.string_claim("org_id"), None);
    }

    #[test]
    fn string_claim_trims_and_rejects_blank() {
        let c = claims(serde_json::json!({ "tenant": "  spaced  " }));
        assert_eq!(c.string_claim("tenant").as_deref(), Some("spaced"));
        let blank = claims(serde_json::json!({ "tenant": "   " }));
        assert_eq!(blank.string_claim("tenant"), None);
    }

    #[test]
    fn string_claim_absent_is_none() {
        let c = claims(serde_json::json!({}));
        assert_eq!(c.string_claim("tenant"), None);
    }

    #[test]
    fn string_claim_non_scalar_is_none() {
        let arr = claims(serde_json::json!({ "tenant": ["a", "b"] }));
        assert_eq!(arr.string_claim("tenant"), None);
        let obj = claims(serde_json::json!({ "tenant": {"x": 1} }));
        assert_eq!(obj.string_claim("tenant"), None);
    }

    #[test]
    fn string_claim_resolves_named_fields() {
        // `sub` / `email` are real struct fields, not in `extra`, but
        // are still reachable by name (so MCPG_CP_OIDC_TENANT_CLAIM=sub
        // gives per-user orgs).
        let c = claims(serde_json::json!({}));
        assert_eq!(c.string_claim("sub").as_deref(), Some("user-1"));
        assert_eq!(
            c.string_claim("email").as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn string_claim_reaches_every_named_field_uniformly() {
        // Regression guard for the old hand-maintained match: `nonce` is a
        // named field that the previous allowlist omitted, so configuring it
        // failed closed even when present. The serialize-and-lookup path
        // reaches it like any other claim.
        let c = claims(serde_json::json!({ "nonce": "the-nonce" }));
        assert_eq!(c.string_claim("nonce").as_deref(), Some("the-nonce"));
    }

    mod jwks_rotation {
        use super::super::*;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

        /// An issuer whose published JWKS the test swaps, counting fetches.
        /// `delay_ms` slows each JWKS answer; `down` makes it a 503.
        struct Issuer {
            url: String,
            jwks: Arc<Mutex<serde_json::Value>>,
            fetches: Arc<AtomicUsize>,
            delay_ms: Arc<AtomicU64>,
            down: Arc<AtomicBool>,
        }

        fn oct(kid: &str, secret: &[u8]) -> serde_json::Value {
            serde_json::json!({
                "kty": "oct",
                "kid": kid,
                "alg": "HS256",
                "k": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
            })
        }

        async fn issuer(keys: Vec<serde_json::Value>) -> Issuer {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let jwks = Arc::new(Mutex::new(serde_json::json!({ "keys": keys })));
            let fetches = Arc::new(AtomicUsize::new(0));
            let delay_ms = Arc::new(AtomicU64::new(0));
            let down = Arc::new(AtomicBool::new(false));
            let discovery = serde_json::json!({
                "issuer": url,
                "authorization_endpoint": format!("{url}/authorize"),
                "token_endpoint": format!("{url}/token"),
                "jwks_uri": format!("{url}/jwks"),
            });
            let (served, counted) = (jwks.clone(), fetches.clone());
            let (slow, unavailable) = (delay_ms.clone(), down.clone());
            let app = axum::Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    axum::routing::get(move || {
                        let d = discovery.clone();
                        async move { axum::Json(d) }
                    }),
                )
                .route(
                    "/jwks",
                    axum::routing::get(move || {
                        let served = served.clone();
                        let counted = counted.clone();
                        let delay = slow.load(Ordering::SeqCst);
                        let unavailable = unavailable.load(Ordering::SeqCst);
                        async move {
                            use axum::response::IntoResponse;
                            counted.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                            if unavailable {
                                return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                            }
                            let body = served.lock().unwrap().clone();
                            axum::Json(body).into_response()
                        }
                    }),
                );
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            Issuer {
                url,
                jwks,
                fetches,
                delay_ms,
                down,
            }
        }

        /// Make the client's cached JWKS due for its max-age refresh.
        async fn expire(c: &OidcClient) {
            c.jwks
                .write()
                .await
                .as_mut()
                .expect("a JWKS is cached")
                .refresh_at = std::time::Instant::now();
        }

        fn token(iss: &str, kid: &str, secret: &[u8]) -> String {
            let header = jsonwebtoken::Header {
                kid: Some(kid.into()),
                ..jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256)
            };
            let claims = serde_json::json!({
                "iss": iss,
                "sub": "tenant",
                "aud": "mcpg-cp",
                "exp": 9_999_999_999i64,
                "iat": 1_700_000_000i64,
            });
            jsonwebtoken::encode(
                &header,
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(secret),
            )
            .unwrap()
        }

        fn client(iss: &Issuer) -> OidcClient {
            OidcClient::new(
                iss.url.parse().unwrap(),
                "mcpg-cp".into(),
                None,
                String::new(),
            )
        }

        async fn verify(c: &OidcClient, t: &str) -> anyhow::Result<serde_json::Value> {
            c.verify_signed_claims::<serde_json::Value>(t, &["mcpg-cp"], false)
                .await
        }

        #[tokio::test]
        async fn a_key_replaced_under_the_same_kid_verifies_after_one_refetch() {
            let iss = issuer(vec![oct("fed-v1", b"old-key-0123456789abcdef")]).await;
            let c = client(&iss);
            verify(&c, &token(&iss.url, "fed-v1", b"old-key-0123456789abcdef"))
                .await
                .expect("the original key verifies");
            assert_eq!(iss.fetches.load(Ordering::SeqCst), 1);

            *iss.jwks.lock().unwrap() =
                serde_json::json!({ "keys": [oct("fed-v1", b"new-key-0123456789abcdef")] });
            let claims = verify(&c, &token(&iss.url, "fed-v1", b"new-key-0123456789abcdef"))
                .await
                .expect("the re-keyed issuer's token verifies without a restart");
            assert_eq!(claims["sub"], "tenant");
            assert_eq!(iss.fetches.load(Ordering::SeqCst), 2);

            // The withdrawn key no longer verifies.
            assert!(
                verify(&c, &token(&iss.url, "fed-v1", b"old-key-0123456789abcdef"))
                    .await
                    .is_err()
            );
        }

        #[tokio::test]
        async fn every_key_under_a_kid_is_accepted() {
            let iss = issuer(vec![
                oct("fed-v1", b"outgoing-0123456789abcdef"),
                oct("fed-v1", b"incoming-0123456789abcdef"),
            ])
            .await;
            let c = client(&iss);
            for secret in [
                b"outgoing-0123456789abcdef".as_slice(),
                b"incoming-0123456789abcdef".as_slice(),
            ] {
                verify(&c, &token(&iss.url, "fed-v1", secret))
                    .await
                    .expect("both keys of a rotation window verify");
            }
            assert_eq!(
                iss.fetches.load(Ordering::SeqCst),
                1,
                "no refetch is needed"
            );
        }

        #[tokio::test]
        async fn forged_signatures_refetch_at_most_once_per_cooldown() {
            let iss = issuer(vec![oct("fed-v1", b"real-key-0123456789abcdef")]).await;
            let c = client(&iss);
            for i in 0..20 {
                let forged = token(&iss.url, "fed-v1", format!("forged-{i}").as_bytes());
                assert!(verify(&c, &forged).await.is_err());
            }
            assert_eq!(
                iss.fetches.load(Ordering::SeqCst),
                2,
                "the first fetch, then one forced refetch for the whole burst"
            );
        }

        /// A licence from the same issuer, signed by a key its JWKS publishes
        /// and naming `mcpg-cp`, is still not an id_token.
        #[tokio::test]
        async fn a_licence_is_never_an_id_token() {
            let secret = b"fed-key-0123456789abcdef";
            let iss = issuer(vec![oct("fed-v1", secret)]).await;
            let c = client(&iss);
            c.verify_id_token(&token(&iss.url, "fed-v1", secret))
                .await
                .expect("an id_token verifies");

            let header = jsonwebtoken::Header {
                kid: Some("fed-v1".into()),
                typ: Some("mcpg-license+jwt".into()),
                ..jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256)
            };
            let license = jsonwebtoken::encode(
                &header,
                &serde_json::json!({
                    "iss": iss.url,
                    "sub": "tenant:0190",
                    "aud": ["mcpg-cp", "mcpg-gateway-managed"],
                    "exp": 9_999_999_999i64,
                    "iat": 1_700_000_000i64,
                    "tenant_slug": "acme",
                    "lic_ver": 1,
                }),
                &jsonwebtoken::EncodingKey::from_secret(secret),
            )
            .unwrap();
            let err = c.verify_id_token(&license).await.unwrap_err().to_string();
            assert!(err.contains("licence"), "{err}");
        }

        #[tokio::test]
        async fn a_claims_failure_does_not_refetch() {
            let iss = issuer(vec![oct("fed-v1", b"real-key-0123456789abcdef")]).await;
            let c = client(&iss);
            let t = token(&iss.url, "fed-v1", b"real-key-0123456789abcdef");
            // Right key, wrong audience: the signature checked, so a refetch
            // cannot help and must not be spent.
            assert!(
                c.verify_signed_claims::<serde_json::Value>(&t, &["someone-else"], false)
                    .await
                    .is_err()
            );
            assert_eq!(iss.fetches.load(Ordering::SeqCst), 1);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn one_verify_refreshes_an_aged_set_while_the_others_use_it() {
            let secret = b"real-key-0123456789abcdef";
            let iss = issuer(vec![oct("fed-v1", secret)]).await;
            let c = client(&iss);
            let t = token(&iss.url, "fed-v1", secret);
            verify(&c, &t).await.expect("the first verify fetches");
            assert_eq!(iss.fetches.load(Ordering::SeqCst), 1);

            // A slow issuer at the max-age mark: every verify that arrives
            // while the refresh is in flight must use the cached set.
            expire(&c).await;
            iss.delay_ms.store(300, Ordering::SeqCst);
            let mut burst = tokio::task::JoinSet::new();
            for _ in 0..16 {
                let (c, t) = (c.clone(), t.clone());
                burst.spawn(async move { verify(&c, &t).await.map(|_| ()) });
            }
            while let Some(done) = burst.join_next().await {
                done.unwrap().expect("a verify during the refresh succeeds");
            }
            assert_eq!(
                iss.fetches.load(Ordering::SeqCst),
                2,
                "one refresh for the whole burst"
            );
        }

        #[tokio::test]
        async fn an_aged_set_drops_a_withdrawn_key_and_survives_an_unreachable_issuer() {
            let old = b"old-key-0123456789abcdef";
            let iss = issuer(vec![oct("fed-v1", old)]).await;
            let c = client(&iss);
            let t = token(&iss.url, "fed-v1", old);
            verify(&c, &t).await.expect("the original key verifies");

            // The issuer is down when the set ages out: the cached key keeps
            // verifying, and the failed refresh is not retried per verify.
            expire(&c).await;
            iss.down.store(true, Ordering::SeqCst);
            for _ in 0..3 {
                verify(&c, &t).await.expect("the cached key still verifies");
            }
            assert_eq!(iss.fetches.load(Ordering::SeqCst), 2);

            // Back up without the old key: once the set ages out again, the
            // withdrawn key stops verifying.
            iss.down.store(false, Ordering::SeqCst);
            *iss.jwks.lock().unwrap() =
                serde_json::json!({ "keys": [oct("fed-v1", b"new-key-0123456789abcdef")] });
            verify(&c, &t)
                .await
                .expect("a fresh cached set is used until it ages out");
            expire(&c).await;
            assert!(verify(&c, &t).await.is_err());
        }
    }
}
