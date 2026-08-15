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
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;

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
        OsRng.fill_bytes(&mut bytes);
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
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Minimum spacing between forced JWKS refetches (a kid-miss storm — e.g. a
/// flood of forged tokens with random kids — must not become a request
/// amplifier against the IdP).
const JWKS_REFETCH_COOLDOWN: Duration = Duration::from_secs(30);

/// OIDC client — caches the discovery doc and JWKS.
#[derive(Clone)]
pub struct OidcClient {
    issuer: Url,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    http: reqwest::Client,
    discovery: Arc<RwLock<Option<DiscoveryDoc>>>,
    jwks: Arc<RwLock<Option<jsonwebtoken::jwk::JwkSet>>>,
    /// Last forced (kid-miss) JWKS refetch, for the cooldown.
    jwks_refetched_at: Arc<RwLock<Option<std::time::Instant>>>,
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

    async fn jwks(&self) -> anyhow::Result<jsonwebtoken::jwk::JwkSet> {
        if let Some(j) = self.jwks.read().await.clone() {
            return Ok(j);
        }
        self.fetch_jwks().await
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
        *self.jwks.write().await = Some(set.clone());
        Ok(set)
    }

    /// Resolve a token's `kid` against the cached JWKS, REFETCHING once on a
    /// miss: an IdP signing-key rotation publishes new kids, and without the
    /// refetch every login/verify breaks until a restart. The refetch is
    /// cooldown-guarded so a flood of forged tokens with random kids can't
    /// amplify into a request storm against the IdP.
    async fn jwk_for_kid(&self, kid: &str) -> anyhow::Result<jsonwebtoken::jwk::Jwk> {
        let set = self.jwks().await?;
        if let Some(jwk) = set.find(kid) {
            return Ok(jwk.clone());
        }
        // Unknown kid — maybe a rotation. Refetch at most once per cooldown.
        // Check-and-set ATOMICALLY under the write lock: a read-then-write
        // gap would let a flood of concurrent forged-kid tokens each pass the
        // check and each fire a fetch, defeating the anti-amplification bound
        // (this path is reachable unauthenticated via stateless Bearer
        // verify). Set-before-fetch is deliberate — a failed fetch burning the
        // window is the correct fail-safe under a flood.
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
        if allow {
            tracing::info!(%kid, issuer = %self.issuer, "unknown kid — refetching JWKS (possible key rotation)");
            let fresh = self.fetch_jwks().await?;
            if let Some(jwk) = fresh.find(kid) {
                return Ok(jwk.clone());
            }
        }
        anyhow::bail!("kid {kid} not in the issuer's JWKS")
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
    /// leeway is 60s, and an unknown `kid` triggers one cooldown-guarded
    /// JWKS refetch (key rotation). Generic so callers with richer claims
    /// types (the server's `LicenseClaims` lives in a crate this one
    /// deliberately doesn't depend on) can layer on top.
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
        let jwk = self.jwk_for_kid(kid).await?;
        let key =
            DecodingKey::from_jwk(&jwk).map_err(|e| anyhow::anyhow!("build decoding key: {e}"))?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.issuer.as_str().trim_end_matches('/')]);
        validation.set_audience(audience);
        validation.leeway = 60;
        validation.validate_nbf = validate_nbf;
        let data = jsonwebtoken::decode::<T>(token, &key, &validation)
            .map_err(|e| anyhow::anyhow!("verify claims: {e}"))?;
        Ok(data.claims)
    }

    /// Verify the id_token and return its claims. Trusts the
    /// JWKS endpoint's published keys; checks issuer + audience
    /// (this client's `client_id`).
    pub async fn verify_id_token(&self, id_token: &str) -> anyhow::Result<IdTokenClaims> {
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
}
