//! Shared plumbing for the MCPG CLI family.
//!
//! Everything in here is *client-side*: the OIDC PKCE login flow and the
//! credentials file it maintains ([`login`]), the JWKS-verifying OIDC client
//! it builds on ([`oidc`] — also consumed by the control-plane server for
//! its browser login + Bearer verification), the Bearer-authenticated HTTP
//! client CP commands use ([`client`]), the SSE phase-ladder renderer for
//! provisioning streams ([`stream`]), and the `~/.mcpg` state-dir
//! conventions ([`paths`]).
//!
//! This crate must stay free of `mcpg-control-plane-server` and
//! `mcpg-control-plane-core`: the whole point of the extraction is that a
//! tenant CLI links none of the server's sqlx/tonic/axum-server dependency
//! tree. License-claims types live in cp-core, so anything
//! license-*schema*-aware (the `LicenseClaims` verify with its `lic_ver`
//! gate) stays in the server crate, layered on [`oidc::OidcClient::verify_signed_claims`].

// Module ↔ feature map (see Cargo.toml): light consumers pick what they
// need — the gateway links only `paths`.
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "context")]
pub mod context;
#[cfg(feature = "login")]
pub mod login;
#[cfg(feature = "oidc")]
pub mod oidc;
#[cfg(feature = "paths")]
pub mod paths;
#[cfg(feature = "stream")]
pub mod stream;
