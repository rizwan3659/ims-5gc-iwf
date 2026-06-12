//! # iwf-security
//!
//! Transport and application security for the IWF:
//!
//! - **TLS 1.3 only** server/client configuration over rustls, with
//!   hot-reloadable certificates ([`tls`]).
//! - **OAuth2 client-credentials** token cache with proactive refresh at
//!   80 % of TTL ([`oauth`]), implementing
//!   [`iwf_core::ports::TokenProvider`].
//! - **JWT validation** — signature, expiry, audience and scope
//!   ([`jwt`]).
//! - **RBAC** for the admin API ([`rbac`]).
//!
//! Secrets policy: nothing in this crate reads secrets from configuration
//! files; certificate/key paths point at Kubernetes Secret volume mounts and
//! OAuth client credentials arrive via environment injection (see
//! `deploy/`).

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod jwt;
pub mod oauth;
pub mod rbac;
pub mod tls;

pub use jwt::{JwtValidator, ValidatedClaims};
pub use oauth::{OAuthConfig, TokenCache, TokenFetcher};
pub use rbac::{Permission, Role};
pub use tls::{ReloadableServerTls, TlsError, TlsPaths};
