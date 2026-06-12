//! # iwf-sba
//!
//! SBA HTTP/2 client stack: the adapter implementing
//! [`iwf_core::ports::SbaPort`] over Hyper, with per-endpoint circuit
//! breaking, idempotency-aware retries, OAuth2 bearer injection, and
//! `traceparent` propagation (TS 29.500 §6.10 / W3C Trace Context).
//!
//! Transport security: the connector speaks cleartext HTTP/2 (h2c) inside
//! the cluster, with mTLS provided by the service mesh (Istio overlay in
//! `deploy/istio/`); direct rustls-terminated h2 is tracked as remaining
//! scope in `iwf-security` (see README "Remaining scope").

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod breaker;
pub mod client;
pub mod error;
pub mod retry;

pub use breaker::{BreakerConfig, CircuitBreaker};
pub use client::{SbaClient, SbaClientConfig};
pub use error::SbaError;
pub use retry::RetryPolicy;
