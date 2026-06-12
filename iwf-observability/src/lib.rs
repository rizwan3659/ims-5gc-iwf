//! # iwf-observability
//!
//! Metrics, structured logging and correlation for the IWF.
//!
//! - **Metrics**: the Prometheus families named in the operational spec,
//!   pre-registered on one registry and rendered for `:9090/metrics`.
//! - **Logging**: `tracing` with a JSON subscriber; the active level is
//!   hot-switchable through the handle exposed to the admin API.
//! - **Correlation**: UUID correlation ids injected at ingress and carried
//!   through every span/log line and outbound SBA request.
//! - **PII policy**: identity values (IMPI/IMPU/SUPI/MSISDN) are never
//!   logged unless the crate is built with `--features pii-logging`
//!   (see [`pii`]).
//!
//! OTLP span export (OpenTelemetry) is feature-gated behind `otlp` and
//! disabled by default in this build; the span structure (one span per
//! Diameter transaction, child span per SBA call) is already in place via
//! `tracing` instrumentation.

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod logging;
pub mod metrics;

pub use logging::{init_logging, LogHandle};
pub use metrics::Metrics;

/// Generate a fresh correlation id for an ingress transaction.
pub fn correlation_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// PII rendering helpers honouring the `pii-logging` feature.
pub mod pii {
    /// Render a subscriber identity for logs. Without the `pii-logging`
    /// feature this is an irreversible redaction (length + stable suffix
    /// hash) sufficient for support correlation without exposure.
    #[cfg(not(feature = "pii-logging"))]
    pub fn render(identity: &str) -> String {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for b in identity.bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        format!("pii:len{}:{:08x}", identity.len(), (hash >> 32) as u32)
    }

    /// Render a subscriber identity for logs (PII build: cleartext).
    #[cfg(feature = "pii-logging")]
    pub fn render(identity: &str) -> String {
        identity.to_owned()
    }

    #[cfg(all(test, not(feature = "pii-logging")))]
    mod tests {
        #[test]
        fn redaction_is_stable_and_opaque() {
            let a = super::render("alice@ims.example.org");
            let b = super::render("alice@ims.example.org");
            assert_eq!(a, b, "stable for correlation");
            assert!(!a.contains("alice"), "no cleartext identity");
            assert!(a.starts_with("pii:len21:"));
        }
    }
}
