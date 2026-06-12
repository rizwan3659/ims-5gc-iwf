//! Domain-level error taxonomy.
//!
//! Adapter crates define their own `thiserror` enums (transport faults,
//! codec faults, HTTP faults) and convert into [`CoreError`] only at the
//! port boundary, so domain logic never matches on infrastructure detail.

use thiserror::Error;

/// Errors that can be produced by domain logic or surfaced across a port.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// An identity string failed format validation (TS 23.003).
    #[error("invalid {kind}: {reason}")]
    InvalidIdentity {
        /// Identity class (IMPI, IMPU, SUPI, SUCI, GPSI).
        kind: &'static str,
        /// Human-readable validation failure; never contains the raw value
        /// (PII discipline — see `iwf-observability` logging policy).
        reason: String,
    },

    /// The subscriber is not known to the network (maps to Diameter
    /// `DIAMETER_ERROR_USER_UNKNOWN` 5001 / HTTP 404 per TS 29.229 §6.2,
    /// TS 29.503).
    #[error("user unknown")]
    UserUnknown,

    /// The peer network function answered but the answer cannot satisfy the
    /// request (maps to `DIAMETER_UNABLE_TO_COMPLY` 5012 / HTTP 5xx).
    #[error("unable to comply: {0}")]
    UnableToComply(String),

    /// A downstream NF could not be reached within the transaction budget.
    #[error("upstream {nf} unavailable: {reason}")]
    NfUnavailable {
        /// Target NF type name (UDM, AUSF, ...).
        nf: &'static str,
        /// Cause summary (circuit open, timeout, connect refused...).
        reason: String,
    },

    /// The transaction exceeded its end-to-end latency budget and was shed.
    #[error("transaction deadline exceeded")]
    DeadlineExceeded,

    /// Ingress backpressure: the node is shedding load to protect the p99
    /// latency target (maps to `DIAMETER_TOO_BUSY` 3004).
    #[error("overloaded, request shed at ingress")]
    Overloaded,

    /// No translation rule matched the incoming request.
    #[error("no translation rule for application {application} command {command}")]
    NoRule {
        /// Diameter Application-Id of the unmatched request.
        application: u32,
        /// Command-Code of the unmatched request.
        command: u32,
    },

    /// A required data element was absent from a message or mapping context.
    #[error("missing required element: {0}")]
    MissingElement(&'static str),

    /// Catch-all for adapter faults crossing a port; the adapter keeps the
    /// structured cause in its own error type and provides a summary here.
    #[error("adapter fault: {0}")]
    Adapter(String),
}

/// Convenience conversions used at port boundaries.
pub trait ResultExt<T> {
    /// Convert any error into [`CoreError::Adapter`] with context.
    fn adapter_err(self, context: &'static str) -> Result<T, CoreError>;
}

impl<T, E: std::fmt::Display> ResultExt<T> for Result<T, E> {
    fn adapter_err(self, context: &'static str) -> Result<T, CoreError> {
        self.map_err(|e| CoreError::Adapter(format!("{context}: {e}")))
    }
}
