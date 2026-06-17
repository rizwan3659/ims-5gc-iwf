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

/// Protocol-agnostic disposition of a [`CoreError`] — *what kind* of failure
/// it is, independent of any wire encoding. Adapters map this onto their own
/// status space (Diameter Result-Code, HTTP status), so the transient/
/// permanent decision lives in one place and new [`CoreError`] variants are
/// forced (by the exhaustive match in [`CoreError::disposition`]) to declare
/// their disposition instead of silently defaulting to "permanent".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorDisposition {
    /// The request/command is not supported (no rule / unknown command).
    Unsupported,
    /// A required element/AVP was absent.
    MissingData,
    /// The request was malformed (bad identity / value).
    InvalidInput,
    /// The subscriber is unknown.
    NotFound,
    /// **Transient**: a downstream NF was unreachable or the transaction timed
    /// out — the peer may retry / route elsewhere.
    Unavailable,
    /// **Transient**: the node is shedding load (overload/backpressure).
    Overload,
    /// **Permanent**: the request cannot be satisfied / internal fault.
    Permanent,
}

impl ErrorDisposition {
    /// Whether the condition is transient (a retry could succeed).
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            ErrorDisposition::Unavailable | ErrorDisposition::Overload
        )
    }
}

impl CoreError {
    /// Classify this error into a protocol-agnostic [`ErrorDisposition`].
    ///
    /// Exhaustive (no `_` arm) so adding a `CoreError` variant fails to
    /// compile until its disposition is declared — the guard against the
    /// classification drift that a catch-all `=> Permanent` would hide.
    pub fn disposition(&self) -> ErrorDisposition {
        match self {
            CoreError::NoRule { .. } => ErrorDisposition::Unsupported,
            CoreError::MissingElement(_) => ErrorDisposition::MissingData,
            CoreError::InvalidIdentity { .. } => ErrorDisposition::InvalidInput,
            CoreError::UserUnknown => ErrorDisposition::NotFound,
            // Transient downstream conditions — a retry may succeed.
            CoreError::NfUnavailable { .. } | CoreError::DeadlineExceeded => {
                ErrorDisposition::Unavailable
            }
            CoreError::Overloaded => ErrorDisposition::Overload,
            // Permanent: the request cannot be satisfied or an adapter faulted.
            CoreError::UnableToComply(_) | CoreError::Adapter(_) => ErrorDisposition::Permanent,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_classifies_transient_vs_permanent() {
        // The deadline/downstream-unavailable cases are TRANSIENT (a retry may
        // succeed) — the regression this guards (F3) is them being lumped into
        // a permanent disposition.
        assert_eq!(
            CoreError::DeadlineExceeded.disposition(),
            ErrorDisposition::Unavailable
        );
        assert!(CoreError::DeadlineExceeded.disposition().is_transient());
        assert!(CoreError::NfUnavailable {
            nf: "HSS",
            reason: "timeout".to_owned()
        }
        .disposition()
        .is_transient());
        assert!(CoreError::Overloaded.disposition().is_transient());

        // Permanent / client-error cases are not transient.
        assert_eq!(
            CoreError::NoRule {
                application: 1,
                command: 2
            }
            .disposition(),
            ErrorDisposition::Unsupported
        );
        assert_eq!(
            CoreError::MissingElement("User-Name").disposition(),
            ErrorDisposition::MissingData
        );
        assert!(!CoreError::UnableToComply("x".to_owned())
            .disposition()
            .is_transient());
        assert!(!CoreError::Adapter("x".to_owned())
            .disposition()
            .is_transient());
    }
}
