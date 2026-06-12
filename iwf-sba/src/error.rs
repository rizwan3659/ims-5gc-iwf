//! SBA adapter errors.

use thiserror::Error;

/// Failures inside the SBA client stack. Converted to
/// [`iwf_core::error::CoreError::NfUnavailable`] (or `DeadlineExceeded`) at
/// the port boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SbaError {
    /// No endpoint known for the target NF type.
    #[error("no endpoint for {0}")]
    NoEndpoint(&'static str),

    /// The per-endpoint circuit breaker is open.
    #[error("circuit open for endpoint {0}")]
    CircuitOpen(String),

    /// The request could not be built (bad URI from rule substitution).
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Connection / protocol failure from Hyper.
    #[error("http transport: {0}")]
    Transport(String),

    /// The per-request deadline elapsed.
    #[error("request timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// All retry attempts exhausted; carries the final attempt's error.
    #[error("retries exhausted after {attempts} attempts: {last}")]
    RetriesExhausted {
        /// Number of attempts made.
        attempts: u32,
        /// Stringified final error.
        last: String,
    },
}
