//! Diameter stack error taxonomy.

use thiserror::Error;

/// Errors produced by the Diameter codec, transport, peer FSM and router.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DiameterError {
    /// Frame shorter than the 20-octet Diameter header (RFC 6733 §3).
    #[error("truncated header: got {0} octets, need 20")]
    TruncatedHeader(usize),

    /// Header version octet was not 1 (RFC 6733 §3).
    #[error("unsupported protocol version {0}")]
    BadVersion(u8),

    /// Message-Length field disagrees with the actual buffer.
    #[error("bad message length: declared {declared}, buffer {actual}")]
    BadMessageLength {
        /// 24-bit length from the header.
        declared: usize,
        /// Octets actually available.
        actual: usize,
    },

    /// Message-Length is not a multiple of 4 (RFC 6733 §3).
    #[error("message length {0} not 32-bit aligned")]
    UnalignedLength(usize),

    /// An AVP header or payload ran past the end of the message.
    #[error("truncated AVP at offset {offset}: {reason}")]
    TruncatedAvp {
        /// Offset of the AVP within the message body.
        offset: usize,
        /// Specific bound that failed.
        reason: &'static str,
    },

    /// AVP-Length smaller than the minimal header for its flag set.
    #[error("invalid AVP length {length} for code {code}")]
    InvalidAvpLength {
        /// AVP code.
        code: u32,
        /// Declared AVP length.
        length: usize,
    },

    /// Grouped-AVP recursion exceeded the safety bound (decompression-bomb
    /// defence; the deepest 3GPP grouping in Cx/Sh is 4 levels).
    #[error("grouped AVP nesting exceeds depth {0}")]
    NestingTooDeep(usize),

    /// AVP payload could not be read as the requested data type.
    #[error("AVP {code} is not a valid {expected}")]
    WrongType {
        /// AVP code.
        code: u32,
        /// Type name requested by the caller.
        expected: &'static str,
    },

    /// A mandatory AVP (M-bit semantics, RFC 6733 §4.1) was absent.
    #[error("missing mandatory AVP {0}")]
    MissingAvp(&'static str),

    /// Frame exceeds the configured maximum (DoS guard).
    #[error("frame of {got} octets exceeds maximum {max}")]
    FrameTooLarge {
        /// Declared frame size.
        got: usize,
        /// Configured ceiling.
        max: usize,
    },

    /// Underlying socket failure.
    #[error("transport: {0}")]
    Io(#[from] std::io::Error),

    /// The peer FSM rejected an event in its current state (RFC 6733 §5.6).
    #[error("protocol violation in state {state}: {event}")]
    FsmViolation {
        /// FSM state name at the time of the event.
        state: &'static str,
        /// Offending event name.
        event: &'static str,
    },

    /// No peer in OPEN state could be selected for the destination.
    #[error("no route to realm {realm} application {application}")]
    NoRoute {
        /// Destination-Realm of the request.
        realm: String,
        /// Application-Id of the request.
        application: u32,
    },

    /// The pending-transaction table has no entry for this answer.
    #[error("unmatched answer hop-by-hop {0:#010x}")]
    UnmatchedAnswer(u32),

    /// The peer closed or watchdog declared it failed mid-transaction.
    #[error("peer {0} unavailable")]
    PeerUnavailable(String),

    /// Outbound queue full — backpressure reached the Diameter layer.
    #[error("peer {0} send queue full")]
    Backpressure(String),
}
