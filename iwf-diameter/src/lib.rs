//! # iwf-diameter
//!
//! Standalone Diameter stack: RFC 6733 base protocol plus the 3GPP
//! applications the IWF terminates (Cx, Dx, Sh, SWx, Zh).
//!
//! Design highlights (see `docs/adr/0002-diameter-codec.md`):
//! - **Zero-copy decode**: AVP payloads are `bytes::Bytes` slices into the
//!   single read buffer of the connection; no per-AVP `Vec<u8>` copies.
//! - **Strict validation**: every length field is checked against the
//!   enclosing buffer before slicing; malformed input can never panic.
//! - **Peer FSM** per RFC 6733 §5.6 with RFC 3539 watchdog behaviour.
//! - **Realm/application routing** with round-robin, least-connections and
//!   weighted balancing across peer groups.
//! - **Session correlation** via a `DashMap` keyed on Hop-by-Hop id.

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod avp;
pub mod base;
pub mod dictionary;
pub mod error;
pub mod message;
pub mod peer;
pub mod routing;
pub mod session;
pub mod transport;

pub use avp::{Avp, AvpFlags, AvpValue};
pub use error::DiameterError;
pub use message::{CommandFlags, Header, Message, MessageBuilder};
