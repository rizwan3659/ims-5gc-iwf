//! # iwf-core
//!
//! Domain model, ports, and shared types for the IMS ↔ 5G Core Interworking
//! Function (IWF).
//!
//! This crate is the hexagonal-architecture core: it defines the ubiquitous
//! language of the IWF (identities, authentication material, network-function
//! taxonomy) and the *ports* through which all I/O flows. It deliberately has
//! **zero** dependencies on transport, serialization formats, or
//! infrastructure crates; adapters live in `iwf-diameter`, `iwf-sba`,
//! `iwf-discovery`, and friends.
//!
//! Spec anchors used throughout: 3GPP TS 23.003 (identity formats),
//! TS 29.229 (Cx/Dx AVPs), TS 29.503 (Nudm), TS 29.509 (Nausf),
//! TS 33.501 (5G AKA key material).

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod auth;
pub mod error;
pub mod identity;
pub mod nf;
pub mod ports;

pub use auth::{AuthContext, AuthScheme};
pub use error::{CoreError, ResultExt};
pub use identity::{Gpsi, IdentityContext, Impi, Impu, Suci, Supi};
pub use nf::NfType;
