//! # iwf-discovery
//!
//! NRF integration (TS 29.510): registration of the IWF as an NF instance,
//! periodic heartbeat with exponential backoff, NF discovery with a
//! TTL-bound endpoint cache, and health-driven cache invalidation feeding
//! [`iwf_core::ports::EndpointResolver`].
//!
//! Notification-based invalidation (Nnrf_NFManagement NFStatusSubscribe) is
//! polled-TTL in this implementation; the subscription callback endpoint is
//! listed as remaining scope in the README.

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod cache;
pub mod heartbeat;
pub mod nrf;
pub mod profile;

pub use cache::DiscoveryService;
pub use heartbeat::{HeartbeatConfig, HeartbeatTask};
pub use nrf::{NrfClient, NrfError};
pub use profile::NfProfile;
