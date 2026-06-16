//! Ports (hexagonal architecture): the only surfaces through which domain
//! logic touches the outside world.
//!
//! Adapters: `iwf-sba` implements [`SbaPort`]; `iwf-discovery` implements
//! [`EndpointResolver`]; `iwf-security` implements [`TokenProvider`].
//! Test doubles for all three live in the crates' test suites.

use std::collections::BTreeMap;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::nf::NfType;

/// Method of a service-based-interface operation. Modelled abstractly so the
/// domain does not depend on an HTTP crate; the SBA adapter maps 1:1 onto
/// HTTP/2 methods per TS 29.501 §4.6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SbiMethod {
    /// Resource retrieval — safe and idempotent, retryable.
    Get,
    /// Resource creation / custom operation — not blindly retryable.
    Post,
    /// Full replacement — idempotent, retryable.
    Put,
    /// Partial modification — retryable only with If-Match semantics.
    Patch,
    /// Removal — idempotent, retryable.
    Delete,
}

impl SbiMethod {
    /// Whether the retry policy may re-issue this operation after an
    /// ambiguous failure (connection reset, timeout) without risking a
    /// duplicate side effect.
    pub fn idempotent(&self) -> bool {
        matches!(self, SbiMethod::Get | SbiMethod::Put | SbiMethod::Delete)
    }
}

/// An abstract SBI request produced by the translation engine.
#[derive(Debug, Clone)]
pub struct SbiRequest {
    /// Operation method.
    pub method: SbiMethod,
    /// Target NF type; endpoint selection is the adapter's concern.
    pub nf_type: NfType,
    /// URI path with all template variables already substituted.
    pub path: String,
    /// Query parameters in deterministic order (stable for tests/tracing).
    pub query: BTreeMap<String, String>,
    /// JSON body, if any, already serialized.
    pub body: Option<Bytes>,
    /// Correlation id propagated end-to-end for tracing and logs.
    pub correlation_id: String,
}

/// An abstract SBI response handed back to the translation engine.
#[derive(Debug, Clone)]
pub struct SbiResponse {
    /// HTTP status code as a plain integer (the domain only branches on it).
    pub status: u16,
    /// Raw JSON body; mapping decodes it lazily.
    pub body: Bytes,
}

/// Port: send one SBI request to a 5GC NF and await the response.
///
/// Implementations own endpoint selection, OAuth2 tokens, retries, circuit
/// breaking, and connection pooling. A returned `Err` means the request
/// could not be completed at all (after policy-permitted retries); an HTTP
/// error status arrives as `Ok` with that status so rules can map it.
#[async_trait]
pub trait SbaPort: Send + Sync {
    /// Execute the request within the transaction's remaining deadline.
    async fn send(&self, request: SbiRequest) -> Result<SbiResponse, CoreError>;
}

/// A resolved NF endpoint, as produced by NRF discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfEndpoint {
    /// NF instance id (UUID string per TS 29.510).
    pub instance_id: String,
    /// Scheme + authority, e.g. `https://udm-1.5gc.example:8443`.
    pub base_uri: String,
    /// Relative selection priority (lower wins, TS 29.510 `priority`).
    pub priority: u16,
    /// Load-balancing weight among same-priority endpoints.
    pub capacity: u16,
}

/// Port: resolve healthy endpoints for an NF type.
#[async_trait]
pub trait EndpointResolver: Send + Sync {
    /// Return candidate endpoints, best first. Empty means "none known".
    async fn resolve(&self, nf_type: NfType) -> Result<Vec<NfEndpoint>, CoreError>;

    /// Report an endpoint failure so the resolver can quarantine it and
    /// trigger re-discovery.
    async fn report_failure(&self, nf_type: NfType, instance_id: &str);
}

/// Port: supply OAuth2 access tokens for SBA requests (TS 29.510 §5.4.2,
/// Nnrf_AccessToken). Implementations cache and proactively refresh.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    /// A currently-valid bearer token for the given target NF type/scope.
    async fn bearer_token(&self, target: NfType) -> Result<String, CoreError>;
}

/// A stateful association between a Diameter session and a 5GC resource,
/// created by a forward flow and consulted/torn down by a later one.
///
/// One type serves every interface that needs server-push or session
/// teardown — keyed by `kind`:
/// - **sh**: an Sh `SNR` subscription → the AS to route a `PNR` back to.
/// - **rx**: an Rx `AAR` → the Npcf app-session id an `STR` must delete and
///   the AF a `RAR`/`ASR` notifies.
/// - **ro**: an Ro initial `CCR` → the Nchf charging resource later
///   `CCR-Update`/`Terminate` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// Diameter Origin-Host of the peer to originate back to (AS / P-CSCF /
    /// S-CSCF). The routing key into the peer registry.
    pub peer_host: String,
    /// Origin-Realm of that peer (Destination-Realm of originated requests).
    pub peer_realm: String,
    /// Subscriber/user identity carried in the originated request
    /// (User-Identity / Public-Identity / MSISDN).
    pub identity: String,
    /// The originating request's Session-Id, when the originated request must
    /// reuse it (e.g. Rx RAR shares the AAR session).
    pub session_id: Option<String>,
    /// The 5GC resource handle this binding owns (Npcf appSessionId, Nchf
    /// charging resource id, Nhss subscription id) — used to address the
    /// follow-up SBI call.
    pub resource_ref: Option<String>,
    /// Binding family (sh / rx / ro), also the notification route segment.
    pub kind: String,
}

/// Port: hold [`Binding`]s for the lifetime of a Diameter session.
///
/// The engine `put`s on a successful forward flow and `take`s on teardown;
/// the notification server `get`s to route an inbound NF event. The default
/// implementation is in-memory (lost on restart — the peer re-subscribes);
/// the port leaves room for a shared/persistent backend.
#[async_trait]
pub trait BindingStore: Send + Sync {
    /// Record (or replace) the binding under `id`.
    async fn put(&self, id: String, binding: Binding);
    /// Look up a binding without removing it (notification routing).
    async fn get(&self, id: &str) -> Option<Binding>;
    /// Remove and return a binding (session teardown / undeliverable push).
    async fn take(&self, id: &str) -> Option<Binding>;
}
