//! Minimal NRF HTTP client: Nnrf_NFManagement (register, heartbeat,
//! deregister) and Nnrf_NFDiscovery (search). TS 29.510.

use std::time::Duration;

use bytes::Bytes;
use http::{header, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use iwf_core::nf::NfType;
use thiserror::Error;

use crate::profile::{NfProfile, SearchResult};

/// NRF client failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NrfError {
    /// Transport-level failure.
    #[error("nrf transport: {0}")]
    Transport(String),
    /// Unexpected HTTP status from the NRF.
    #[error("nrf returned {status} for {operation}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// Operation name for diagnostics.
        operation: &'static str,
    },
    /// The NRF no longer knows this registration (heartbeat 404) — the
    /// caller must re-register.
    #[error("nf instance not found at nrf")]
    NotRegistered,
    /// Malformed response body.
    #[error("nrf response decode: {0}")]
    Decode(String),
    /// Request timed out.
    #[error("nrf request timed out")]
    Timeout,
}

/// NRF client bound to one NRF base URI.
pub struct NrfClient {
    http: Client<HttpConnector, Full<Bytes>>,
    base_uri: String,
    timeout: Duration,
    /// `requester-nf-type` sent on discovery queries. 5GC NRFs (Open5GS
    /// included) authorize discovery by requester type: a UDM is only
    /// returned to types that legitimately consume it (AMF/AUSF/SMF/SCP),
    /// not to AF/NEF. Deployments therefore set this to a type their NRF
    /// permits (e.g. `AUSF`, closest to the IWF's Cx/MAR auth role).
    requester_nf_type: String,
}

impl std::fmt::Debug for NrfClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NrfClient")
            .field("base_uri", &self.base_uri)
            .finish()
    }
}

impl NrfClient {
    /// Client for the NRF at `base_uri` using HTTP/1.1 (test mocks).
    pub fn new(base_uri: impl Into<String>, timeout: Duration) -> Self {
        Self::with_http2(base_uri, timeout, false)
    }

    /// Client for the NRF at `base_uri`. Real 5GC SBI (Open5GS included) is
    /// HTTP/2 cleartext (h2c) prior-knowledge per TS 29.500 §5.2, so set
    /// `http2_only` for production; HTTP/1.1 (`false`) is for axum test mocks.
    /// `requester_nf_type` is the discovery requester label (see field docs).
    pub fn with_http2(base_uri: impl Into<String>, timeout: Duration, http2_only: bool) -> Self {
        Self::configured(base_uri, timeout, http2_only, "IWF")
    }

    /// Fully-configured constructor.
    pub fn configured(
        base_uri: impl Into<String>,
        timeout: Duration,
        http2_only: bool,
        requester_nf_type: impl Into<String>,
    ) -> Self {
        let mut builder = Client::builder(TokioExecutor::new());
        if http2_only {
            builder.http2_only(true);
        }
        NrfClient {
            http: builder.build(HttpConnector::new()),
            base_uri: base_uri.into().trim_end_matches('/').to_owned(),
            timeout,
            requester_nf_type: requester_nf_type.into(),
        }
    }

    async fn call(
        &self,
        method: http::Method,
        path: &str,
        body: Option<(serde_json::Value, &'static str)>,
        operation: &'static str,
    ) -> Result<(u16, Bytes), NrfError> {
        let uri = format!("{}{}", self.base_uri, path);
        let mut builder = Request::builder()
            .method(method)
            .uri(&uri)
            .header(header::ACCEPT, "application/json");
        if let Some((_, content_type)) = &body {
            builder = builder.header(header::CONTENT_TYPE, *content_type);
        }
        let body = body.map(|(v, _)| v);
        let request = builder
            .body(Full::new(
                body.map(|b| Bytes::from(b.to_string())).unwrap_or_default(),
            ))
            .map_err(|e| NrfError::Transport(e.to_string()))?;

        let response = tokio::time::timeout(self.timeout, self.http.request(request))
            .await
            .map_err(|_| NrfError::Timeout)?
            .map_err(|e| NrfError::Transport(e.to_string()))?;
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| NrfError::Transport(format!("{operation} body: {e}")))?
            .to_bytes();
        Ok((status, bytes))
    }

    /// Register (or replace) this NF profile:
    /// `PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}` (TS 29.510 §5.2.2.2).
    /// Returns the profile echoed by the NRF (it may set `heartBeatTimer`).
    pub async fn register(&self, profile: &NfProfile) -> Result<NfProfile, NrfError> {
        let path = format!("/nnrf-nfm/v1/nf-instances/{}", profile.nf_instance_id);
        let body = serde_json::to_value(profile).map_err(|e| NrfError::Decode(e.to_string()))?;
        let (status, bytes) = self
            .call(
                http::Method::PUT,
                &path,
                Some((body, "application/json")),
                "register",
            )
            .await?;
        match status {
            200 | 201 => serde_json::from_slice(&bytes)
                .map_err(|e| NrfError::Decode(format!("register response: {e}"))),
            s => Err(NrfError::Status {
                status: s,
                operation: "register",
            }),
        }
    }

    /// Heartbeat: `PATCH /nnrf-nfm/v1/nf-instances/{id}` with a JSON-Patch
    /// refreshing `nfStatus` (TS 29.510 §5.2.2.3.2).
    pub async fn heartbeat(&self, instance_id: &str) -> Result<(), NrfError> {
        let path = format!("/nnrf-nfm/v1/nf-instances/{instance_id}");
        let patch = serde_json::json!([
            { "op": "replace", "path": "/nfStatus", "value": "REGISTERED" }
        ]);
        // RFC 6902 / TS 29.510: PATCH bodies are application/json-patch+json.
        // Open5GS rejects application/json on heartbeat with 400.
        let (status, _) = self
            .call(
                http::Method::PATCH,
                &path,
                Some((patch, "application/json-patch+json")),
                "heartbeat",
            )
            .await?;
        match status {
            200 | 204 => Ok(()),
            404 => Err(NrfError::NotRegistered),
            s => Err(NrfError::Status {
                status: s,
                operation: "heartbeat",
            }),
        }
    }

    /// Deregister: `DELETE /nnrf-nfm/v1/nf-instances/{id}` (graceful
    /// shutdown path).
    pub async fn deregister(&self, instance_id: &str) -> Result<(), NrfError> {
        let path = format!("/nnrf-nfm/v1/nf-instances/{instance_id}");
        let (status, _) = self
            .call(http::Method::DELETE, &path, None, "deregister")
            .await?;
        match status {
            204 => Ok(()),
            s => Err(NrfError::Status {
                status: s,
                operation: "deregister",
            }),
        }
    }

    /// Discover instances of `target`:
    /// `GET /nnrf-disc/v1/nf-instances?target-nf-type=&requester-nf-type=`
    /// (TS 29.510 §5.3.2.2).
    pub async fn discover(&self, target: NfType) -> Result<SearchResult, NrfError> {
        let path = format!(
            "/nnrf-disc/v1/nf-instances?target-nf-type={}&requester-nf-type={}",
            target.as_str(),
            self.requester_nf_type
        );
        let (status, bytes) = self
            .call(http::Method::GET, &path, None, "discover")
            .await?;
        match status {
            200 => serde_json::from_slice(&bytes)
                .map_err(|e| NrfError::Decode(format!("search result: {e}"))),
            s => Err(NrfError::Status {
                status: s,
                operation: "discover",
            }),
        }
    }
}
