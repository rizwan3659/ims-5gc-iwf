//! The SBA client: implements [`SbaPort`] over a pooled Hyper client with
//! endpoint resolution, OAuth2 bearer injection, circuit breaking,
//! idempotency-aware retries and per-request deadlines.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use iwf_core::error::CoreError;
use iwf_core::ports::{
    EndpointResolver, NfEndpoint, SbaPort, SbiMethod, SbiRequest, SbiResponse, TokenProvider,
};

use crate::breaker::{BreakerConfig, CircuitBreaker};
use crate::error::SbaError;
use crate::retry::RetryPolicy;

/// Client tuning.
#[derive(Debug, Clone)]
pub struct SbaClientConfig {
    /// Per-attempt deadline. The 5 ms internal-latency budget excludes NF
    /// round trips, but the end-to-end p99 < 20 ms target bounds this; the
    /// default leaves headroom for one retry inside the budget.
    pub request_timeout: Duration,
    /// Retry policy (idempotent operations only).
    pub retry: RetryPolicy,
    /// Circuit-breaker tuning.
    pub breaker: BreakerConfig,
    /// Negotiate HTTP/2 prior knowledge (TS 29.500 §5.2 requires HTTP/2 on
    /// SBI; tests with HTTP/1.1 mocks set this to false).
    pub http2_only: bool,
}

impl Default for SbaClientConfig {
    fn default() -> Self {
        SbaClientConfig {
            request_timeout: Duration::from_millis(1500),
            retry: RetryPolicy::default(),
            breaker: BreakerConfig::default(),
            http2_only: true,
        }
    }
}

/// Pooled, breaker-guarded SBA client.
pub struct SbaClient {
    http: Client<HttpConnector, Full<Bytes>>,
    resolver: Arc<dyn EndpointResolver>,
    tokens: Arc<dyn TokenProvider>,
    breaker: CircuitBreaker,
    config: SbaClientConfig,
}

impl std::fmt::Debug for SbaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SbaClient")
            .field("config", &self.config)
            .finish()
    }
}

impl SbaClient {
    /// Build the client. Hyper's pool multiplexes HTTP/2 streams over one
    /// connection per endpoint, which is what carries the 100k TPS target —
    /// no per-request connection setup on the hot path.
    pub fn new(
        resolver: Arc<dyn EndpointResolver>,
        tokens: Arc<dyn TokenProvider>,
        config: SbaClientConfig,
    ) -> Self {
        let mut builder = Client::builder(TokioExecutor::new());
        builder.pool_idle_timeout(Duration::from_secs(90));
        if config.http2_only {
            builder.http2_only(true);
        }
        SbaClient {
            http: builder.build(HttpConnector::new()),
            resolver,
            tokens,
            breaker: CircuitBreaker::new(config.breaker),
            config,
        }
    }

    fn method_of(m: SbiMethod) -> http::Method {
        match m {
            SbiMethod::Get => http::Method::GET,
            SbiMethod::Post => http::Method::POST,
            SbiMethod::Put => http::Method::PUT,
            SbiMethod::Patch => http::Method::PATCH,
            SbiMethod::Delete => http::Method::DELETE,
        }
    }

    fn build_uri(endpoint: &NfEndpoint, req: &SbiRequest) -> Result<http::Uri, SbaError> {
        let mut uri = format!("{}{}", endpoint.base_uri.trim_end_matches('/'), req.path);
        if !req.query.is_empty() {
            uri.push('?');
            let mut first = true;
            for (k, v) in &req.query {
                if !first {
                    uri.push('&');
                }
                first = false;
                uri.push_str(&percent_encode(k));
                uri.push('=');
                uri.push_str(&percent_encode(v));
            }
        }
        uri.parse()
            .map_err(|e| SbaError::InvalidRequest(format!("uri {uri}: {e}")))
    }

    async fn send_once(
        &self,
        endpoint: &NfEndpoint,
        req: &SbiRequest,
        token: &str,
    ) -> Result<SbiResponse, SbaError> {
        let uri = Self::build_uri(endpoint, req)?;
        let mut builder = Request::builder()
            .method(Self::method_of(req.method))
            .uri(uri)
            .header(header::ACCEPT, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("x-correlation-id", &req.correlation_id);
        if req.body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let request = builder
            .body(Full::new(req.body.clone().unwrap_or_default()))
            .map_err(|e| SbaError::InvalidRequest(e.to_string()))?;

        let response =
            tokio::time::timeout(self.config.request_timeout, self.http.request(request))
                .await
                .map_err(|_| SbaError::Timeout(self.config.request_timeout))?
                .map_err(|e| SbaError::Transport(e.to_string()))?;

        let status = response.status().as_u16();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| SbaError::Transport(format!("body: {e}")))?
            .to_bytes();
        Ok(SbiResponse { status, body })
    }
}

#[async_trait]
impl SbaPort for SbaClient {
    async fn send(&self, request: SbiRequest) -> Result<SbiResponse, CoreError> {
        let endpoints = self.resolver.resolve(request.nf_type).await?;
        if endpoints.is_empty() {
            return Err(CoreError::NfUnavailable {
                nf: request.nf_type.as_str(),
                reason: "no endpoints discovered".to_owned(),
            });
        }
        let token = self.tokens.bearer_token(request.nf_type).await?;

        let mut attempt: u32 = 0;
        let mut last_error = SbaError::NoEndpoint(request.nf_type.as_str());

        // Walk endpoints round-robin across attempts so a retry after a
        // connect failure lands on a different instance (NRF failover
        // within the transaction, per the 500 ms reroute requirement).
        'attempts: while attempt < self.config.retry.max_attempts {
            for endpoint in &endpoints {
                if !self.breaker.admit(&endpoint.instance_id) {
                    tracing::debug!(
                        endpoint = %endpoint.instance_id,
                        "circuit open, skipping endpoint"
                    );
                    continue;
                }
                attempt += 1;
                match self.send_once(endpoint, &request, &token).await {
                    Ok(response) => {
                        if response.status >= 500 {
                            // A 5xx is a valid SBI answer that the rules map,
                            // but it still counts against endpoint health.
                            if self.breaker.record_failure(&endpoint.instance_id) {
                                self.resolver
                                    .report_failure(request.nf_type, &endpoint.instance_id)
                                    .await;
                            }
                        } else {
                            self.breaker.record_success(&endpoint.instance_id);
                        }
                        return Ok(response);
                    }
                    Err(e) => {
                        tracing::warn!(
                            endpoint = %endpoint.instance_id,
                            error = %e,
                            attempt,
                            "SBI attempt failed"
                        );
                        if self.breaker.record_failure(&endpoint.instance_id) {
                            self.resolver
                                .report_failure(request.nf_type, &endpoint.instance_id)
                                .await;
                        }
                        last_error = e;
                        if !self.config.retry.may_retry(request.method, attempt) {
                            break 'attempts;
                        }
                        tokio::time::sleep(self.config.retry.backoff(attempt)).await;
                    }
                }
            }
            if attempt == 0 {
                // Every endpoint's breaker is open.
                last_error = SbaError::CircuitOpen("all endpoints".to_owned());
                break;
            }
        }

        Err(CoreError::NfUnavailable {
            nf: request.nf_type.as_str(),
            reason: SbaError::RetriesExhausted {
                attempts: attempt,
                last: last_error.to_string(),
            }
            .to_string(),
        })
    }
}

/// Percent-encode for URI query components (RFC 3986 unreserved set kept).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b))
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::http::HeaderMap;
    use axum::routing::get;
    use axum::Router;
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct StaticResolver {
        endpoints: Vec<NfEndpoint>,
        failures: AtomicU32,
    }

    #[async_trait]
    impl EndpointResolver for StaticResolver {
        async fn resolve(&self, _nf: iwf_core::nf::NfType) -> Result<Vec<NfEndpoint>, CoreError> {
            Ok(self.endpoints.clone())
        }
        async fn report_failure(&self, _nf: iwf_core::nf::NfType, _id: &str) {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct StaticTokens;

    #[async_trait]
    impl TokenProvider for StaticTokens {
        async fn bearer_token(&self, _t: iwf_core::nf::NfType) -> Result<String, CoreError> {
            Ok("test-token".to_owned())
        }
    }

    async fn spawn_mock() -> String {
        let app = Router::new().route(
            "/nudm-uecm/v1/:ueid/registrations",
            get(
                |Query(q): Query<HashMap<String, String>>, headers: HeaderMap| async move {
                    assert_eq!(
                        headers.get("authorization").and_then(|v| v.to_str().ok()),
                        Some("Bearer test-token")
                    );
                    assert!(headers.contains_key("x-correlation-id"));
                    axum::Json(serde_json::json!({
                        "scscfName": "sip:scscf1.example.org",
                        "impu": q.get("impu"),
                    }))
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock serve");
        });
        format!("http://{addr}")
    }

    fn client_for(base: &str, max_attempts: u32) -> SbaClient {
        let resolver = Arc::new(StaticResolver {
            endpoints: vec![NfEndpoint {
                instance_id: "udm-test".to_owned(),
                base_uri: base.to_owned(),
                priority: 0,
                capacity: 100,
            }],
            failures: AtomicU32::new(0),
        });
        SbaClient::new(
            resolver,
            Arc::new(StaticTokens),
            SbaClientConfig {
                http2_only: false, // mock is HTTP/1.1
                retry: RetryPolicy {
                    max_attempts,
                    base: Duration::from_millis(1),
                    cap: Duration::from_millis(2),
                },
                ..Default::default()
            },
        )
    }

    fn sample_request() -> SbiRequest {
        let mut query = BTreeMap::new();
        query.insert("impu".to_owned(), "sip:alice@example.org".to_owned());
        SbiRequest {
            method: SbiMethod::Get,
            nf_type: iwf_core::nf::NfType::Udm,
            path: "/nudm-uecm/v1/imsi-001011234567890/registrations".to_owned(),
            query,
            body: None,
            correlation_id: "corr-test".to_owned(),
        }
    }

    #[tokio::test]
    async fn get_round_trip_with_auth_and_query() {
        let base = spawn_mock().await;
        let client = client_for(&base, 3);
        let response = client.send(sample_request()).await.expect("response");
        assert_eq!(response.status, 200);
        let json: serde_json::Value = serde_json::from_slice(&response.body).expect("json");
        assert_eq!(json["impu"], "sip:alice@example.org");
    }

    #[tokio::test]
    async fn connect_failure_exhausts_retries_for_get() {
        // Reserved port with no listener.
        let client = client_for("http://127.0.0.1:1", 2);
        let err = client.send(sample_request()).await;
        assert!(matches!(err, Err(CoreError::NfUnavailable { .. })));
    }

    #[tokio::test]
    async fn post_is_not_retried() {
        let client = client_for("http://127.0.0.1:1", 3);
        let mut req = sample_request();
        req.method = SbiMethod::Post;
        let start = std::time::Instant::now();
        let err = client.send(req).await;
        assert!(err.is_err());
        // One attempt only: no backoff sleeps stacked up.
        assert!(start.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn percent_encoding_reserved_chars() {
        assert_eq!(percent_encode("sip:a@b"), "sip%3Aa%40b");
        assert_eq!(percent_encode("plain-text_1.0~x"), "plain-text_1.0~x");
    }
}
