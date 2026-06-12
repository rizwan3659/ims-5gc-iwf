//! TTL endpoint cache + the [`EndpointResolver`] adapter.
//!
//! Resolution path: cache hit (fresh, healthy entries) → zero NRF traffic.
//! Miss or expiry → one NRF discovery, result cached with the NRF-granted
//! `validityPeriod` (capped by `max_ttl`). `report_failure` marks an
//! instance unhealthy immediately — in-flight rerouting then happens inside
//! `iwf-sba` (next endpoint in the same attempt loop, well inside the
//! 500 ms failover budget) — and drops the entry's TTL so the next resolve
//! re-queries the NRF.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use iwf_core::error::CoreError;
use iwf_core::nf::NfType;
use iwf_core::ports::{EndpointResolver, NfEndpoint};

use crate::nrf::NrfClient;
use crate::profile::{NfService, SearchResult};

#[derive(Debug, Clone)]
struct CachedEndpoint {
    endpoint: NfEndpoint,
    healthy: bool,
}

#[derive(Debug)]
struct CacheEntry {
    endpoints: Vec<CachedEndpoint>,
    expires: Instant,
}

/// Discovery-backed endpoint resolver with TTL cache.
#[derive(Debug)]
pub struct DiscoveryService {
    nrf: NrfClient,
    cache: DashMap<NfType, CacheEntry>,
    /// Ceiling applied to NRF `validityPeriod` so a misconfigured NRF cannot
    /// pin stale endpoints for hours.
    max_ttl: Duration,
}

impl DiscoveryService {
    /// Service over `nrf` with the given TTL ceiling.
    pub fn new(nrf: NrfClient, max_ttl: Duration) -> Self {
        DiscoveryService {
            nrf,
            cache: DashMap::new(),
            max_ttl,
        }
    }

    fn endpoints_from(result: &SearchResult) -> Vec<CachedEndpoint> {
        let mut out = Vec::new();
        for instance in &result.nf_instances {
            // Address resolution order (TS 29.510): a service's apiPrefix or
            // ipEndPoints (NfService::base_uri covers both), then the
            // instance-level FQDN. Open5GS uses service ipEndPoints.
            let service = instance.nf_services.first();
            let base = service
                .and_then(NfService::base_uri)
                .or_else(|| instance.fqdn.as_ref().map(|f| format!("http://{f}")));
            let Some(base_uri) = base else {
                tracing::warn!(
                    instance = %instance.nf_instance_id,
                    "discovered NF without addressable endpoint; skipping"
                );
                continue;
            };
            let (priority, capacity) = service
                .map(|s| (s.priority, s.capacity))
                .unwrap_or((0, 100));
            out.push(CachedEndpoint {
                endpoint: NfEndpoint {
                    instance_id: instance.nf_instance_id.clone(),
                    base_uri,
                    priority,
                    capacity,
                },
                healthy: true,
            });
        }
        out.sort_by_key(|c| c.endpoint.priority);
        out
    }

    async fn refresh(&self, nf_type: NfType) -> Result<Vec<NfEndpoint>, CoreError> {
        let started = Instant::now();
        let result = self
            .nrf
            .discover(nf_type)
            .await
            .map_err(|e| CoreError::NfUnavailable {
                nf: "NRF",
                reason: e.to_string(),
            })?;
        tracing::info!(
            target_nf = %nf_type,
            instances = result.nf_instances.len(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "nrf discovery refresh"
        );
        let endpoints = Self::endpoints_from(&result);
        let ttl = Duration::from_secs(result.validity_period).min(self.max_ttl);
        let healthy: Vec<NfEndpoint> = endpoints.iter().map(|c| c.endpoint.clone()).collect();
        self.cache.insert(
            nf_type,
            CacheEntry {
                endpoints,
                expires: Instant::now() + ttl,
            },
        );
        Ok(healthy)
    }
}

#[async_trait]
impl EndpointResolver for DiscoveryService {
    async fn resolve(&self, nf_type: NfType) -> Result<Vec<NfEndpoint>, CoreError> {
        if let Some(entry) = self.cache.get(&nf_type) {
            if entry.expires > Instant::now() {
                let healthy: Vec<NfEndpoint> = entry
                    .endpoints
                    .iter()
                    .filter(|c| c.healthy)
                    .map(|c| c.endpoint.clone())
                    .collect();
                if !healthy.is_empty() {
                    return Ok(healthy);
                }
                // All cached endpoints unhealthy → fall through to refresh.
            }
        }
        self.refresh(nf_type).await
    }

    async fn report_failure(&self, nf_type: NfType, instance_id: &str) {
        if let Some(mut entry) = self.cache.get_mut(&nf_type) {
            for c in &mut entry.endpoints {
                if c.endpoint.instance_id == instance_id {
                    c.healthy = false;
                    tracing::warn!(
                        target_nf = %nf_type,
                        instance = instance_id,
                        "endpoint marked unhealthy"
                    );
                }
            }
            // Expire the entry so the next resolve re-queries the NRF.
            entry.expires = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    async fn spawn_nrf(hits: Arc<AtomicU32>) -> String {
        let app = Router::new().route(
            "/nnrf-disc/v1/nf-instances",
            get(move || {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::Relaxed);
                    axum::Json(serde_json::json!({
                        "validityPeriod": 3600,
                        "nfInstances": [
                            {
                                "nfInstanceId": "udm-1",
                                "nfType": "UDM",
                                "nfStatus": "REGISTERED",
                                "nfServices": [{
                                    "serviceInstanceId": "s1",
                                    "serviceName": "nudm-uecm",
                                    "scheme": "http",
                                    "apiPrefix": "http://udm-1.5gc:8080",
                                    "priority": 0,
                                    "capacity": 100
                                }]
                            },
                            {
                                // Open5GS shape: address via ipEndPoints,
                                // no apiPrefix.
                                "nfInstanceId": "udm-2",
                                "nfType": "UDM",
                                "nfStatus": "REGISTERED",
                                "nfServices": [{
                                    "serviceInstanceId": "s1",
                                    "serviceName": "nudm-sdm",
                                    "scheme": "http",
                                    "ipEndPoints": [{"ipv4Address": "127.0.0.12", "port": 7777}],
                                    "priority": 0,
                                    "capacity": 100
                                }]
                            }
                        ]
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock nrf");
        });
        format!("http://{addr}")
    }

    fn service(base: &str) -> DiscoveryService {
        DiscoveryService::new(
            NrfClient::new(base, Duration::from_secs(2)),
            Duration::from_secs(300),
        )
    }

    #[tokio::test]
    async fn discovery_populates_and_caches() {
        let hits = Arc::new(AtomicU32::new(0));
        let base = spawn_nrf(hits.clone()).await;
        let svc = service(&base);

        let eps = svc.resolve(NfType::Udm).await.expect("resolve");
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].instance_id, "udm-1");
        assert_eq!(eps[0].base_uri, "http://udm-1.5gc:8080");
        assert_eq!(
            eps[1].base_uri, "http://127.0.0.12:7777",
            "ipEndPoints resolution (Open5GS shape)"
        );

        // Second resolve: served from cache, no extra NRF hit.
        let _ = svc.resolve(NfType::Udm).await.expect("resolve");
        assert_eq!(hits.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn failure_marks_unhealthy_and_requeries() {
        let hits = Arc::new(AtomicU32::new(0));
        let base = spawn_nrf(hits.clone()).await;
        let svc = service(&base);

        let _ = svc.resolve(NfType::Udm).await.expect("resolve");
        svc.report_failure(NfType::Udm, "udm-1").await;

        // Entry expired by report_failure → next resolve re-queries.
        let eps = svc.resolve(NfType::Udm).await.expect("resolve");
        assert_eq!(hits.load(Ordering::Relaxed), 2);
        assert_eq!(eps.len(), 2, "fresh discovery restores both");
    }

    #[tokio::test]
    async fn nrf_down_is_nf_unavailable() {
        let svc = service("http://127.0.0.1:1");
        assert!(matches!(
            svc.resolve(NfType::Ausf).await,
            Err(CoreError::NfUnavailable { .. })
        ));
    }
}
