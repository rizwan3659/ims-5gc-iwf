//! Prometheus metric families. Every family from the operational spec is
//! pre-registered here so a scrape never races registration.

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};

/// Latency buckets tuned to the SLOs: internal p99 < 5 ms, end-to-end
/// p99 < 20 ms — buckets concentrate resolution there.
const LATENCY_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.002, 0.003, 0.005, 0.0075, 0.010, 0.015, 0.020, 0.030, 0.050, 0.100, 0.250,
    1.0,
];

/// All IWF metric families on one registry.
#[derive(Debug, Clone)]
pub struct Metrics {
    registry: Registry,
    /// `iwf_diameter_requests_total{interface, command, result_code}`
    pub diameter_requests: prometheus::IntCounterVec,
    /// `iwf_diameter_latency_seconds{interface, command}` (histogram —
    /// quantiles are computed by Prometheus from buckets).
    pub diameter_latency: HistogramVec,
    /// `iwf_sba_requests_total{nf_type, operation, http_status}`
    pub sba_requests: prometheus::IntCounterVec,
    /// `iwf_sba_latency_seconds{nf_type, operation}`
    pub sba_latency: HistogramVec,
    /// `iwf_translation_errors_total{rule_id, error_type}`
    pub translation_errors: prometheus::IntCounterVec,
    /// `iwf_nrf_discovery_latency_seconds`
    pub nrf_discovery_latency: prometheus::Histogram,
    /// `iwf_peer_state{peer_fqdn, state}` — 1 for the active state, 0 else.
    pub peer_state: IntGaugeVec,
    /// `iwf_active_sessions_total`
    pub active_sessions: IntGauge,
}

impl Metrics {
    /// Create and register every family.
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let diameter_requests = prometheus::IntCounterVec::new(
            Opts::new(
                "iwf_diameter_requests_total",
                "Diameter requests processed, by interface, command and result code",
            ),
            &["interface", "command", "result_code"],
        )?;
        let diameter_latency = HistogramVec::new(
            HistogramOpts::new(
                "iwf_diameter_latency_seconds",
                "Diameter transaction latency (ingress to answer)",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["interface", "command"],
        )?;
        let sba_requests = prometheus::IntCounterVec::new(
            Opts::new(
                "iwf_sba_requests_total",
                "SBA requests issued, by NF type, operation and HTTP status",
            ),
            &["nf_type", "operation", "http_status"],
        )?;
        let sba_latency = HistogramVec::new(
            HistogramOpts::new("iwf_sba_latency_seconds", "SBA request latency")
                .buckets(LATENCY_BUCKETS.to_vec()),
            &["nf_type", "operation"],
        )?;
        let translation_errors = prometheus::IntCounterVec::new(
            Opts::new(
                "iwf_translation_errors_total",
                "Translation failures by rule and error type",
            ),
            &["rule_id", "error_type"],
        )?;
        let nrf_discovery_latency = prometheus::Histogram::with_opts(
            HistogramOpts::new(
                "iwf_nrf_discovery_latency_seconds",
                "NRF discovery query latency",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
        )?;
        let peer_state = IntGaugeVec::new(
            Opts::new(
                "iwf_peer_state",
                "Diameter peer FSM state (1 = active state)",
            ),
            &["peer_fqdn", "state"],
        )?;
        let active_sessions = IntGauge::new(
            "iwf_active_sessions_total",
            "In-flight Diameter transactions",
        )?;

        registry.register(Box::new(diameter_requests.clone()))?;
        registry.register(Box::new(diameter_latency.clone()))?;
        registry.register(Box::new(sba_requests.clone()))?;
        registry.register(Box::new(sba_latency.clone()))?;
        registry.register(Box::new(translation_errors.clone()))?;
        registry.register(Box::new(nrf_discovery_latency.clone()))?;
        registry.register(Box::new(peer_state.clone()))?;
        registry.register(Box::new(active_sessions.clone()))?;

        Ok(Metrics {
            registry,
            diameter_requests,
            diameter_latency,
            sba_requests,
            sba_latency,
            translation_errors,
            nrf_discovery_latency,
            peer_state,
            active_sessions,
        })
    }

    /// Update the peer-state gauge family so exactly one state is 1.
    pub fn set_peer_state(&self, peer_fqdn: &str, active: &str) {
        for state in [
            "closed",
            "wait_conn_ack",
            "wait_i_cea",
            "wait_conn_ack_elect",
            "wait_returns",
            "i_open",
            "r_open",
            "closing",
        ] {
            self.peer_state
                .with_label_values(&[peer_fqdn, state])
                .set(i64::from(state == active));
        }
    }

    /// Render the registry in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        if let Err(e) = encoder.encode(&self.registry.gather(), &mut buf) {
            tracing::error!(error = %e, "metrics encode failed");
            return String::new();
        }
        String::from_utf8(buf).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_spec_families_render() {
        let m = Metrics::new().expect("metrics");
        m.diameter_requests
            .with_label_values(&["cx", "UAR", "2001"])
            .inc();
        m.diameter_latency
            .with_label_values(&["cx", "UAR"])
            .observe(0.0042);
        m.sba_requests
            .with_label_values(&["UDM", "GET /nudm-uecm", "200"])
            .inc();
        m.sba_latency
            .with_label_values(&["UDM", "GET /nudm-uecm"])
            .observe(0.003);
        m.translation_errors
            .with_label_values(&["cx_uar_to_udm_identity_query", "no_rule"])
            .inc();
        m.nrf_discovery_latency.observe(0.002);
        m.set_peer_state("hss-1.example.org", "r_open");
        m.active_sessions.set(17);

        let text = m.render();
        for family in [
            "iwf_diameter_requests_total",
            "iwf_diameter_latency_seconds",
            "iwf_sba_requests_total",
            "iwf_sba_latency_seconds",
            "iwf_translation_errors_total",
            "iwf_nrf_discovery_latency_seconds",
            "iwf_peer_state",
            "iwf_active_sessions_total",
        ] {
            assert!(text.contains(family), "{family} missing from exposition");
        }
        assert!(text.contains(r#"state="r_open"} 1"#));
        assert!(text.contains(r#"state="closed"} 0"#));
    }
}
