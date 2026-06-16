//! IWF composition root: wires configuration, observability, security,
//! discovery, the SBA client, the translation engine and the Diameter
//! front-end into one process, and owns the graceful-shutdown sequence.

#![deny(warnings)]
#![forbid(unsafe_code)]

mod diameter_front;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use iwf_admin::{admin_router, metrics_router, AdminState, Readiness};
use iwf_core::error::CoreError;
use iwf_core::ports::{SbaPort, SbiRequest, SbiResponse, TokenProvider};
use iwf_discovery::{DiscoveryService, HeartbeatConfig, HeartbeatTask, NrfClient};
use iwf_observability::Metrics;
use iwf_sba::{SbaClient, SbaClientConfig};
use iwf_security::jwt::JwtValidator;
use iwf_translation::{PluginRegistry, RuleStore, TranslationEngine};

/// SBA decorator recording `iwf_sba_*` metrics around the real client.
struct MeteredSba {
    inner: SbaClient,
    metrics: Metrics,
}

#[async_trait::async_trait]
impl SbaPort for MeteredSba {
    async fn send(&self, request: SbiRequest) -> Result<SbiResponse, CoreError> {
        let nf = request.nf_type.as_str();
        let operation = format!("{:?} {}", request.method, generalize_path(&request.path));
        let started = std::time::Instant::now();
        let result = self.inner.send(request).await;
        self.metrics
            .sba_latency
            .with_label_values(&[nf, &operation])
            .observe(started.elapsed().as_secs_f64());
        let status = match &result {
            Ok(r) => r.status.to_string(),
            Err(_) => "error".to_owned(),
        };
        self.metrics
            .sba_requests
            .with_label_values(&[nf, &operation, &status])
            .inc();
        result
    }
}

/// Collapse identifier path segments so metric cardinality stays bounded.
fn generalize_path(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if seg.contains('@')
                || seg.starts_with("imsi-")
                || seg.starts_with("msisdn-")
                || seg.starts_with("suci-")
            {
                "{id}"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Token provider used when OAuth is disabled (lab mode without an
/// authorization server): emits a fixed placeholder accepted by lab NFs.
struct AnonymousTokens;

#[async_trait::async_trait]
impl TokenProvider for AnonymousTokens {
    async fn bearer_token(&self, _t: iwf_core::nf::NfType) -> Result<String, CoreError> {
        Ok("anonymous".to_owned())
    }
}

fn fatal(message: &str, error: impl std::fmt::Display) -> ! {
    // Logging may not be up yet; write to both channels.
    eprintln!("FATAL {message}: {error}");
    tracing::error!(%error, "{message}");
    std::process::exit(1);
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        // Worker count defaults to available parallelism, which under
        // Kubernetes is the cgroup CPU quota — i.e. the requested cores.
        // NUMA pinning strategy is documented in docs/runbook.md §Scaling.
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => fatal("tokio runtime", e),
    };
    runtime.block_on(run());
    // The drain sequence inside run() has already done everything that must
    // happen on the way out (readiness off, in-flight drain, DPR, NRF
    // deregistration). Remaining worker shutdown must therefore be *bounded*:
    // an implicit Runtime::drop can wait forever on a worker parked in a
    // syscall, wedging the pod in Terminating until the kubelet SIGKILLs it.
    runtime.shutdown_timeout(Duration::from_secs(5));
}

async fn run() {
    let config_path = PathBuf::from(
        std::env::var("IWF_CONFIG").unwrap_or_else(|_| "/etc/iwf/config.yaml".to_owned()),
    );

    let log = iwf_observability::init_logging(
        &std::env::var("IWF_LOG_LEVEL").unwrap_or_else(|_| "info".to_owned()),
    );

    let (config_rx, _config_watcher) = match iwf_config::watch(config_path.clone()) {
        Ok(pair) => pair,
        Err(e) => fatal("loading configuration", e),
    };
    let config = config_rx.borrow().clone();

    let metrics = match Metrics::new() {
        Ok(m) => m,
        Err(e) => fatal("metrics registry", e),
    };

    // ---- AVP dictionary (per-interface catalog; builtin when unset) -------
    let catalog = match &config.dictionary_file {
        Some(path) => {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => fatal("reading dictionary file", e),
            };
            match iwf_translation::AvpCatalog::from_yaml(&text) {
                Ok(c) => {
                    tracing::info!(path = %path.display(), avps = c.len(), "AVP dictionary loaded");
                    Arc::new(c)
                }
                Err(e) => fatal("parsing dictionary file", e),
            }
        }
        None => Arc::new(iwf_translation::AvpCatalog::builtin()),
    };

    // ---- translation rules (hot-reload via admin PUT /admin/v1/rules) ----
    let rules_text = match std::fs::read_to_string(&config.rules_file) {
        Ok(t) => t,
        Err(e) => fatal("reading rules file", e),
    };
    let rules = match iwf_translation::rule::RuleSet::from_yaml_with(&rules_text, &catalog) {
        Ok(set) => Arc::new(RuleStore::with_catalog(set, catalog.clone())),
        Err(e) => fatal("parsing rules file", e),
    };

    // ---- 5GC side ---------------------------------------------------------
    // All SBI (NRF discovery/heartbeat + NF calls) is HTTP/2 per TS 29.500
    // §5.2. Real cores (Open5GS) speak h2c prior-knowledge. Set IWF_SBA_HTTP1
    // only when pointing at HTTP/1.1 test mocks.
    let sbi_http2 = std::env::var("IWF_SBA_HTTP1").is_err();
    // NRFs authorize discovery by requester-nf-type. The IWF advertises its
    // own type for registration but must discover as a type the NRF permits
    // to consume the target NF (Open5GS: AMF/AUSF/SMF/SCP can see the UDM,
    // AF/NEF cannot). Default "IWF"; set IWF_NRF_REQUESTER_NF_TYPE=AUSF for
    // Open5GS (see docs/deploy-open5gs.md).
    let requester = std::env::var("IWF_NRF_REQUESTER_NF_TYPE").unwrap_or_else(|_| "IWF".to_owned());
    let nrf = Arc::new(NrfClient::configured(
        &config.sba.nrf_uri,
        Duration::from_secs(5),
        sbi_http2,
        requester.clone(),
    ));
    let discovery = Arc::new(DiscoveryService::new(
        NrfClient::configured(
            &config.sba.nrf_uri,
            Duration::from_secs(5),
            sbi_http2,
            requester,
        ),
        Duration::from_secs(config.sba.discovery_ttl_s),
    ));
    let tokens: Arc<dyn TokenProvider> = if std::env::var("IWF_OAUTH_CLIENT_ID").is_ok() {
        match iwf_security::oauth::token_cache_from_env(
            config.token_endpoint(),
            Duration::from_secs(5),
        ) {
            Ok(cache) => cache,
            Err(e) => fatal("OAuth configuration", e),
        }
    } else {
        tracing::warn!("IWF_OAUTH_CLIENT_ID not set; running with anonymous SBA tokens (lab mode)");
        Arc::new(AnonymousTokens)
    };
    let sba = Arc::new(MeteredSba {
        inner: SbaClient::new(
            discovery.clone(),
            tokens,
            SbaClientConfig {
                request_timeout: Duration::from_millis(config.sba.request_timeout_ms),
                http2_only: sbi_http2,
                ..Default::default()
            },
        ),
        metrics: metrics.clone(),
    });

    let engine = Arc::new(
        TranslationEngine::new(
            rules.clone(),
            PluginRegistry::with_builtins(),
            sba,
            config.diameter.origin_host.clone(),
            config.diameter.origin_realm.clone(),
        )
        .with_catalog(catalog),
    );

    // ---- NRF registration / heartbeat --------------------------------------
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let readiness = Arc::new(Readiness::default());
    let heartbeat = HeartbeatTask::spawn(
        nrf,
        iwf_discovery::NfProfile::for_iwf(instance_id(), config.diameter.origin_host.clone()),
        HeartbeatConfig::default(),
        shutdown.clone(),
    );
    {
        let readiness = readiness.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.notified() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        readiness
                            .nrf_registered
                            .store(heartbeat.is_registered(), Ordering::Release);
                    }
                }
            }
        });
    }

    // ---- admin + metrics listeners ------------------------------------------
    let jwt = match admin_jwt(&config) {
        Ok(v) => Arc::new(v),
        Err(e) => fatal("admin JWT configuration", e),
    };
    let admin_state = AdminState {
        log,
        rules: rules.clone(),
        metrics: metrics.clone(),
        readiness: readiness.clone(),
        jwt,
    };
    spawn_http(&config.admin.listen, admin_router(admin_state.clone())).await;
    spawn_http(&config.admin.metrics_listen, metrics_router(admin_state)).await;

    // ---- Diameter front-end ---------------------------------------------------
    let front = diameter_front::DiameterFront::new(
        config.clone(),
        engine,
        metrics.clone(),
        readiness.clone(),
    );
    let front_handle = match front.spawn().await {
        Ok(h) => h,
        Err(e) => fatal("diameter listener", e),
    };

    tracing::info!(
        origin_host = %config.diameter.origin_host,
        listen = %config.diameter.listen,
        "IWF up"
    );

    // ---- shutdown sequence ------------------------------------------------------
    wait_for_termination().await;
    tracing::info!("shutdown requested; draining");
    readiness.draining.store(true, Ordering::Release);
    front_handle
        .drain(Duration::from_secs(config.drain_timeout_s))
        .await;
    shutdown.notify_waiters(); // heartbeat task deregisters from NRF
    tokio::time::sleep(Duration::from_millis(200)).await; // let the dereg flush
    tracing::info!("drain complete; exiting");
}

fn instance_id() -> String {
    // Stable for the pod lifetime; the NRF treats PUT as upsert, so a new id
    // after restart is also fine (the old one ages out via heartbeat).
    std::env::var("IWF_NF_INSTANCE_ID").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
}

fn admin_jwt(config: &iwf_config::Config) -> Result<JwtValidator, String> {
    if let Some(path) = &config.admin.jwt_rs256_public_key {
        let pem = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        return JwtValidator::rs256(&pem, &config.admin.jwt_audience)
            .map_err(|e| format!("rs256 key: {e}"));
    }
    if let Some(env_name) = &config.admin.jwt_hs256_secret_env {
        let secret = std::env::var(env_name).map_err(|_| format!("env {env_name} not set"))?;
        return Ok(JwtValidator::hs256(
            secret.as_bytes(),
            &config.admin.jwt_audience,
        ));
    }
    Err("admin JWT: set jwt_rs256_public_key or jwt_hs256_secret_env".to_owned())
}

async fn spawn_http(listen: &str, router: axum::Router) {
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => fatal(&format!("binding {listen}"), e),
    };
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!(error = %e, "http listener terminated");
        }
    });
}

async fn wait_for_termination() {
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => fatal("installing SIGTERM handler", e),
    };
    tokio::select! {
        _ = sigterm.recv() => {}
        result = tokio::signal::ctrl_c() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "ctrl-c handler failed");
            }
        }
    }
}
