//! # iwf-config
//!
//! Runtime configuration: schema, YAML/TOML loading, validation, and
//! hot-reload via an inotify watcher publishing fresh snapshots on a
//! `tokio::sync::watch` channel.
//!
//! Secrets policy: this schema holds **no secrets** — TLS paths point at
//! mounted Kubernetes Secret volumes and OAuth credentials are read from
//! the environment by `iwf-security`.

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// File could not be read.
    #[error("reading {path}: {source}")]
    Io {
        /// Offending path.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Parse failure (YAML or TOML).
    #[error("parsing {path}: {message}")]
    Parse {
        /// Offending path.
        path: String,
        /// Parser diagnostic.
        message: String,
    },
    /// Semantic validation failure.
    #[error("invalid configuration: {0}")]
    Invalid(String),
    /// File watcher failure.
    #[error("watcher: {0}")]
    Watch(String),
}

/// Diameter front-end settings.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DiameterConfig {
    /// Listen address for peers, e.g. `0.0.0.0:3868`.
    pub listen: String,
    /// Local Origin-Host (DiameterIdentity).
    pub origin_host: String,
    /// Local Origin-Realm.
    pub origin_realm: String,
    /// Watchdog interval seconds (RFC 3539 Tw), default 30.
    #[serde(default = "default_watchdog")]
    pub watchdog_interval_s: u64,
    /// Per-transaction answer timeout in milliseconds, default 5000.
    #[serde(default = "default_tx_timeout")]
    pub transaction_timeout_ms: u64,
    /// Ingress shed threshold: maximum in-flight transactions before new
    /// requests are answered DIAMETER_TOO_BUSY, default 50000.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: u64,
}

fn default_watchdog() -> u64 {
    30
}
fn default_tx_timeout() -> u64 {
    5000
}
fn default_max_in_flight() -> u64 {
    50_000
}

/// SBA / 5GC side settings.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SbaConfig {
    /// NRF base URI.
    pub nrf_uri: String,
    /// Per-attempt SBI request timeout, milliseconds. Default 1500.
    #[serde(default = "default_sbi_timeout")]
    pub request_timeout_ms: u64,
    /// Discovery cache TTL ceiling, seconds. Default 300.
    #[serde(default = "default_cache_ttl")]
    pub discovery_ttl_s: u64,
    /// OAuth token endpoint; defaults to `<nrf_uri>/oauth2/token` when None.
    #[serde(default)]
    pub token_endpoint: Option<String>,
}

fn default_sbi_timeout() -> u64 {
    1500
}
fn default_cache_ttl() -> u64 {
    300
}

/// TLS material locations (Secret volume mounts).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Certificate chain PEM.
    pub cert: PathBuf,
    /// Private key PEM.
    pub key: PathBuf,
    /// Trust anchors PEM.
    pub ca: PathBuf,
}

/// Admin / observability endpoints.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Admin API listen address, e.g. `0.0.0.0:8080`.
    pub listen: String,
    /// Metrics listen address, e.g. `0.0.0.0:9090`.
    pub metrics_listen: String,
    /// HS256 secret env var name for admin JWTs (lab) or RS256 public key
    /// path (production). One of the two must be set.
    #[serde(default)]
    pub jwt_hs256_secret_env: Option<String>,
    /// RS256 public key PEM path.
    #[serde(default)]
    pub jwt_rs256_public_key: Option<PathBuf>,
    /// Expected JWT audience. Default `iwf-admin`.
    #[serde(default = "default_audience")]
    pub jwt_audience: String,
}

/// Inbound 5GC notification callback server (Phase 2 server-push: Sh PNR,
/// Cx RTR/PPR, Rx RAR/ASR). Optional — unset disables notification flows.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NotificationConfig {
    /// Listen address for the callback endpoint, e.g. `0.0.0.0:8081`.
    pub listen: String,
    /// Base URL advertised to 5GC NFs as the callback (`callbackReference` /
    /// `notifyUri`), e.g. `http://iwf-notif.epc.svc:8081`. The IWF appends
    /// `/iwf-notif/v1/{session}`.
    pub advertised_uri: String,
}

fn default_audience() -> String {
    "iwf-admin".to_owned()
}

/// Top-level configuration document.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Diameter front-end.
    pub diameter: DiameterConfig,
    /// SBA side.
    pub sba: SbaConfig,
    /// Admin/metrics endpoints.
    pub admin: AdminConfig,
    /// Translation rule document path.
    pub rules_file: PathBuf,
    /// AVP dictionary document path (per-interface AVP catalog). Unset →
    /// the builtin Cx/Sh table compiled into `iwf-translation`.
    #[serde(default)]
    pub dictionary_file: Option<PathBuf>,
    /// Inbound notification callback server (server-push flows). Unset →
    /// notifications disabled.
    #[serde(default)]
    pub notification: Option<NotificationConfig>,
    /// TLS material (optional: plain TCP inside a service mesh).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Graceful-shutdown drain budget, seconds. Default 30.
    #[serde(default = "default_drain")]
    pub drain_timeout_s: u64,
}

fn default_drain() -> u64 {
    30
}

impl Config {
    /// Load from a YAML (`.yaml`/`.yml`) or TOML (`.toml`) file.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let config: Config = match path.extension().and_then(|e| e.to_str()) {
            Some("toml") => toml::from_str(&text).map_err(|e| ConfigError::Parse {
                path: path.display().to_string(),
                message: e.to_string(),
            })?,
            _ => serde_yaml::from_str(&text).map_err(|e| ConfigError::Parse {
                path: path.display().to_string(),
                message: e.to_string(),
            })?,
        };
        config.validate()?;
        Ok(config)
    }

    /// Semantic checks that serde cannot express.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.diameter.origin_host.contains('.') {
            return Err(ConfigError::Invalid(
                "diameter.origin_host must be an FQDN".to_owned(),
            ));
        }
        if self.diameter.transaction_timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "diameter.transaction_timeout_ms must be > 0".to_owned(),
            ));
        }
        if !self.sba.nrf_uri.starts_with("http://") && !self.sba.nrf_uri.starts_with("https://") {
            return Err(ConfigError::Invalid(
                "sba.nrf_uri must be an http(s) URI".to_owned(),
            ));
        }
        Ok(())
    }

    /// Effective OAuth token endpoint.
    pub fn token_endpoint(&self) -> String {
        self.sba
            .token_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oauth2/token", self.sba.nrf_uri.trim_end_matches('/')))
    }

    /// Watchdog interval as a `Duration`.
    pub fn watchdog_interval(&self) -> Duration {
        Duration::from_secs(self.diameter.watchdog_interval_s)
    }

    /// Transaction timeout as a `Duration`.
    pub fn transaction_timeout(&self) -> Duration {
        Duration::from_millis(self.diameter.transaction_timeout_ms)
    }
}

/// Watch `path` and publish validated snapshots. The initial load must
/// succeed; later failures keep the last good snapshot and log the error.
pub fn watch(
    path: PathBuf,
) -> Result<
    (
        tokio::sync::watch::Receiver<Arc<Config>>,
        notify::RecommendedWatcher,
    ),
    ConfigError,
> {
    use notify::Watcher;

    let initial = Arc::new(Config::load(&path)?);
    let (tx, rx) = tokio::sync::watch::channel(initial);

    let watch_path = path.clone();
    let mut watcher = notify::recommended_watcher(move |event: Result<notify::Event, _>| {
        let Ok(event) = event else { return };
        if !matches!(
            event.kind,
            notify::EventKind::Modify(_) | notify::EventKind::Create(_)
        ) {
            return;
        }
        match Config::load(&watch_path) {
            Ok(fresh) => {
                if tx.send(Arc::new(fresh)).is_err() {
                    tracing::debug!("config watch receiver dropped");
                }
                tracing::info!(path = %watch_path.display(), "configuration reloaded");
            }
            Err(e) => {
                tracing::error!(error = %e, "config reload failed; keeping previous");
            }
        }
    })
    .map_err(|e| ConfigError::Watch(e.to_string()))?;

    watcher
        .watch(&path, notify::RecursiveMode::NonRecursive)
        .map_err(|e| ConfigError::Watch(e.to_string()))?;

    Ok((rx, watcher))
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
diameter:
  listen: "0.0.0.0:3868"
  origin_host: "iwf-0.epc.example.org"
  origin_realm: "epc.example.org"
sba:
  nrf_uri: "http://nrf.5gc:8080"
admin:
  listen: "0.0.0.0:8080"
  metrics_listen: "0.0.0.0:9090"
rules_file: "/etc/iwf/rules.yaml"
"#;

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("iwf-config-test-{name}-{}", std::process::id()));
        std::fs::write(&path, contents).expect("write temp config");
        path
    }

    #[test]
    fn yaml_loads_with_defaults() {
        let path = write_temp("ok.yaml", YAML);
        let config = Config::load(&path).expect("load");
        assert_eq!(config.diameter.watchdog_interval_s, 30);
        assert_eq!(config.diameter.max_in_flight, 50_000);
        assert_eq!(config.drain_timeout_s, 30);
        assert_eq!(config.token_endpoint(), "http://nrf.5gc:8080/oauth2/token");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn rejects_non_fqdn_origin_host() {
        let bad = YAML.replace("iwf-0.epc.example.org", "localhost");
        let path = write_temp("badhost.yaml", &bad);
        assert!(matches!(Config::load(&path), Err(ConfigError::Invalid(_))));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = format!("{YAML}\nunknown_key: 1\n");
        let path = write_temp("unknown.yaml", &bad);
        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::Parse { .. })
        ));
        std::fs::remove_file(path).ok();
    }

    #[tokio::test]
    async fn watcher_publishes_reloads() {
        let path = write_temp("watch.yaml", YAML);
        let (mut rx, _watcher) = watch(path.clone()).expect("watch");
        assert_eq!(rx.borrow().diameter.watchdog_interval_s, 30);

        let updated = YAML.replace(
            "origin_realm: \"epc.example.org\"",
            "origin_realm: \"epc.example.org\"\n  watchdog_interval_s: 10",
        );
        std::fs::write(&path, updated).expect("rewrite");

        // The inotify event arrives asynchronously.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if tokio::time::timeout(Duration::from_millis(200), rx.changed())
                .await
                .is_ok()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no reload observed within 5 s"
            );
        }
        assert_eq!(rx.borrow().diameter.watchdog_interval_s, 10);
        std::fs::remove_file(path).ok();
    }
}
