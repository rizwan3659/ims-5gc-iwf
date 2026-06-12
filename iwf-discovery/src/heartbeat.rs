//! Registration + heartbeat background task.
//!
//! On start: register the IWF profile with the NRF (retrying with backoff
//! until it succeeds — readiness gates on this, see `iwf-admin`). Then
//! heartbeat at the NRF-granted interval; on failure back off
//! exponentially; on 404 re-register (the NRF lost us, e.g. it restarted).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::nrf::{NrfClient, NrfError};
use crate::profile::NfProfile;

/// Heartbeat tuning.
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// Interval when the NRF does not grant `heartBeatTimer` (default 30 s).
    pub default_interval: Duration,
    /// First retry delay after a failure.
    pub backoff_base: Duration,
    /// Backoff ceiling.
    pub backoff_cap: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        HeartbeatConfig {
            default_interval: Duration::from_secs(30),
            backoff_base: Duration::from_secs(1),
            backoff_cap: Duration::from_secs(60),
        }
    }
}

/// Handle to the registration/heartbeat loop.
#[derive(Debug)]
pub struct HeartbeatTask {
    /// Flips true once the initial registration succeeds (readiness gate).
    registered: Arc<AtomicBool>,
}

impl HeartbeatTask {
    /// Spawn the loop on the current runtime. The task runs until the
    /// returned handle (and its clones) observe `shutdown` being notified.
    pub fn spawn(
        nrf: Arc<NrfClient>,
        profile: NfProfile,
        config: HeartbeatConfig,
        shutdown: Arc<tokio::sync::Notify>,
    ) -> Self {
        let registered = Arc::new(AtomicBool::new(false));
        let flag = registered.clone();

        tokio::spawn(async move {
            let mut profile = profile;
            let mut interval = config.default_interval;
            let mut backoff = config.backoff_base;

            // Phase 1: initial registration with backoff.
            loop {
                tokio::select! {
                    _ = shutdown.notified() => return,
                    result = nrf.register(&profile) => match result {
                        Ok(echoed) => {
                            if let Some(secs) = echoed.heart_beat_timer {
                                interval = Duration::from_secs(u64::from(secs));
                            }
                            profile = echoed;
                            flag.store(true, Ordering::Release);
                            tracing::info!(interval_s = interval.as_secs(), "registered with NRF");
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, retry_in = ?backoff, "NRF registration failed");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(config.backoff_cap);
                        }
                    }
                }
            }

            // Phase 2: heartbeat loop.
            backoff = config.backoff_base;
            loop {
                tokio::select! {
                    _ = shutdown.notified() => {
                        // Graceful: deregister so peers stop discovering us.
                        if let Err(e) = nrf.deregister(&profile.nf_instance_id).await {
                            tracing::warn!(error = %e, "NRF deregistration failed");
                        }
                        return;
                    }
                    _ = tokio::time::sleep(interval) => {
                        match nrf.heartbeat(&profile.nf_instance_id).await {
                            Ok(()) => {
                                backoff = config.backoff_base;
                                flag.store(true, Ordering::Release);
                            }
                            Err(NrfError::NotRegistered) => {
                                tracing::warn!("NRF lost our registration; re-registering");
                                flag.store(false, Ordering::Release);
                                if let Ok(echoed) = nrf.register(&profile).await {
                                    if let Some(secs) = echoed.heart_beat_timer {
                                        interval = Duration::from_secs(u64::from(secs));
                                    }
                                    profile = echoed;
                                    flag.store(true, Ordering::Release);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, retry_in = ?backoff, "heartbeat failed");
                                flag.store(false, Ordering::Release);
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(config.backoff_cap);
                            }
                        }
                    }
                }
            }
        });

        HeartbeatTask { registered }
    }

    /// Whether the NRF currently considers us registered (readiness input).
    pub fn is_registered(&self) -> bool {
        self.registered.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Path;
    use axum::routing::{delete, put};
    use axum::Router;
    use std::sync::atomic::AtomicU32;

    async fn spawn_nrf(beats: Arc<AtomicU32>) -> String {
        let app = Router::new()
            .route(
                "/nnrf-nfm/v1/nf-instances/:id",
                put(|Path(_id): Path<String>, body: String| async move {
                    let mut profile: serde_json::Value =
                        serde_json::from_str(&body).expect("profile json");
                    profile["heartBeatTimer"] = serde_json::json!(1);
                    (axum::http::StatusCode::CREATED, axum::Json(profile))
                })
                .patch(move |Path(_id): Path<String>| {
                    let beats = beats.clone();
                    async move {
                        beats.fetch_add(1, Ordering::Relaxed);
                        axum::http::StatusCode::NO_CONTENT
                    }
                }),
            )
            .route(
                "/nnrf-nfm/v1/nf-instances/:id/dereg",
                delete(|| async { axum::http::StatusCode::NO_CONTENT }),
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

    #[tokio::test]
    async fn registers_and_heartbeats() {
        let beats = Arc::new(AtomicU32::new(0));
        let base = spawn_nrf(beats.clone()).await;
        let nrf = Arc::new(NrfClient::new(&base, Duration::from_secs(2)));
        let shutdown = Arc::new(tokio::sync::Notify::new());

        let task = HeartbeatTask::spawn(
            nrf,
            NfProfile::for_iwf("iwf-test".to_owned(), "iwf-0".to_owned()),
            HeartbeatConfig {
                default_interval: Duration::from_millis(50),
                ..Default::default()
            },
            shutdown.clone(),
        );

        // Wait for registration + at least one heartbeat (granted timer 1 s
        // overrides the default, so allow for that).
        for _ in 0..60 {
            if task.is_registered() && beats.load(Ordering::Relaxed) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(task.is_registered());
        assert!(beats.load(Ordering::Relaxed) >= 1);
        shutdown.notify_waiters();
    }
}
