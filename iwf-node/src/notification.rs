//! Inbound 5GC notification callback server (Phase 2 server-push).
//!
//! A 5GC NF (HSS/PCF/CHF) calls back the `callbackReference`/`notifyUri` the
//! IWF advertised when the forward flow created a [`Binding`]. This server
//! turns that HTTP notification into an **originated** Diameter request
//! (PNR/RTR/PPR/RAR/ASR) routed to the bound Diameter peer:
//!
//! `POST /iwf-notif/v1/{bindingId}` → look up binding → `build_notification`
//! (declarative, via the `notifications:` rules) → `PeerRegistry::originate`
//! → map the Diameter answer back to the NF (`204` on 2001).
//!
//! `bindingId` is the (URL-encoded) Diameter Session-Id the forward flow
//! bound under; Axum URL-decodes it back to the raw key.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use bytes::Bytes;
use iwf_core::ports::BindingStore;
use iwf_diameter::dictionary as dict;
use iwf_translation::{RuleStore, TranslationEngine};

use crate::peer_registry::{OriginateError, PeerRegistry};

/// Shared state for the notification routes.
#[derive(Clone)]
pub struct NotificationState {
    /// OPEN peer connections to originate into.
    pub peers: Arc<PeerRegistry>,
    /// Session→resource bindings recorded by forward flows.
    pub bindings: Arc<dyn BindingStore>,
    /// Engine (declarative `build_notification`).
    pub engine: Arc<TranslationEngine>,
    /// Active rules (the `notifications:` section).
    pub rules: Arc<RuleStore>,
    /// Per-origination budget waiting for the peer's answer.
    pub timeout: Duration,
}

/// Notification router.
pub fn notification_router(state: NotificationState) -> Router {
    Router::new()
        .route("/iwf-notif/v1/:binding_id", post(handle_notification))
        .with_state(state)
}

async fn handle_notification(
    State(state): State<NotificationState>,
    Path(binding_id): Path<String>,
    body: Bytes,
) -> StatusCode {
    // 1. Resolve the binding (the AS/P-CSCF/S-CSCF to push to, and its kind).
    let binding = match state.bindings.get(&binding_id).await {
        Some(b) => b,
        None => {
            tracing::debug!(%binding_id, "notification for unknown binding");
            return StatusCode::NOT_FOUND;
        }
    };

    // 2. Pick the notification rule for this binding's kind and the event in
    //    the notification body (RTR vs PPR, RAR vs ASR, ...).
    let snapshot = state.rules.load();
    let body_json = serde_json::from_slice::<serde_json::Value>(&body).ok();
    let rule = match snapshot
        .notifications
        .iter()
        .find(|n| n.bind_kind == binding.kind && n.matches(body_json.as_ref()))
    {
        Some(r) => r,
        None => {
            tracing::warn!(kind = %binding.kind, "no notification rule matched");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // 3. Build the originated Diameter request (declarative).
    let request = match state.engine.build_notification(rule, &binding, body) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, rule = %rule.id, "build_notification failed");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // 4. Originate to the bound peer and await the answer.
    match state
        .peers
        .originate(&binding.peer_host, request, state.timeout)
        .await
    {
        Ok(answer) => {
            if answer.result_code() == Some(dict::RC_SUCCESS) {
                StatusCode::NO_CONTENT
            } else {
                tracing::info!(
                    peer = %binding.peer_host,
                    result = ?answer.result_code(),
                    "originated request answered with non-success"
                );
                StatusCode::BAD_GATEWAY
            }
        }
        Err(OriginateError::UnknownPeer(_)) => {
            // The subscriber is no longer connected: drop the binding so the
            // NF stops notifying (TS 29.500 §6.x undeliverable subscription).
            state.bindings.take(&binding_id).await;
            tracing::info!(peer = %binding.peer_host, "subscriber gone; binding dropped");
            StatusCode::GONE
        }
        Err(OriginateError::Timeout { .. }) => StatusCode::GATEWAY_TIMEOUT,
        Err(OriginateError::ConnectionGone(_)) => StatusCode::BAD_GATEWAY,
    }
}
