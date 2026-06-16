//! # iwf-admin
//!
//! Management REST API (Axum) plus health/readiness/metrics endpoints.
//!
//! Routes (OpenAPI spec in `openapi/iwf-admin.yaml`):
//!
//! | Route | Method | Permission |
//! |---|---|---|
//! | `/healthz` | GET | none (liveness) |
//! | `/readyz` | GET | none (readiness) |
//! | `/metrics` | GET | none (scrape; served on the metrics listener) |
//! | `/admin/v1/log-level` | PUT | `operate` |
//! | `/admin/v1/rules` | GET | `read` |
//! | `/admin/v1/rules` | PUT | `provision` |
//! | `/admin/v1/dictionary` | PUT | `provision` |
//!
//! Authentication: `Authorization: Bearer <JWT>`; the JWT must pass
//! signature/expiry/audience validation and carry a scope mapping to a
//! role that grants the route's permission (see `iwf_security::rbac`).

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::Router;
use iwf_observability::{LogHandle, Metrics};
use iwf_security::jwt::JwtValidator;
use iwf_security::rbac::{allows, role_from_scopes, Permission};
use iwf_translation::rule::RuleStore;
use iwf_translation::{AvpCatalog, CatalogStore};

/// Readiness inputs aggregated from the rest of the node.
#[derive(Debug, Default)]
pub struct Readiness {
    /// NRF registration succeeded (heartbeat task).
    pub nrf_registered: AtomicBool,
    /// At least one Diameter peer is OPEN.
    pub peer_connected: AtomicBool,
    /// Drain in progress: readiness goes false first so the LB stops
    /// sending new work while in-flight transactions complete.
    pub draining: AtomicBool,
}

impl Readiness {
    /// Ready to take traffic?
    pub fn ready(&self) -> bool {
        self.nrf_registered.load(Ordering::Acquire)
            && self.peer_connected.load(Ordering::Acquire)
            && !self.draining.load(Ordering::Acquire)
    }
}

/// Shared state for the admin routers.
#[derive(Clone)]
pub struct AdminState {
    /// Log-level reload handle (None only in tests without logging).
    pub log: Option<LogHandle>,
    /// Active translation rules.
    pub rules: Arc<RuleStore>,
    /// Active AVP dictionary (shared with the engine + rule validation), so a
    /// `PUT /admin/v1/dictionary` swap is seen everywhere.
    pub catalog: Arc<CatalogStore>,
    /// Metric registry.
    pub metrics: Metrics,
    /// Readiness aggregation.
    pub readiness: Arc<Readiness>,
    /// Validator for admin JWTs.
    pub jwt: Arc<JwtValidator>,
}

fn authorize(
    state: &AdminState,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<(), StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims =
        validate_with_any_iwf_scope(&state.jwt, token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let role = role_from_scopes(&claims.scope).ok_or(StatusCode::FORBIDDEN)?;
    if !allows(role, permission) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

async fn readyz(State(state): State<AdminState>) -> impl IntoResponse {
    if state.readiness.ready() {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn metrics(State(state): State<AdminState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

async fn put_log_level(
    State(state): State<AdminState>,
    headers: HeaderMap,
    body: String,
) -> Result<StatusCode, StatusCode> {
    authorize(&state, &headers, Permission::Operate)?;
    let level = body.trim().trim_matches('"');
    match &state.log {
        Some(handle) => handle
            .set_level(level)
            .map(|()| StatusCode::NO_CONTENT)
            .map_err(|_| StatusCode::BAD_REQUEST),
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn get_rules(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    authorize(&state, &headers, Permission::Read)?;
    let snapshot = state.rules.load();
    let summary: Vec<serde_json::Value> = snapshot
        .rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "version": r.version,
                "rollout_percent": r.rollout_percent,
                "trigger": {
                    "diameter_application": r.trigger.diameter_application,
                    "command_code": r.trigger.command_code,
                },
            })
        })
        .collect();
    Ok(axum::Json(serde_json::json!({ "rules": summary })))
}

async fn put_rules(
    State(state): State<AdminState>,
    headers: HeaderMap,
    body: String,
) -> Result<impl IntoResponse, StatusCode> {
    authorize(&state, &headers, Permission::Provision)?;
    match state.rules.reload_yaml(&body) {
        Ok(count) => Ok(axum::Json(serde_json::json!({ "activated_rules": count }))),
        Err(e) => {
            tracing::warn!(error = %e, "rule reload rejected");
            Err(StatusCode::UNPROCESSABLE_ENTITY)
        }
    }
}

/// Hot-swap the AVP dictionary. The new document must parse *and* the
/// currently-active rules must still validate against it (no orphaned AVP
/// names), otherwise the swap is rejected and the old dictionary stays active.
/// Replaces the whole catalog (PUT semantics), like `PUT /admin/v1/rules`.
async fn put_dictionary(
    State(state): State<AdminState>,
    headers: HeaderMap,
    body: String,
) -> Result<impl IntoResponse, StatusCode> {
    authorize(&state, &headers, Permission::Provision)?;
    let new = AvpCatalog::from_yaml(&body).map_err(|e| {
        tracing::warn!(error = %e, "dictionary reload: parse rejected");
        StatusCode::UNPROCESSABLE_ENTITY
    })?;
    if let Err(e) = state.rules.load().validate(&new) {
        tracing::warn!(error = %e, "dictionary reload: active rules no longer valid");
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let count = new.len();
    state.catalog.store(new);
    Ok(axum::Json(serde_json::json!({ "activated_avps": count })))
}

/// Admin API router (health + admin routes).
pub fn admin_router(state: AdminState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/admin/v1/log-level", put(put_log_level))
        .route("/admin/v1/rules", get(get_rules).put(put_rules))
        .route("/admin/v1/dictionary", put(put_dictionary))
        .with_state(state)
}

/// Metrics-only router for the scrape listener.
pub fn metrics_router(state: AdminState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(state)
}

/// Validate the token requiring *some* IWF role scope; which permissions
/// that scope grants is decided afterwards by RBAC in [`authorize`].
fn validate_with_any_iwf_scope(
    validator: &JwtValidator,
    token: &str,
) -> Result<iwf_security::jwt::ValidatedClaims, iwf_security::jwt::JwtError> {
    for scope in ["iwf:read", "iwf:provisioning", "iwf:operator"] {
        match validator.validate(token, scope) {
            Ok(claims) => return Ok(claims),
            Err(iwf_security::jwt::JwtError::InsufficientScope) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(iwf_security::jwt::JwtError::InsufficientScope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;
    use tower::util::ServiceExt;

    #[derive(Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        aud: &'a str,
        scope: &'a str,
        exp: u64,
    }

    fn token(scope: &str) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            + 600;
        encode(
            &Header::default(),
            &TestClaims {
                sub: "test",
                aud: "iwf-admin",
                scope,
                exp,
            },
            &EncodingKey::from_secret(b"admin-test-secret"),
        )
        .expect("encode")
    }

    const RULES: &str = r#"
rules:
  - id: r1
    trigger: { diameter_application: 16777216, command_code: 300 }
    actions:
      - map_response: { default: build_success }
    version: v1
"#;

    fn state() -> AdminState {
        let rules = Arc::new(RuleStore::new(
            iwf_translation::rule::RuleSet::from_yaml(RULES).expect("rules"),
        ));
        let catalog = rules.catalog(); // share the builtin catalog with admin
        AdminState {
            log: None,
            rules,
            catalog,
            metrics: Metrics::new().expect("metrics"),
            readiness: Arc::new(Readiness::default()),
            jwt: Arc::new(JwtValidator::hs256(b"admin-test-secret", "iwf-admin")),
        }
    }

    async fn call(router: Router, request: Request<Body>) -> (StatusCode, String) {
        let response = router.oneshot(request).await.expect("infallible");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn healthz_is_open() {
        let (status, _) = call(
            admin_router(state()),
            Request::get("/healthz").body(Body::empty()).expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_gates_on_registration_and_peers() {
        let s = state();
        let router = admin_router(s.clone());
        let (status, _) = call(
            router.clone(),
            Request::get("/readyz").body(Body::empty()).expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        s.readiness.nrf_registered.store(true, Ordering::Release);
        s.readiness.peer_connected.store(true, Ordering::Release);
        let (status, _) = call(
            router,
            Request::get("/readyz").body(Body::empty()).expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn rules_require_auth() {
        let (status, _) = call(
            admin_router(state()),
            Request::get("/admin/v1/rules")
                .body(Body::empty())
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn read_only_can_get_but_not_put_rules() {
        let s = state();
        let auth = format!("Bearer {}", token("iwf:read"));
        let (status, body) = call(
            admin_router(s.clone()),
            Request::get("/admin/v1/rules")
                .header("authorization", &auth)
                .body(Body::empty())
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("r1"));

        let (status, _) = call(
            admin_router(s),
            Request::put("/admin/v1/rules")
                .header("authorization", &auth)
                .body(Body::from(RULES))
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn provisioning_can_replace_rules_and_bad_yaml_is_rejected() {
        let s = state();
        let auth = format!("Bearer {}", token("iwf:provisioning"));
        let updated = RULES.replace("id: r1", "id: r2");
        let (status, body) = call(
            admin_router(s.clone()),
            Request::put("/admin/v1/rules")
                .header("authorization", &auth)
                .body(Body::from(updated))
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("activated_rules"));
        assert_eq!(s.rules.load().rules[0].id, "r2");

        let (status, _) = call(
            admin_router(s.clone()),
            Request::put("/admin/v1/rules")
                .header("authorization", &auth)
                .body(Body::from("rules: ["))
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(s.rules.load().rules[0].id, "r2", "previous rules intact");
    }

    #[tokio::test]
    async fn dictionary_reload_adds_avp_and_protects_active_rules() {
        let s = state();
        let auth = format!("Bearer {}", token("iwf:provisioning"));
        let custom_rule = r#"
rules:
  - id: r1
    trigger: { diameter_application: 16777216, command_code: 300 }
    actions:
      - extract: { avp: "Foo-Thing", as: x }
      - map_response: { default: build_success }
    version: v1
"#;
        // Foo-Thing is unknown to the builtin catalog → rule reload rejected.
        let (status, _) = call(
            admin_router(s.clone()),
            Request::put("/admin/v1/rules")
                .header("authorization", &auth)
                .body(Body::from(custom_rule))
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // PUT a dictionary defining Foo-Thing.
        let dictionary = r#"
interfaces:
  custom:
    avps:
      - { name: Foo-Thing, code: 9000, vendor: 4242, type: UTF8String }
"#;
        let (status, body) = call(
            admin_router(s.clone()),
            Request::put("/admin/v1/dictionary")
                .header("authorization", &auth)
                .body(Body::from(dictionary))
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("activated_avps"), "got {body}");

        // …now the same rule validates against the hot-swapped dictionary.
        let (status, _) = call(
            admin_router(s.clone()),
            Request::put("/admin/v1/rules")
                .header("authorization", &auth)
                .body(Body::from(custom_rule))
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // A dictionary that would orphan the now-active rule's AVP is rejected.
        let drops_foo = r#"
interfaces:
  custom:
    avps:
      - { name: Other-Thing, code: 9001, vendor: 4242, type: UTF8String }
"#;
        let (status, _) = call(
            admin_router(s.clone()),
            Request::put("/admin/v1/dictionary")
                .header("authorization", &auth)
                .body(Body::from(drops_foo))
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        // Old dictionary intact: Foo-Thing still resolves.
        assert!(s.catalog.load().get("Foo-Thing").is_some());
    }

    #[tokio::test]
    async fn dictionary_reload_requires_provisioning() {
        let s = state();
        let (status, _) = call(
            admin_router(s),
            Request::put("/admin/v1/dictionary")
                .header("authorization", format!("Bearer {}", token("iwf:read")))
                .body(Body::from("interfaces: {}"))
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn log_level_requires_operator() {
        let s = state();
        let (status, _) = call(
            admin_router(s.clone()),
            Request::put("/admin/v1/log-level")
                .header(
                    "authorization",
                    format!("Bearer {}", token("iwf:provisioning")),
                )
                .body(Body::from("debug"))
                .expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn metrics_render() {
        let (status, body) = call(
            metrics_router(state()),
            Request::get("/metrics").body(Body::empty()).expect("req"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("iwf_active_sessions_total"));
    }
}
