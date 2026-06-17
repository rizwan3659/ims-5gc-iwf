//! Mock Nhss HSS (3GPP TS 29.562) for IWF integration/load testing.
//!
//! Serves two roles on loopback:
//!   * NRF (Nnrf): register/heartbeat/deregister + discovery that returns
//!     *this* process as an `HSS` instance, so the IWF can discover it.
//!   * HSS (Nhss): the `Nhss_imsUECM`, `Nhss_imsSDM`, `Nhss_imsUEAU`
//!     endpoints exercised by `config/rules-nhss.yaml`.
//!
//! Usage: `mock_nhss [nrf_listen] [hss_listen]`
//! (defaults `127.0.0.1:18080` / `127.0.0.1:18082`).
//!
//! Responses are constant-time so the IWF, not the mock, is the bottleneck.

#![deny(warnings)]
#![forbid(unsafe_code)]

use axum::routing::{get, post, put};
use axum::Router;

fn nrf_app(hss_base: String) -> Router {
    Router::new()
        .route(
            "/nnrf-nfm/v1/nf-instances/:id",
            put(|body: String| async move {
                let mut p: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or_else(|_| serde_json::json!({}));
                p["heartBeatTimer"] = serde_json::json!(30);
                (axum::http::StatusCode::CREATED, axum::Json(p))
            })
            .patch(|| async { axum::http::StatusCode::NO_CONTENT })
            .delete(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        .route(
            "/nnrf-disc/v1/nf-instances",
            get(move || {
                // Advertise this process as an HSS via ipEndPoints.
                let (host, port) = hss_base
                    .strip_prefix("http://")
                    .and_then(|s| s.split_once(':'))
                    .unwrap_or(("127.0.0.1", "18082"));
                let payload = serde_json::json!({
                    "validityPeriod": 3600,
                    "nfInstances": [{
                        "nfInstanceId": "hss-mock",
                        "nfType": "HSS",
                        "nfStatus": "REGISTERED",
                        "nfServices": [
                            { "serviceInstanceId": "uecm", "serviceName": "nhss-ims-uecm",
                              "scheme": "http", "priority": 0, "capacity": 100,
                              "ipEndPoints": [{ "ipv4Address": host, "port": port.parse::<u16>().unwrap_or(18082) }] }
                        ]
                    }]
                });
                async move { axum::Json(payload) }
            }),
        )
}

fn hss_app() -> Router {
    // Nhss_imsUEAU — authentication vector (Cx MAR).
    let ueau = || async {
        axum::Json(serde_json::json!({
            "av5gAka": {
                "rand": "a5".repeat(16),
                "autn": "5a".repeat(16),
                "xresStar": "42".repeat(16)
            }
        }))
    };
    // Nhss_imsSDM — server-name (Cx LIR), scscf-capabilities (Cx UAR),
    // profile-data (Cx SAR), and a catch-all SDM_Get (Sh UDR).
    Router::new()
        .route(
            "/nhss-ims-uecm/v1/:imsUeId/authorize",
            post(|| async { axum::Json(serde_json::json!({"authorizationResult": "AUTHORIZED"})) }),
        )
        .route(
            "/nhss-ims-uecm/v1/:imsUeId/:op",
            put(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/ims-data/location-data/scscf-capabilities",
            get(|| async {
                axum::Json(
                    serde_json::json!({"mandatoryCapabilities": [1], "optionalCapabilities": []}),
                )
            }),
        )
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/ims-data/location-data/server-name",
            get(|| async {
                axum::Json(serde_json::json!({"serverName": "sip:scscf1.ims.example.org"}))
            }),
        )
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/ims-data/profile-data",
            get(|| async {
                axum::Json(serde_json::json!({
                    "imsUserProfile": { "privateId": "user@ims.example.org",
                        "publicIds": ["sip:user@ims.example.org"] }
                }))
            }),
        )
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/repository-data",
            get(|| async {
                axum::Json(serde_json::json!({"repositoryData": {"serviceData": "x"}}))
            })
            .put(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        // Sh SNR → SDM Subscribe (POST): 201 with a subscription resource.
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/subscriptions",
            post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    axum::Json(serde_json::json!({"subscriptionId": "sub-1"})),
                )
            }),
        )
        // Catch-all SDM_Get for the remaining Data-Reference resources.
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/*rest",
            get(|| async { axum::Json(serde_json::json!({"data": "ok"})) }),
        )
        .route("/nhss-ims-ueau/v1/:imsUeId/ims-aka/generate-av", post(ueau))
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let nrf_listen = args.next().unwrap_or_else(|| "127.0.0.1:18080".to_owned());
    let hss_listen = args.next().unwrap_or_else(|| "127.0.0.1:18082".to_owned());

    let hss_listener = match tokio::net::TcpListener::bind(&hss_listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {hss_listen}: {e}");
            std::process::exit(1);
        }
    };
    let nrf_listener = match tokio::net::TcpListener::bind(&nrf_listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {nrf_listen}: {e}");
            std::process::exit(1);
        }
    };
    println!("mock_nhss: NRF on {nrf_listen}, Nhss HSS on {hss_listen}");

    let nrf = nrf_app(format!("http://{hss_listen}"));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(nrf_listener, nrf).await {
            eprintln!("nrf serve: {e}");
        }
    });
    if let Err(e) = axum::serve(hss_listener, hss_app()).await {
        eprintln!("hss serve: {e}");
    }
}
