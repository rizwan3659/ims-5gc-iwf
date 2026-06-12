//! High-throughput mock 5GC (NRF + UDM) for IWF load testing.
//!
//! Serves NRF registration/heartbeat/discovery and a constant-time
//! Nudm_UECM registration query, fast enough that the IWF under test —
//! not the mock — is the bottleneck.
//!
//! Usage: `mock5gc [nrf_listen] [udm_listen]`
//! (defaults `127.0.0.1:18080` / `127.0.0.1:18081`).

#![deny(warnings)]
#![forbid(unsafe_code)]

use axum::routing::{get, put};
use axum::Router;

fn nrf_app(udm_base: String) -> Router {
    Router::new()
        .route(
            "/nnrf-nfm/v1/nf-instances/:id",
            put(|body: String| async move {
                let mut profile: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or_else(|_| serde_json::json!({}));
                profile["heartBeatTimer"] = serde_json::json!(30);
                (axum::http::StatusCode::CREATED, axum::Json(profile))
            })
            .patch(|| async { axum::http::StatusCode::NO_CONTENT })
            .delete(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        .route(
            "/nnrf-disc/v1/nf-instances",
            get(move || {
                let payload = serde_json::json!({
                    "validityPeriod": 3600,
                    "nfInstances": [{
                        "nfInstanceId": "udm-mock",
                        "nfType": "UDM",
                        "nfStatus": "REGISTERED",
                        "nfServices": [{
                            "serviceInstanceId": "s1",
                            "serviceName": "nudm-uecm",
                            "scheme": "http",
                            "apiPrefix": udm_base.clone(),
                            "priority": 0,
                            "capacity": 100
                        }]
                    }]
                });
                async move { axum::Json(payload) }
            }),
        )
}

fn udm_app() -> Router {
    Router::new().route(
        "/nudm-uecm/v1/:ueid/registrations",
        get(|| async {
            axum::Json(serde_json::json!({"scscfName": "sip:scscf1.ims.example.org"}))
        }),
    )
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let nrf_listen = args.next().unwrap_or_else(|| "127.0.0.1:18080".to_owned());
    let udm_listen = args.next().unwrap_or_else(|| "127.0.0.1:18081".to_owned());

    let udm_listener = match tokio::net::TcpListener::bind(&udm_listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {udm_listen}: {e}");
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
    println!("mock5gc: NRF on {nrf_listen}, UDM on {udm_listen}");

    let nrf = nrf_app(format!("http://{udm_listen}"));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(nrf_listener, nrf).await {
            eprintln!("nrf serve: {e}");
        }
    });
    if let Err(e) = axum::serve(udm_listener, udm_app()).await {
        eprintln!("udm serve: {e}");
    }
}
