//! End-to-end Nhss integration test (3GPP TS 29.562): boots the real
//! `iwf-node` binary with the *shipped* `config/rules-nhss.yaml` against an
//! in-process mock NRF + Nhss HSS (the same route set as
//! `iwf-benchmark/src/bin/mock_nhss.rs`), then drives every Phase-1 flow —
//! UAR, LIR, SAR (registration + deregistration), MAR, UDR, PUR — over a
//! real Diameter TCP connection.
//!
//! The NRF advertises the HSS via `nfServices[].ipEndPoints` (not
//! `apiPrefix`), matching observed Open5GS behavior.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use iwf_diameter::avp::AvpValue;
use iwf_diameter::base::LocalIdentity;
use iwf_diameter::dictionary as dict;
use iwf_diameter::message::{Message, MessageBuilder};
use iwf_diameter::transport::{read_frame, write_frame, DEFAULT_MAX_FRAME};
use tokio::net::TcpStream;

/// The production rule document under test — not a test-local copy.
const RULES: &str = include_str!("../../config/rules-nhss.yaml");

/// The shipped AVP dictionary, loaded through `dictionary_file` so the
/// dynamic catalog path (not the builtin table) is what this test runs on.
const DICTIONARY: &str = include_str!("../../config/dictionary.yaml");

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

/// Mock NRF (registration + heartbeat + discovery → HSS via ipEndPoints) and
/// the Nhss_imsUECM / Nhss_imsSDM / Nhss_imsUEAU data plane.
async fn spawn_mock_nhss(hss_port: u16) -> String {
    let nrf_app = axum::Router::new()
        .route(
            "/nnrf-nfm/v1/nf-instances/:id",
            axum::routing::put(|body: String| async move {
                let mut profile: serde_json::Value = serde_json::from_str(&body).expect("profile");
                profile["heartBeatTimer"] = serde_json::json!(30);
                (axum::http::StatusCode::CREATED, axum::Json(profile))
            })
            .patch(|| async { axum::http::StatusCode::NO_CONTENT })
            .delete(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        .route(
            "/nnrf-disc/v1/nf-instances",
            axum::routing::get(move || {
                let payload = serde_json::json!({
                    "validityPeriod": 3600,
                    "nfInstances": [{
                        "nfInstanceId": "hss-e2e",
                        "nfType": "HSS",
                        "nfStatus": "REGISTERED",
                        "nfServices": [{
                            "serviceInstanceId": "nhss",
                            "serviceName": "nhss-ims-uecm",
                            "scheme": "http",
                            "priority": 0,
                            "capacity": 100,
                            "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": hss_port }]
                        }]
                    }]
                });
                async move { axum::Json(payload) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind nrf");
    let nrf_addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, nrf_app).await.expect("mock nrf");
    });

    // Nhss data plane on the pre-allocated port the NRF advertises.
    // "unknown" identities 404 so the 5001 USER_UNKNOWN mapping is exercised.
    let hss_app = axum::Router::new()
        .route(
            "/nhss-ims-uecm/v1/:imsUeId/authorize",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({"authorizationResult": "AUTHORIZED"}))
            }),
        )
        .route(
            "/nhss-ims-uecm/v1/:imsUeId/:op",
            axum::routing::put(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/ims-data/location-data/scscf-capabilities",
            axum::routing::get(|| async {
                axum::Json(
                    serde_json::json!({"mandatoryCapabilities": [1], "optionalCapabilities": []}),
                )
            }),
        )
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/ims-data/location-data/server-name",
            axum::routing::get(
                |axum::extract::Path(ims_ue_id): axum::extract::Path<String>| async move {
                    if ims_ue_id.contains("unknown") {
                        (
                            axum::http::StatusCode::NOT_FOUND,
                            axum::Json(serde_json::json!({"cause": "USER_NOT_FOUND"})),
                        )
                    } else {
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(
                                serde_json::json!({"serverName": "sip:scscf1.ims.example.org"}),
                            ),
                        )
                    }
                },
            ),
        )
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/ims-data/profile-data",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "imsUserProfile": { "privateId": "alice@ims.example.org",
                        "publicIds": ["sip:alice@ims.example.org"] }
                }))
            }),
        )
        .route(
            "/nhss-ims-sdm/v1/:imsUeId/repository-data",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"repositoryData": {"serviceData": "x"}}))
            })
            .put(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        .route(
            "/nhss-ims-ueau/v1/:imsUeId/ims-aka/generate-av",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "av5gAka": {
                        "rand": "a5".repeat(16),
                        "autn": "5a".repeat(16),
                        "xresStar": "42".repeat(16)
                    }
                }))
            }),
        );
    let hss_listener = tokio::net::TcpListener::bind(("127.0.0.1", hss_port))
        .await
        .expect("bind hss");
    tokio::spawn(async move {
        axum::serve(hss_listener, hss_app).await.expect("mock hss");
    });

    format!("http://{nrf_addr}")
}

struct NodeProcess {
    child: Child,
    diameter_addr: String,
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn spawn_node(nrf_uri: &str) -> NodeProcess {
    let diameter_port = free_port().await;
    let admin_port = free_port().await;
    let metrics_port = free_port().await;

    let dir = std::env::temp_dir().join(format!("iwf-e2e-nhss-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let rules_path = dir.join("rules-nhss.yaml");
    std::fs::write(&rules_path, RULES).expect("rules");
    let dictionary_path = dir.join("dictionary.yaml");
    std::fs::write(&dictionary_path, DICTIONARY).expect("dictionary");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            r#"
diameter:
  listen: "127.0.0.1:{diameter_port}"
  origin_host: "iwf-e2e.epc.example.org"
  origin_realm: "epc.example.org"
  transaction_timeout_ms: 4000
sba:
  nrf_uri: "{nrf_uri}"
admin:
  listen: "127.0.0.1:{admin_port}"
  metrics_listen: "127.0.0.1:{metrics_port}"
  jwt_hs256_secret_env: "IWF_E2E_JWT_SECRET"
rules_file: "{rules}"
dictionary_file: "{dictionary}"
"#,
            rules = rules_path.display(),
            dictionary = dictionary_path.display()
        ),
    )
    .expect("config");

    let child = Command::new(env!("CARGO_BIN_EXE_iwf-node"))
        .env("IWF_CONFIG", &config_path)
        .env("IWF_LOG_LEVEL", "info")
        .env("IWF_SBA_HTTP1", "1") // axum mocks negotiate HTTP/1.1
        .env("IWF_E2E_JWT_SECRET", "e2e-secret")
        .spawn()
        .expect("spawn iwf-node");

    let node = NodeProcess {
        child,
        diameter_addr: format!("127.0.0.1:{diameter_port}"),
    };

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect(&node.diameter_addr).await.is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "iwf-node did not come up");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    node
}

struct DiameterSession {
    reader: tokio::net::tcp::OwnedReadHalf,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl DiameterSession {
    async fn open(addr: &str) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect diameter");
        let (mut reader, mut writer) = stream.into_split();
        let local = LocalIdentity {
            origin_host: "icscf.ims.example.org".to_owned(),
            origin_realm: "ims.example.org".to_owned(),
            product_name: "e2e-nhss-client".to_owned(),
            vendor_id: dict::VENDOR_3GPP,
            applications: vec![dict::APP_CX, dict::APP_SH],
            origin_state_id: 1,
        };
        write_frame(&mut writer, &local.build_cer(1, 1))
            .await
            .expect("send CER");
        let cea = read_frame(&mut reader, DEFAULT_MAX_FRAME)
            .await
            .expect("read CEA")
            .expect("CEA frame");
        let cea = Message::decode(cea).expect("decode CEA");
        assert_eq!(cea.result_code(), Some(dict::RC_SUCCESS), "CEA success");
        DiameterSession { reader, writer }
    }

    async fn transact(&mut self, request: Message) -> Message {
        write_frame(&mut self.writer, &request)
            .await
            .expect("send request");
        let frame = read_frame(&mut self.reader, DEFAULT_MAX_FRAME)
            .await
            .expect("read answer")
            .expect("answer frame");
        Message::decode(frame).expect("decode answer")
    }
}

fn experimental_code(answer: &Message) -> u32 {
    answer
        .find(dict::AVP_EXPERIMENTAL_RESULT, None)
        .expect("Experimental-Result")
        .as_grouped()
        .expect("grouped")
        .iter()
        .find(|a| a.code == dict::AVP_EXPERIMENTAL_RESULT_CODE)
        .expect("code")
        .as_u32()
        .expect("u32")
}

#[tokio::test]
async fn nhss_flows_end_to_end() {
    let hss_port = free_port().await;
    let nrf_uri = spawn_mock_nhss(hss_port).await;
    let node = spawn_node(&nrf_uri).await;
    let mut session = DiameterSession::open(&node.diameter_addr).await;

    // --- Cx UAR → UECM_Authorize + SDM_Get(scscf-capabilities) → UAA 2001 --
    let uar = MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
        .ids(10, 10)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8("icscf;10;1".to_owned()),
        )
        .std(
            dict::AVP_USER_NAME,
            AvpValue::Utf8("alice@ims.example.org".to_owned()),
        )
        .tgpp(
            dict::AVP_PUBLIC_IDENTITY,
            AvpValue::Utf8("sip:alice@ims.example.org".to_owned()),
        )
        .build();
    let answer = session.transact(uar).await;
    assert_eq!(answer.header.command, dict::CMD_UAR);
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
    assert_eq!(answer.session_id(), Some("icscf;10;1"));

    // --- Cx LIR → SDM_Get(server-name) → LIA 2001 + Server-Name ------------
    let lir = MessageBuilder::request(dict::CMD_LIR, dict::APP_CX)
        .ids(11, 11)
        .tgpp(
            dict::AVP_PUBLIC_IDENTITY,
            AvpValue::Utf8("sip:alice@ims.example.org".to_owned()),
        )
        .build();
    let answer = session.transact(lir).await;
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
    assert_eq!(
        answer
            .find(dict::AVP_SERVER_NAME, Some(dict::VENDOR_3GPP))
            .and_then(|a| a.as_utf8().ok()),
        Some("sip:scscf1.ims.example.org")
    );

    // --- Cx LIR, unknown user → Experimental-Result 5001 -------------------
    let lir = MessageBuilder::request(dict::CMD_LIR, dict::APP_CX)
        .ids(12, 12)
        .tgpp(
            dict::AVP_PUBLIC_IDENTITY,
            AvpValue::Utf8("sip:unknown@ims.example.org".to_owned()),
        )
        .build();
    let answer = session.transact(lir).await;
    assert_eq!(answer.result_code(), None);
    assert_eq!(experimental_code(&answer), dict::ERC_USER_UNKNOWN);

    // --- Cx SAR (REGISTRATION) → UECM PUT registration + profile → SAA -----
    let sar = MessageBuilder::request(dict::CMD_SAR, dict::APP_CX)
        .ids(13, 13)
        .tgpp(
            dict::AVP_PUBLIC_IDENTITY,
            AvpValue::Utf8("sip:alice@ims.example.org".to_owned()),
        )
        .tgpp(
            dict::AVP_SERVER_NAME,
            AvpValue::Utf8("sip:scscf1.ims.example.org".to_owned()),
        )
        .tgpp(
            dict::AVP_SERVER_ASSIGNMENT_TYPE,
            AvpValue::Enum(dict::server_assignment_type::REGISTRATION),
        )
        .build();
    let answer = session.transact(sar).await;
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
    let profile = answer
        .find(dict::AVP_USER_DATA, Some(dict::VENDOR_3GPP))
        .expect("User-Data");
    let profile: serde_json::Value = serde_json::from_slice(&profile.data).expect("profile json");
    assert_eq!(
        profile["imsUserProfile"]["privateId"],
        "alice@ims.example.org"
    );

    // --- Cx SAR (USER_DEREGISTRATION) → UECM PUT deregistration → SAA ------
    let sar = MessageBuilder::request(dict::CMD_SAR, dict::APP_CX)
        .ids(14, 14)
        .tgpp(
            dict::AVP_PUBLIC_IDENTITY,
            AvpValue::Utf8("sip:alice@ims.example.org".to_owned()),
        )
        .tgpp(
            dict::AVP_SERVER_ASSIGNMENT_TYPE,
            AvpValue::Enum(dict::server_assignment_type::USER_DEREGISTRATION),
        )
        .build();
    let answer = session.transact(sar).await;
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));

    // --- Cx MAR → UEAU generate-av → MAA 2001 + SIP-Auth-Data-Item ---------
    let mar = MessageBuilder::request(dict::CMD_MAR, dict::APP_CX)
        .ids(15, 15)
        .std(
            dict::AVP_USER_NAME,
            AvpValue::Utf8("alice@ims.example.org".to_owned()),
        )
        .build();
    let answer = session.transact(mar).await;
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
    assert!(answer
        .find(dict::AVP_SIP_AUTH_DATA_ITEM, Some(dict::VENDOR_3GPP))
        .is_some());

    // --- Sh UDR (Data-Reference 12 S-CSCFName) → SDM_Get(server-name) ------
    let udr = MessageBuilder::request(dict::CMD_UDR, dict::APP_SH)
        .ids(16, 16)
        .std(
            dict::AVP_USER_NAME,
            AvpValue::Utf8("alice@ims.example.org".to_owned()),
        )
        .tgpp(
            dict::AVP_DATA_REFERENCE,
            AvpValue::Enum(dict::data_reference::SCSCF_NAME),
        )
        .build();
    let answer = session.transact(udr).await;
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
    let user_data = answer
        .find(dict::AVP_USER_DATA, Some(dict::VENDOR_3GPP))
        .expect("User-Data");
    let body: serde_json::Value = serde_json::from_slice(&user_data.data).expect("json payload");
    assert_eq!(body["serverName"], "sip:scscf1.ims.example.org");

    // --- Sh PUR → SDM_Update(repository-data) → PUA 2001 --------------------
    let pur = MessageBuilder::request(dict::CMD_PUR, dict::APP_SH)
        .ids(17, 17)
        .std(
            dict::AVP_USER_NAME,
            AvpValue::Utf8("alice@ims.example.org".to_owned()),
        )
        .tgpp(
            dict::AVP_USER_DATA,
            AvpValue::Utf8("service-data-x".to_owned()),
        )
        .build();
    let answer = session.transact(pur).await;
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
}
