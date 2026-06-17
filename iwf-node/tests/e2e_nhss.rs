//! End-to-end Nhss integration test (3GPP TS 29.562): boots the real
//! `iwf-node` binary with the *shipped* `config/rules-nhss.yaml` against an
//! in-process mock NRF + Nhss HSS, then drives the flows over a real Diameter
//! TCP connection:
//!   * Phase 1 (terminating): UAR, LIR, SAR, MAR, UDR, PUR.
//!   * Phase 2 (server-push): Sh SNR → bind → an HSS notification → the IWF
//!     **originates** a PNR back to the AS; Cx SAR-register → bind → an HSS
//!     deregistration → the IWF originates an RTR to the S-CSCF.
//!   * All interfaces (`all_interfaces_end_to_end`): Cx, Sh, Rx and Ro driven
//!     against a multi-NF mock (NRF discovery resolves HSS/PCF/CHF by
//!     `target-nf-type`).
//!   * Dynamic config (`dynamic_avp_and_rule_via_admin_api`): a new vendor AVP
//!     + its rule added at runtime through the admin API, no restart.
//!
//! The NRF advertises NFs via `nfServices[].ipEndPoints` (not `apiPrefix`),
//! matching observed Open5GS behavior.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use iwf_diameter::avp::{avp_vendor, AvpValue};
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
            // Sh SNR → SDM Subscribe: 201 with a subscription resource.
            "/nhss-ims-sdm/v1/:imsUeId/subscriptions",
            axum::routing::post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    axum::Json(serde_json::json!({"subscriptionId": "sub-1"})),
                )
            }),
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
    notif_addr: String,
    admin_addr: String,
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
    let notif_port = free_port().await;

    // Unique per spawn (diameter_port) so concurrently-running tests don't
    // clobber each other's config/rules files.
    let dir = std::env::temp_dir().join(format!(
        "iwf-e2e-nhss-{}-{diameter_port}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let rules_path = dir.join("rules-nhss.yaml");
    std::fs::write(&rules_path, RULES).expect("rules");
    // Load the dictionary from a *directory* of *.yaml files, exercising the
    // node's directory-merge path (the "separate file per interface" feature).
    let dictionary_path = dir.join("dictionary.d");
    std::fs::create_dir_all(&dictionary_path).expect("dictionary dir");
    std::fs::write(dictionary_path.join("ims.yaml"), DICTIONARY).expect("dictionary");
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
notification:
  listen: "127.0.0.1:{notif_port}"
  advertised_uri: "http://127.0.0.1:{notif_port}"
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
        notif_addr: format!("127.0.0.1:{notif_port}"),
        admin_addr: format!("127.0.0.1:{admin_port}"),
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
        self.recv().await
    }

    /// Read one message off the connection (an answer, or an IWF-originated
    /// request such as PNR).
    async fn recv(&mut self) -> Message {
        let frame = read_frame(&mut self.reader, DEFAULT_MAX_FRAME)
            .await
            .expect("read frame")
            .expect("frame");
        Message::decode(frame).expect("decode")
    }

    /// Write one message (e.g. a PNA answering an IWF-originated PNR).
    async fn send(&mut self, msg: Message) {
        write_frame(&mut self.writer, &msg).await.expect("send");
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
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8("scscf;13;1".to_owned()),
        )
        .std(
            dict::AVP_ORIGIN_HOST,
            AvpValue::Utf8("icscf.ims.example.org".to_owned()),
        )
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
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8("scscf;14;1".to_owned()),
        )
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
        .find(dict::AVP_SH_USER_DATA, Some(dict::VENDOR_3GPP))
        .expect("Sh-User-Data");
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

/// Sh SNR (subscribe) → bind, then an Nhss data-change notification → the IWF
/// originates a Diameter PNR to the subscribing AS over its connection.
#[tokio::test]
async fn sh_snr_then_pnr_notification() {
    let hss_port = free_port().await;
    let nrf_uri = spawn_mock_nhss(hss_port).await;
    let node = spawn_node(&nrf_uri).await;
    let mut session = DiameterSession::open(&node.diameter_addr).await;

    // --- Sh SNR → SDM Subscribe → SNA 2001, binding recorded --------------
    // Origin-Host must match the CER origin host so the IWF can originate the
    // PNR back over this same connection.
    let snr = MessageBuilder::request(dict::CMD_SNR, dict::APP_SH)
        .ids(20, 20)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8("as-sub;20;1".to_owned()),
        )
        .std(
            dict::AVP_ORIGIN_HOST,
            AvpValue::Utf8("icscf.ims.example.org".to_owned()),
        )
        .std(
            dict::AVP_ORIGIN_REALM,
            AvpValue::Utf8("ims.example.org".to_owned()),
        )
        .tgpp(
            dict::AVP_PUBLIC_IDENTITY,
            AvpValue::Utf8("sip:alice@ims.example.org".to_owned()),
        )
        .build();
    let sna = session.transact(snr).await;
    assert_eq!(sna.header.command, dict::CMD_SNR);
    assert_eq!(sna.result_code(), Some(dict::RC_SUCCESS));

    // --- Fire the HSS notification to the IWF callback (binding = Session-Id,
    //     percent-encoded). The POST blocks until the IWF gets the PNA. ------
    let notif_url = format!("http://{}/iwf-notif/v1/as-sub%3B20%3B1", node.notif_addr);
    let post =
        tokio::spawn(async move { http_post(&notif_url, r#"{"changed":"profile-data"}"#).await });

    // --- The IWF originates a PNR on this connection ----------------------
    let pnr = session.recv().await;
    assert!(pnr.header.flags.request(), "PNR is a request");
    assert_eq!(pnr.header.command, dict::CMD_PNR);
    assert_eq!(pnr.header.application, dict::APP_SH);
    assert_eq!(
        pnr.find(dict::AVP_DESTINATION_HOST, None)
            .and_then(|a| a.as_utf8().ok()),
        Some("icscf.ims.example.org"),
        "routed to the subscribing AS"
    );
    // User-Identity (grouped) carries the bound subscriber Public-Identity.
    let user_identity = pnr
        .find(dict::AVP_USER_IDENTITY, Some(dict::VENDOR_3GPP))
        .expect("User-Identity")
        .as_grouped()
        .expect("grouped");
    assert_eq!(
        user_identity
            .iter()
            .find(|a| a.code == dict::AVP_PUBLIC_IDENTITY)
            .and_then(|a| a.as_utf8().ok()),
        Some("sip:alice@ims.example.org")
    );
    // The changed data was echoed from the notification body.
    let user_data = pnr
        .find(dict::AVP_SH_USER_DATA, Some(dict::VENDOR_3GPP))
        .expect("Sh-User-Data");
    let body: serde_json::Value = serde_json::from_slice(&user_data.data).expect("json");
    assert_eq!(body["changed"], "profile-data");

    // --- AS answers PNA 2001 → the IWF returns 204 to the HSS notification --
    let pna = MessageBuilder::answer_to(&pnr.header)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8(pnr.session_id().expect("PNR Session-Id").to_owned()),
        )
        .std(
            dict::AVP_ORIGIN_HOST,
            AvpValue::Utf8("icscf.ims.example.org".to_owned()),
        )
        .std(
            dict::AVP_ORIGIN_REALM,
            AvpValue::Utf8("ims.example.org".to_owned()),
        )
        .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS))
        .build();
    session.send(pna).await;

    let status = post.await.expect("post task");
    assert_eq!(status, 204, "HSS notification acknowledged after PNA");
}

/// Cx SAR (register) → bind, then an HSS deregistration notification → the IWF
/// originates a Diameter RTR to the serving S-CSCF; event routing picks RTR
/// (not PPR) from the notification body's `notificationType`.
#[tokio::test]
async fn cx_dereg_notification_originates_rtr() {
    let hss_port = free_port().await;
    let nrf_uri = spawn_mock_nhss(hss_port).await;
    let node = spawn_node(&nrf_uri).await;
    let mut session = DiameterSession::open(&node.diameter_addr).await;

    // --- SAR (REGISTRATION) records the S-CSCF binding (key = Session-Id) ---
    let sar = MessageBuilder::request(dict::CMD_SAR, dict::APP_CX)
        .ids(30, 30)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8("scscf;30;1".to_owned()),
        )
        .std(
            dict::AVP_ORIGIN_HOST,
            AvpValue::Utf8("icscf.ims.example.org".to_owned()),
        )
        .tgpp(
            dict::AVP_PUBLIC_IDENTITY,
            AvpValue::Utf8("sip:alice@ims.example.org".to_owned()),
        )
        .tgpp(
            dict::AVP_SERVER_ASSIGNMENT_TYPE,
            AvpValue::Enum(dict::server_assignment_type::REGISTRATION),
        )
        .build();
    assert_eq!(
        session.transact(sar).await.result_code(),
        Some(dict::RC_SUCCESS)
    );

    // --- HSS deregistration notification → IWF originates RTR --------------
    let notif_url = format!("http://{}/iwf-notif/v1/scscf%3B30%3B1", node.notif_addr);
    let post = tokio::spawn(async move {
        http_post(
            &notif_url,
            r#"{"notificationType":"DEREGISTRATION","reason":"admin-removed"}"#,
        )
        .await
    });

    let rtr = session.recv().await;
    assert!(rtr.header.flags.request());
    assert_eq!(rtr.header.command, dict::CMD_RTR);
    assert_eq!(rtr.header.application, dict::APP_CX);
    assert_eq!(
        rtr.find(dict::AVP_PUBLIC_IDENTITY, Some(dict::VENDOR_3GPP))
            .and_then(|a| a.as_utf8().ok()),
        Some("sip:alice@ims.example.org")
    );
    // Deregistration-Reason (grouped) with Reason-Code + Reason-Info from body.
    let dereg = rtr
        .find(dict::AVP_DEREGISTRATION_REASON, Some(dict::VENDOR_3GPP))
        .expect("Deregistration-Reason")
        .as_grouped()
        .expect("grouped");
    assert_eq!(
        dereg
            .iter()
            .find(|a| a.code == dict::AVP_REASON_INFO)
            .and_then(|a| a.as_utf8().ok()),
        Some("admin-removed")
    );

    // --- S-CSCF answers RTA 2001 → 204 to the HSS notification -------------
    let rta = MessageBuilder::answer_to(&rtr.header)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8(rtr.session_id().expect("RTR Session-Id").to_owned()),
        )
        .std(
            dict::AVP_ORIGIN_HOST,
            AvpValue::Utf8("icscf.ims.example.org".to_owned()),
        )
        .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS))
        .build();
    session.send(rta).await;

    assert_eq!(post.await.expect("post"), 204);
}

/// Minimal HTTP/1.1 POST returning the status code (avoids a client dep).
async fn http_post(url: &str, body: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let without_scheme = url.strip_prefix("http://").expect("http url");
    let (host, path) = without_scheme
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((without_scheme, "/".to_owned()));
    let mut stream = TcpStream::connect(host).await.expect("connect notif");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send notif");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read notif response");
    response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code")
}

// =====================================================================
// All-interfaces + dynamic-AVP coverage (Cx / Sh / Rx / Ro over one node).
// =====================================================================

/// Mock NRF that answers discovery per `target-nf-type` (HSS / PCF / CHF, all
/// pointing at one combined data plane) plus a data plane serving Nhss, Npcf
/// and Nchf routes.
async fn spawn_mock_5gc_multi() -> String {
    let data_port = free_port().await;

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
            axum::routing::get(
                move |axum::extract::Query(params): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    let nf_type = params
                        .get("target-nf-type")
                        .cloned()
                        .unwrap_or_else(|| "HSS".to_owned());
                    let service = match nf_type.as_str() {
                        "PCF" => "npcf-policyauthorization",
                        "CHF" => "nchf-convergedcharging",
                        _ => "nhss-ims-uecm",
                    };
                    axum::Json(serde_json::json!({
                        "validityPeriod": 3600,
                        "nfInstances": [{
                            "nfInstanceId": format!("{nf_type}-mock"),
                            "nfType": nf_type,
                            "nfStatus": "REGISTERED",
                            "nfServices": [{
                                "serviceInstanceId": "s1", "serviceName": service,
                                "scheme": "http", "priority": 0, "capacity": 100,
                                "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": data_port }]
                            }]
                        }]
                    }))
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind nrf");
    let nrf_addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, nrf_app).await.expect("mock nrf");
    });

    // Combined data plane: HSS (Cx/Sh) + PCF (Rx) + CHF (Ro).
    let ok_json = || async { axum::Json(serde_json::json!({})) };
    let data_app = axum::Router::new()
        // --- Nhss (Cx UAR, Sh UDR) ---
        .route(
            "/nhss-ims-uecm/v1/:id/authorize",
            axum::routing::post(ok_json),
        )
        .route(
            "/nhss-ims-sdm/v1/:id/*rest",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"repositoryData": {"serviceData": "x"}}))
            }),
        )
        // --- Npcf_PolicyAuthorization (Rx AAR/STR) ---
        .route(
            "/npcf-policyauthorization/v1/app-sessions",
            axum::routing::post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    axum::Json(serde_json::json!({"appSessionId": "app-1"})),
                )
            }),
        )
        .route(
            "/npcf-policyauthorization/v1/app-sessions/:id/delete",
            axum::routing::post(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        // --- Nchf_ConvergedCharging (Ro CCR I/U/T) ---
        .route(
            "/nchf-convergedcharging/v1/chargingdata",
            axum::routing::post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    axum::Json(
                        serde_json::json!({"chargingDataRef": "chg-1", "grantedUnit": {"ccTime": 3600}}),
                    ),
                )
            }),
        )
        .route(
            "/nchf-convergedcharging/v1/chargingdata/:ref/update",
            axum::routing::post(ok_json),
        )
        .route(
            "/nchf-convergedcharging/v1/chargingdata/:ref/release",
            axum::routing::post(ok_json),
        );
    let data_listener = tokio::net::TcpListener::bind(("127.0.0.1", data_port))
        .await
        .expect("bind data plane");
    tokio::spawn(async move {
        axum::serve(data_listener, data_app)
            .await
            .expect("mock data plane");
    });

    format!("http://{nrf_addr}")
}

/// Drive every interface — Cx, Sh, Rx, Ro — over one Diameter connection
/// against the multi-NF mock, asserting each answers success.
#[tokio::test]
async fn all_interfaces_end_to_end() {
    let nrf_uri = spawn_mock_5gc_multi().await;
    let node = spawn_node(&nrf_uri).await;
    let mut session = DiameterSession::open(&node.diameter_addr).await;

    // --- Cx UAR → HSS ---
    let uar = MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
        .ids(60, 60)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8("icscf;60;1".to_owned()),
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
    assert_eq!(
        session.transact(uar).await.result_code(),
        Some(dict::RC_SUCCESS),
        "Cx UAR"
    );

    // --- Sh UDR → HSS ---
    let udr = MessageBuilder::request(dict::CMD_UDR, dict::APP_SH)
        .ids(61, 61)
        .std(
            dict::AVP_USER_NAME,
            AvpValue::Utf8("alice@ims.example.org".to_owned()),
        )
        .tgpp(dict::AVP_DATA_REFERENCE, AvpValue::Enum(0))
        .build();
    assert_eq!(
        session.transact(udr).await.result_code(),
        Some(dict::RC_SUCCESS),
        "Sh UDR"
    );

    // --- Rx AAR (create app-session) then STR (delete it) → PCF ---
    let aar = MessageBuilder::request(dict::CMD_AAR, dict::APP_RX)
        .ids(62, 62)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8("pcscf;62;1".to_owned()),
        )
        .std(
            dict::AVP_ORIGIN_HOST,
            AvpValue::Utf8("pcscf.ims.example.org".to_owned()),
        )
        .build();
    assert_eq!(
        session.transact(aar).await.result_code(),
        Some(dict::RC_SUCCESS),
        "Rx AAR"
    );
    let str_req = MessageBuilder::request(dict::CMD_STR, dict::APP_RX)
        .ids(63, 63)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8("pcscf;62;1".to_owned()),
        )
        .build();
    assert_eq!(
        session.transact(str_req).await.result_code(),
        Some(dict::RC_SUCCESS),
        "Rx STR"
    );

    // --- Ro CCR Initial / Update / Terminate (one charging session) → CHF ---
    let ccr = |num: u32, req_type: i32| {
        MessageBuilder::request(dict::CMD_CCR, dict::APP_RO)
            .ids(num, num)
            .std(dict::AVP_SESSION_ID, AvpValue::Utf8("ctf;64;1".to_owned()))
            .std(416, AvpValue::Enum(req_type)) // CC-Request-Type
            .std(415, AvpValue::U32(num)) // CC-Request-Number
            .build()
    };
    for (num, req_type, label) in [
        (64, 1, "INITIAL"),
        (65, 2, "UPDATE"),
        (66, 3, "TERMINATION"),
    ] {
        assert_eq!(
            session.transact(ccr(num, req_type)).await.result_code(),
            Some(dict::RC_SUCCESS),
            "Ro CCR {label}"
        );
    }
}

#[derive(serde::Serialize)]
struct AdminClaims {
    sub: String,
    aud: String,
    scope: String,
    exp: u64,
}

/// Mint an HS256 admin JWT signed with the e2e secret (matches the node's
/// `jwt_hs256_secret_env`).
fn mint_admin_token(scope: &str) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        + 600;
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &AdminClaims {
            sub: "e2e".to_owned(),
            aud: "iwf-admin".to_owned(),
            scope: scope.to_owned(),
            exp,
        },
        &jsonwebtoken::EncodingKey::from_secret(b"e2e-secret"),
    )
    .expect("encode jwt")
}

/// Authenticated HTTP/1.1 PUT returning the status code.
async fn http_put_auth(url: &str, body: &str, token: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let without_scheme = url.strip_prefix("http://").expect("http url");
    let (host, path) = without_scheme
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((without_scheme, "/".to_owned()));
    let mut stream = TcpStream::connect(host).await.expect("connect admin");
    let request = format!(
        "PUT {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send put");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read put response");
    response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code")
}

/// Define a **brand-new vendor AVP and its translation entirely at runtime**
/// via the admin API (no recompile, no restart), then exercise it over real
/// Diameter: a command that was unknown before becomes a 2001 that echoes the
/// dynamically-defined AVP.
#[tokio::test]
async fn dynamic_avp_and_rule_via_admin_api() {
    let hss_port = free_port().await;
    let nrf_uri = spawn_mock_nhss(hss_port).await;
    let node = spawn_node(&nrf_uri).await;
    let mut session = DiameterSession::open(&node.diameter_addr).await;

    // A Cx-application request on an unused command carrying a not-yet-known
    // vendor AVP (code 9100, vendor 4242).
    let probe = || {
        MessageBuilder::request(320, dict::APP_CX)
            .ids(50, 50)
            .std(dict::AVP_SESSION_ID, AvpValue::Utf8("dyn;50;1".to_owned()))
            .avp(avp_vendor(
                9100,
                4242,
                AvpValue::Utf8("hello-dynamic".to_owned()),
            ))
            .build()
    };

    // 1. Before: no rule for command 320 → DIAMETER_COMMAND_UNSUPPORTED.
    assert_eq!(
        session.transact(probe()).await.result_code(),
        Some(dict::RC_COMMAND_UNSUPPORTED)
    );

    let token = mint_admin_token("iwf:provisioning");
    let admin = |p: &str| format!("http://{}{p}", node.admin_addr);

    // 2. Add the AVP: the shipped dictionary plus a new `custom` interface.
    let dict_plus = format!(
        "{DICTIONARY}\n  custom:\n    avps:\n      - {{ name: My-New-Avp, code: 9100, vendor: 4242, type: UTF8String }}\n"
    );
    assert_eq!(
        http_put_auth(&admin("/admin/v1/dictionary"), &dict_plus, &token).await,
        200,
        "dictionary hot-reload"
    );

    // 3. Add a rule that extracts the new AVP and echoes it back.
    let dyn_rule = r#"
rules:
  - id: dyn_echo
    trigger: { diameter_application: 16777216, command_code: 320 }
    actions:
      - extract: { avp: "My-New-Avp", as: v }
      - map_response:
          default:
            result_code: 2001
            avps:
              - { avp: My-New-Avp, value: "{v}" }
    version: dyn
"#;
    assert_eq!(
        http_put_auth(&admin("/admin/v1/rules"), dyn_rule, &token).await,
        200,
        "rule hot-reload"
    );

    // 4. After: the request now translates, echoing the runtime-defined AVP.
    let answer = session.transact(probe()).await;
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
    assert_eq!(
        answer.find(9100, Some(4242)).and_then(|a| a.as_utf8().ok()),
        Some("hello-dynamic"),
        "the dynamically-added AVP round-trips"
    );
}
