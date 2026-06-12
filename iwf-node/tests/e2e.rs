//! End-to-end integration test: boots the real `iwf-node` binary against
//! in-process mock NRF / UDM / UDR servers (Axum — no docker-compose), then
//! drives Cx and Sh flows over a real Diameter TCP connection.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use iwf_diameter::avp::AvpValue;
use iwf_diameter::base::LocalIdentity;
use iwf_diameter::dictionary as dict;
use iwf_diameter::message::{Message, MessageBuilder};
use iwf_diameter::transport::{read_frame, write_frame, DEFAULT_MAX_FRAME};
use tokio::net::TcpStream;

const RULES: &str = r#"
rules:
  - id: cx_uar_to_udm_identity_query
    trigger:
      diameter_application: 16777216
      command_code: 300
    actions:
      - extract: { avp: "User-Name", as: impi }
      - extract: { avp: "Public-Identity", as: impu }
      - http_request:
          method: GET
          nf_type: UDM
          path: "/nudm-uecm/v1/{impi}/registrations"
          query:
            impu: "{impu}"
      - map_response:
          200: build_uaa_success
          404: build_uaa_user_unknown
          503: build_uaa_unable_to_comply
    version: "3gpp-rel18"
  - id: sh_udr_to_udr_data_read
    trigger:
      diameter_application: 16777217
      command_code: 306
    actions:
      - extract: { avp: "User-Name", as: impi, required: false }
      - http_request:
          method: GET
          nf_type: UDR
          path: "/nudr-dr/v1/subscription-data"
      - map_response:
          200: build_uda_success
          404: build_user_unknown
          default: build_unable_to_comply
    version: "3gpp-rel18"
"#;

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

/// Mock NRF (registration + heartbeat + discovery) and UDM/UDR data plane.
async fn spawn_mock_5gc(udm_port: u16) -> String {
    let udm_base = format!("http://127.0.0.1:{udm_port}");

    // NRF + data plane on one server, distinct route spaces.
    let discovery_payload = serde_json::json!({
        "validityPeriod": 3600,
        "nfInstances": [{
            "nfInstanceId": "nf-mock-1",
            "nfType": "UDM",
            "nfStatus": "REGISTERED",
            "nfServices": [{
                "serviceInstanceId": "s1",
                "serviceName": "nudm-uecm",
                "scheme": "http",
                "apiPrefix": udm_base,
                "priority": 0,
                "capacity": 100
            }]
        }]
    });

    let app = axum::Router::new()
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
                let payload = discovery_payload.clone();
                async move { axum::Json(payload) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind nrf");
    let nrf_addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock nrf");
    });

    // UDM/UDR data plane on the pre-allocated port the NRF advertises.
    let data_app = axum::Router::new()
        .route(
            "/nudm-uecm/v1/:ueid/registrations",
            axum::routing::get(
                |axum::extract::Path(ueid): axum::extract::Path<String>| async move {
                    if ueid.starts_with("unknown") {
                        (
                            axum::http::StatusCode::NOT_FOUND,
                            axum::Json(serde_json::json!({"cause": "USER_NOT_FOUND"})),
                        )
                    } else {
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(
                                serde_json::json!({"scscfName": "sip:scscf1.ims.example.org"}),
                            ),
                        )
                    }
                },
            ),
        )
        .route(
            "/nudr-dr/v1/subscription-data",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({"repositoryData": {"serviceData": "x"}})),
                )
            }),
        );
    let data_listener = tokio::net::TcpListener::bind(("127.0.0.1", udm_port))
        .await
        .expect("bind udm");
    tokio::spawn(async move {
        axum::serve(data_listener, data_app)
            .await
            .expect("mock udm");
    });

    format!("http://{nrf_addr}")
}

struct NodeProcess {
    child: Child,
    diameter_addr: String,
    admin_base: String,
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

    let dir = std::env::temp_dir().join(format!("iwf-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let rules_path = dir.join("rules.yaml");
    std::fs::write(&rules_path, RULES).expect("rules");
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
"#,
            rules = rules_path.display()
        ),
    )
    .expect("config");

    let child = Command::new(env!("CARGO_BIN_EXE_iwf-node"))
        .env("IWF_CONFIG", &config_path)
        .env("IWF_LOG_LEVEL", "info")
        .env("IWF_SBA_HTTP1", "1") // mocks are HTTP/1.1
        .env("IWF_E2E_JWT_SECRET", "e2e-secret")
        .spawn()
        .expect("spawn iwf-node");

    let node = NodeProcess {
        child,
        diameter_addr: format!("127.0.0.1:{diameter_port}"),
        admin_base: format!("http://127.0.0.1:{admin_port}"),
    };

    // Wait for the Diameter listener.
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
            product_name: "e2e-client".to_owned(),
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

fn uar(hbh: u32, impi: &str) -> Message {
    MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
        .ids(hbh, hbh)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8(format!("icscf;{hbh};1")),
        )
        .std(dict::AVP_USER_NAME, AvpValue::Utf8(impi.to_owned()))
        .tgpp(
            dict::AVP_PUBLIC_IDENTITY,
            AvpValue::Utf8("sip:alice@ims.example.org".to_owned()),
        )
        .build()
}

#[tokio::test]
async fn cx_and_sh_flows_end_to_end() {
    let udm_port = free_port().await;
    let nrf_uri = spawn_mock_5gc(udm_port).await;
    let node = spawn_node(&nrf_uri).await;
    let mut session = DiameterSession::open(&node.diameter_addr).await;

    // --- Cx UAR, known user → UAA 2001 with Server-Name -------------------
    let answer = session.transact(uar(10, "alice@ims.example.org")).await;
    assert_eq!(answer.header.command, dict::CMD_UAR);
    assert_eq!(answer.header.hop_by_hop, 10);
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
    assert_eq!(
        answer
            .find(dict::AVP_SERVER_NAME, Some(dict::VENDOR_3GPP))
            .and_then(|a| a.as_utf8().ok()),
        Some("sip:scscf1.ims.example.org")
    );
    assert_eq!(answer.session_id(), Some("icscf;10;1"));

    // --- Cx UAR, unknown user → Experimental-Result 5001 ------------------
    let answer = session.transact(uar(11, "unknown@ims.example.org")).await;
    assert_eq!(answer.result_code(), None);
    let experimental = answer
        .find(dict::AVP_EXPERIMENTAL_RESULT, None)
        .expect("Experimental-Result")
        .as_grouped()
        .expect("grouped");
    let code = experimental
        .iter()
        .find(|a| a.code == dict::AVP_EXPERIMENTAL_RESULT_CODE)
        .expect("code")
        .as_u32()
        .expect("u32");
    assert_eq!(code, dict::ERC_USER_UNKNOWN);

    // --- Sh UDR → UDA with User-Data ---------------------------------------
    let udr = MessageBuilder::request(dict::CMD_UDR, dict::APP_SH)
        .ids(12, 12)
        .std(dict::AVP_SESSION_ID, AvpValue::Utf8("as;12;1".to_owned()))
        .std(
            dict::AVP_USER_NAME,
            AvpValue::Utf8("alice@ims.example.org".to_owned()),
        )
        .build();
    let answer = session.transact(udr).await;
    assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
    let user_data = answer
        .find(dict::AVP_USER_DATA, Some(dict::VENDOR_3GPP))
        .expect("User-Data");
    let body: serde_json::Value = serde_json::from_slice(&user_data.data).expect("json payload");
    assert_eq!(body["repositoryData"]["serviceData"], "x");

    // --- Unsupported command → 3001 ----------------------------------------
    let bogus = MessageBuilder::request(dict::CMD_PPR, dict::APP_CX)
        .ids(13, 13)
        .build();
    let answer = session.transact(bogus).await;
    assert_eq!(answer.result_code(), Some(dict::RC_COMMAND_UNSUPPORTED));

    // --- Watchdog -----------------------------------------------------------
    let local = LocalIdentity {
        origin_host: "icscf.ims.example.org".to_owned(),
        origin_realm: "ims.example.org".to_owned(),
        product_name: "e2e".to_owned(),
        vendor_id: dict::VENDOR_3GPP,
        applications: vec![dict::APP_CX],
        origin_state_id: 1,
    };
    let dwa = session.transact(local.build_dwr(99, 99)).await;
    assert_eq!(dwa.header.command, dict::CMD_DWR);
    assert_eq!(dwa.result_code(), Some(dict::RC_SUCCESS));

    // --- Health endpoints -----------------------------------------------------
    let healthz = http_get(&format!("{}/healthz", node.admin_base)).await;
    assert_eq!(healthz, 200);
}

/// Minimal HTTP GET returning the status code (avoids a client dependency).
async fn http_get(url: &str) -> u16 {
    let without_scheme = url.strip_prefix("http://").expect("http url");
    let (host, path) = without_scheme
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((without_scheme, "/".to_owned()));
    let mut stream = TcpStream::connect(host).await.expect("connect admin");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("send request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read response");
    response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code")
}
