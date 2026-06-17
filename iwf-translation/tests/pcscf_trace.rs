//! Test cases generated from a real IMS P-CSCF capture
//! (`traces_ims/sip_log_…pcap`). The P-CSCF speaks the **Rx interface** to
//! policy: AAR (media authorization), STR (teardown), with PCRF→P-CSCF
//! RAR/ASR. The raw on-the-wire bytes of the actual AAR and STR are embedded
//! and decoded (proving the codec parses the Rx AVP set — Media-Component-
//! Description → Media-Sub-Component → Flow-Number/Usage, repeated
//! Specific-Action / Subscription-Id, Supported-Features, …), then translated
//! to `Npcf_PolicyAuthorization`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use iwf_core::error::CoreError;
use iwf_core::ports::{Binding, BindingStore, SbaPort, SbiMethod, SbiRequest, SbiResponse};
use iwf_diameter::dictionary as dict;
use iwf_diameter::message::Message;
use iwf_translation::{AvpCatalog, CatalogStore, PluginRegistry, RuleStore, TranslationEngine};

const RULES: &str = include_str!("../../config/rules-nhss.yaml");
const DICT: &str = include_str!("../../config/dictionary.yaml");

const AAR: &[u8] = include_bytes!("fixtures/pcscf/aar.bin");
const STR: &[u8] = include_bytes!("fixtures/pcscf/str.bin");

const IMSI: &str = "404762140552482";

struct MockSba {
    seen: Mutex<Vec<SbiRequest>>,
}

#[async_trait]
impl SbaPort for MockSba {
    async fn send(&self, request: SbiRequest) -> Result<SbiResponse, CoreError> {
        let (status, body) = if request.path.ends_with("app-sessions") {
            (201, r#"{"appSessionId":"app-1"}"#) // create
        } else if request.path.ends_with("/delete") {
            (204, "{}") // teardown
        } else {
            (200, "{}")
        };
        self.seen.lock().expect("lock").push(request);
        Ok(SbiResponse {
            status,
            body: Bytes::from(body),
        })
    }
}

#[derive(Default)]
struct Bindings(Mutex<HashMap<String, Binding>>);

#[async_trait]
impl BindingStore for Bindings {
    async fn put(&self, id: String, b: Binding) {
        self.0.lock().expect("lock").insert(id, b);
    }
    async fn get(&self, id: &str) -> Option<Binding> {
        self.0.lock().expect("lock").get(id).cloned()
    }
    async fn take(&self, id: &str) -> Option<Binding> {
        self.0.lock().expect("lock").remove(id)
    }
}

fn engine() -> (TranslationEngine, Arc<MockSba>, Arc<Bindings>) {
    let catalog = Arc::new(CatalogStore::new(
        AvpCatalog::from_yaml(DICT).expect("dictionary"),
    ));
    let rules = Arc::new(RuleStore::with_catalog_store(
        iwf_translation::rule::RuleSet::from_yaml_with(RULES, &catalog.load()).expect("rules"),
        catalog.clone(),
    ));
    let sba = Arc::new(MockSba {
        seen: Mutex::new(Vec::new()),
    });
    let bindings = Arc::new(Bindings::default());
    let engine = TranslationEngine::new(
        rules,
        PluginRegistry::with_builtins(),
        sba.clone(),
        "iwf.epc.example.org",
        "epc.example.org",
    )
    .with_catalog_store(catalog)
    .with_bindings(bindings.clone())
    .with_notification_base("http://iwf-notif.epc.example.org");
    (engine, sba, bindings)
}

fn decode(bytes: &[u8]) -> Message {
    Message::decode(Bytes::copy_from_slice(bytes)).expect("decode real Diameter message")
}

#[tokio::test]
async fn rx_aar_maps_to_npcf_app_session_create() {
    let (engine, sba, bindings) = engine();
    let aar = decode(AAR);
    assert_eq!(aar.header.command, dict::CMD_AAR);
    assert_eq!(aar.header.application, dict::APP_RX);
    let session_id = aar.session_id().expect("AAR Session-Id").to_owned();

    let aaa = engine
        .translate(&aar, "pcscf-aar")
        .await
        .expect("translate");
    assert_eq!(aaa.result_code(), Some(dict::RC_SUCCESS));

    // The app-session was bound under the AAR Session-Id for later STR/RAR/ASR
    // (await before locking the recorder).
    assert!(bindings.get(&session_id).await.is_some());

    let seen = sba.seen.lock().expect("lock");
    assert_eq!(seen[0].method, SbiMethod::Post);
    assert_eq!(seen[0].nf_type, iwf_core::nf::NfType::Pcf);
    assert_eq!(seen[0].path, "/npcf-policyauthorization/v1/app-sessions");
    // SUPI dug out of the first Subscription-Id (END_USER_IMSI); AF service id
    // from AF-Application-Identifier.
    let body: serde_json::Value =
        serde_json::from_slice(seen[0].body.as_ref().expect("body")).expect("json");
    assert_eq!(body["ascReqData"]["supi"], IMSI);
    assert!(body["ascReqData"]["afAppId"]
        .as_str()
        .expect("afAppId")
        .contains("mmtel"));
}

#[tokio::test]
async fn rx_str_deletes_bound_app_session() {
    let (engine, sba, bindings) = engine();
    let str_msg = decode(STR);
    assert_eq!(str_msg.header.command, dict::CMD_STR);
    let session_id = str_msg.session_id().expect("STR Session-Id").to_owned();

    // A prior AAR (not in this fixture's session) created the app-session.
    bindings
        .put(
            session_id.clone(),
            Binding {
                peer_host: "pcscf-cp-0.rx.ims.example.org".to_owned(),
                peer_realm: "ims.example.org".to_owned(),
                identity: "ims-af".to_owned(),
                session_id: Some(session_id.clone()),
                resource_ref: Some("app-77".to_owned()),
                kind: "rx".to_owned(),
            },
        )
        .await;

    let sta = engine
        .translate(&str_msg, "pcscf-str")
        .await
        .expect("translate");
    assert_eq!(sta.result_code(), Some(dict::RC_SUCCESS));
    assert!(bindings.get(&session_id).await.is_none(), "binding freed");
    let seen = sba.seen.lock().expect("lock");
    assert_eq!(
        seen[0].path,
        "/npcf-policyauthorization/v1/app-sessions/app-77/delete"
    );
}

/// The codec round-trips the real AAR and STR (decode → re-encode is
/// byte-identical), covering the full Rx AVP tree.
#[test]
fn pcscf_messages_round_trip() {
    for (label, bytes) in [("AAR", AAR), ("STR", STR)] {
        let msg = decode(bytes);
        assert_eq!(
            msg.encode().as_ref(),
            bytes,
            "{label} did not re-encode to the original wire bytes"
        );
    }
}
