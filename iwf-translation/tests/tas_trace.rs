//! Test cases generated from a real IMS TAS (Telephony Application Server)
//! capture (`traces_ims/tas.pcapng`) — the "register" and "call" legs. The
//! raw on-the-wire bytes of the actual Cx SAR, Sh UDR, Sh PUR and **Rf ACR**
//! requests are embedded and decoded by the IWF codec (proving it parses the
//! deep TS 32.299 charging tree — Service-Information → IMS-Information /
//! MMTel-Information / Inter-Operator-Identifier / Time-Stamps …), then
//! translated against the shipped rules. Each test asserts the exact 5GC
//! service the command maps to.

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

const ACR: &[u8] = include_bytes!("fixtures/tas/acr.bin");
const SAR: &[u8] = include_bytes!("fixtures/tas/sar.bin");
const UDR: &[u8] = include_bytes!("fixtures/tas/udr.bin");
const PUR: &[u8] = include_bytes!("fixtures/tas/pur.bin");

const SAR_IMPU: &str = "sip:+918801000842@ims.mnc053.mcc404.3gppnetwork.org";
const UDR_IMPU: &str = "sip:+918801000201@ims.mnc053.mcc404.3gppnetwork.org";
const PUR_IMPU: &str = "tel:+918801000842";
const ACR_SERVED: &str = "sip:+918801000842@ims.mnc053.mcc404.3gppnetwork.org";

struct MockSba {
    seen: Mutex<Vec<SbiRequest>>,
}

#[async_trait]
impl SbaPort for MockSba {
    async fn send(&self, request: SbiRequest) -> Result<SbiResponse, CoreError> {
        let (status, body) = route(&request);
        self.seen.lock().expect("lock").push(request);
        Ok(SbiResponse {
            status,
            body: Bytes::from(body),
        })
    }
}

fn route(req: &SbiRequest) -> (u16, &'static str) {
    let p = &req.path;
    if p.contains("nchf-convergedcharging") {
        (201, r#"{"invocationSequenceNumber":1}"#)
    } else if p.contains("profile-data") {
        (200, r#"{"imsUserProfile":{}}"#)
    } else if p.contains("location-data") || p.contains("repository-data") {
        (200, r#"{"locationData":{"location":"x"}}"#)
    } else {
        (200, "{}")
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

fn engine() -> (TranslationEngine, Arc<MockSba>) {
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
    let engine = TranslationEngine::new(
        rules,
        PluginRegistry::with_builtins(),
        sba.clone(),
        "iwf.epc.example.org",
        "epc.example.org",
    )
    .with_catalog_store(catalog)
    .with_bindings(Arc::new(Bindings::default()))
    .with_notification_base("http://iwf-notif.epc.example.org");
    (engine, sba)
}

fn decode(bytes: &[u8]) -> Message {
    Message::decode(Bytes::copy_from_slice(bytes)).expect("decode real Diameter message")
}

#[tokio::test]
async fn rf_acr_call_charging_maps_to_nchf() {
    let (engine, sba) = engine();
    let acr = decode(ACR);
    assert_eq!(acr.header.command, dict::CMD_ACR);
    assert_eq!(acr.header.application, dict::APP_RF);

    let aca = engine.translate(&acr, "tas-acr").await.expect("translate");
    assert_eq!(aca.result_code(), Some(dict::RC_SUCCESS));

    let seen = sba.seen.lock().expect("lock");
    assert_eq!(seen[0].method, SbiMethod::Post);
    assert_eq!(seen[0].nf_type, iwf_core::nf::NfType::Chf);
    assert_eq!(seen[0].path, "/nchf-convergedcharging/v1/chargingdata");
    // The served identity was dug out of the deep nested charging tree
    // (Service-Information → Subscription-Id → Subscription-Id-Data).
    let body: serde_json::Value =
        serde_json::from_slice(seen[0].body.as_ref().expect("charging body")).expect("json");
    assert_eq!(body["servedIdentity"], ACR_SERVED);
    assert_eq!(body["recordType"], "EVENT");
}

#[tokio::test]
async fn cx_sar_unregistered_user_maps_to_uecm_registration() {
    let (engine, sba) = engine();
    let sar = decode(SAR);
    assert_eq!(sar.header.command, dict::CMD_SAR);

    let saa = engine.translate(&sar, "tas-sar").await.expect("translate");
    assert_eq!(saa.result_code(), Some(dict::RC_SUCCESS));
    // Server-Assignment-Type = UNREGISTERED_USER → UECM registration.
    let seen = sba.seen.lock().expect("lock");
    assert_eq!(
        seen[0].path,
        format!("/nhss-ims-uecm/v1/{SAR_IMPU}/registration")
    );
}

#[tokio::test]
async fn sh_udr_location_info_maps_to_sdm_location_data() {
    let (engine, sba) = engine();
    let udr = decode(UDR);
    assert_eq!(udr.header.command, dict::CMD_UDR);

    let uda = engine.translate(&udr, "tas-udr").await.expect("translate");
    assert_eq!(uda.result_code(), Some(dict::RC_SUCCESS));
    // Data-Reference 14 (LocationInformation) + nested identity → the
    // ps-domain location-data SDM resource.
    let seen = sba.seen.lock().expect("lock");
    assert_eq!(seen[0].method, SbiMethod::Get);
    assert_eq!(
        seen[0].path,
        format!("/nhss-ims-sdm/v1/{UDR_IMPU}/access-data/ps-domain/location-data")
    );
}

#[tokio::test]
async fn sh_pur_stn_sr_maps_to_sdm_update() {
    let (engine, sba) = engine();
    let pur = decode(PUR);
    assert_eq!(pur.header.command, dict::CMD_PUR);

    let pua = engine.translate(&pur, "tas-pur").await.expect("translate");
    assert_eq!(pua.result_code(), Some(dict::RC_SUCCESS));
    // Identity is a tel: URI nested in User-Identity; PUR → SDM update.
    let seen = sba.seen.lock().expect("lock");
    assert_eq!(seen[0].method, SbiMethod::Put);
    assert_eq!(
        seen[0].path,
        format!("/nhss-ims-sdm/v1/{PUR_IMPU}/repository-data")
    );
}

/// The codec round-trips every real TAS message (decode → re-encode yields
/// the identical bytes), proving full wire-format coverage including the
/// 1372-byte Rf ACR charging tree.
#[test]
fn all_tas_messages_round_trip() {
    for (label, bytes) in [("ACR", ACR), ("SAR", SAR), ("UDR", UDR), ("PUR", PUR)] {
        let msg = decode(bytes);
        assert_eq!(
            msg.encode().as_ref(),
            bytes,
            "{label} did not re-encode to the original wire bytes"
        );
    }
}
