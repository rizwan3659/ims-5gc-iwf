//! Test cases generated from a real IMS S-CSCF registration capture
//! (`traces_ims/scscf.pcapng`). The raw, on-the-wire bytes of the actual
//! MAR / SAR / UDR / SNR requests are embedded as fixtures, decoded by the
//! IWF codec (proving it handles the full 3GPP AVP set — Vendor-Specific-
//! Application-Id, Supported-Features, nested User-Identity, SCSCF-
//! Restoration-Info, …), then translated by the engine against the shipped
//! rules + dictionary. Each test asserts the exact Nhss service the command
//! maps to.
//!
//! Identities in the trace: IMPI `404535130000201@ims.mnc053.mcc404.
//! 3gppnetwork.org`, IMPU `sip:404535130000201@…` (Cx), and `sip:+918801000201@…`
//! carried inside `User-Identity → Public-Identity` (Sh).

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

const MAR: &[u8] = include_bytes!("fixtures/scscf/mar.bin");
const SAR: &[u8] = include_bytes!("fixtures/scscf/sar.bin");
const UDR: &[u8] = include_bytes!("fixtures/scscf/udr.bin");
const SNR: &[u8] = include_bytes!("fixtures/scscf/snr.bin");

const IMPI: &str = "404535130000201@ims.mnc053.mcc404.3gppnetwork.org";
const CX_IMPU: &str = "sip:404535130000201@ims.mnc053.mcc404.3gppnetwork.org";
const SH_IMPU: &str = "sip:+918801000201@ims.mnc053.mcc404.3gppnetwork.org";

/// SBA mock that records each request and answers per the target path (so one
/// engine drives all four commands).
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
    if p.contains("ims-aka/generate-av") {
        (
            200,
            r#"{"av5gAka":{"rand":"a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5","autn":"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a","xresStar":"42424242424242424242424242424242"}}"#,
        )
    } else if p.contains("subscriptions") {
        (201, r#"{"subscriptionId":"sub-1"}"#)
    } else if p.contains("profile-data") {
        (200, r#"{"imsUserProfile":{"privateId":"404535130000201"}}"#)
    } else if p.contains("repository-data") {
        (200, r#"{"repositoryData":{"serviceData":"x"}}"#)
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
async fn mar_from_trace_maps_to_nhss_ueau() {
    let (engine, sba) = engine();
    let mar = decode(MAR);
    assert_eq!(mar.header.command, dict::CMD_MAR);
    assert_eq!(mar.header.application, dict::APP_CX);

    let maa = engine
        .translate(&mar, "trace-mar")
        .await
        .expect("translate");
    assert_eq!(maa.result_code(), Some(dict::RC_SUCCESS));
    // MAR → Nhss_imsUEAU generate-av, keyed by the IMPI (User-Name).
    let seen = sba.seen.lock().expect("lock");
    assert_eq!(seen[0].method, SbiMethod::Post);
    assert_eq!(seen[0].nf_type, iwf_core::nf::NfType::Hss);
    assert_eq!(
        seen[0].path,
        format!("/nhss-ims-ueau/v1/{IMPI}/ims-aka/generate-av")
    );
    // MAA carries the assembled SIP-Auth-Data-Item.
    assert!(maa
        .find(dict::AVP_SIP_AUTH_DATA_ITEM, Some(dict::VENDOR_3GPP))
        .is_some());
}

#[tokio::test]
async fn sar_from_trace_maps_to_uecm_registration_and_sdm_profile() {
    let (engine, sba) = engine();
    let sar = decode(SAR);
    assert_eq!(sar.header.command, dict::CMD_SAR);

    let saa = engine
        .translate(&sar, "trace-sar")
        .await
        .expect("translate");
    assert_eq!(saa.result_code(), Some(dict::RC_SUCCESS));
    // Server-Assignment-Type = REGISTRATION → UECM registration, then the
    // S-CSCF profile via SDM, keyed by the IMPU (Public-Identity).
    let seen = sba.seen.lock().expect("lock");
    assert_eq!(seen[0].method, SbiMethod::Put);
    assert_eq!(
        seen[0].path,
        format!("/nhss-ims-uecm/v1/{CX_IMPU}/registration")
    );
    assert_eq!(seen[1].method, SbiMethod::Get);
    assert_eq!(
        seen[1].path,
        format!("/nhss-ims-sdm/v1/{CX_IMPU}/ims-data/profile-data")
    );
    // SAA echoes the user profile in Cx-User-Data (606).
    assert!(saa
        .find(dict::AVP_USER_DATA, Some(dict::VENDOR_3GPP))
        .is_some());
}

#[tokio::test]
async fn udr_from_trace_extracts_nested_identity_and_maps_to_sdm() {
    let (engine, sba) = engine();
    let udr = decode(UDR);
    assert_eq!(udr.header.command, dict::CMD_UDR);
    assert_eq!(udr.header.application, dict::APP_SH);

    let uda = engine
        .translate(&udr, "trace-udr")
        .await
        .expect("translate");
    assert_eq!(uda.result_code(), Some(dict::RC_SUCCESS));
    // Identity comes from User-Identity → Public-Identity (no top-level
    // User-Name in the IPSMGW UDR); Data-Reference 0 (RepositoryData) → the
    // repository-data SDM resource.
    let seen = sba.seen.lock().expect("lock");
    assert_eq!(seen[0].method, SbiMethod::Get);
    assert_eq!(
        seen[0].path,
        format!("/nhss-ims-sdm/v1/{SH_IMPU}/repository-data")
    );
    // UDA carries Sh-User-Data (702), not Cx-User-Data (606).
    assert!(uda
        .find(dict::AVP_SH_USER_DATA, Some(dict::VENDOR_3GPP))
        .is_some());
}

#[tokio::test]
async fn snr_from_trace_maps_to_sdm_subscribe() {
    let (engine, sba) = engine();
    let snr = decode(SNR);
    assert_eq!(snr.header.command, dict::CMD_SNR);

    let sna = engine
        .translate(&snr, "trace-snr")
        .await
        .expect("translate");
    // The mock HSS accepts the subscription (201) → SNA success. (The real
    // trace's HSS returned 5106 SUBS_DATA_ABSENT; the *translation* — SNR →
    // SDM Subscribe — is what this asserts.)
    assert_eq!(sna.result_code(), Some(dict::RC_SUCCESS));
    let seen = sba.seen.lock().expect("lock");
    assert_eq!(seen[0].method, SbiMethod::Post);
    assert_eq!(
        seen[0].path,
        format!("/nhss-ims-sdm/v1/{SH_IMPU}/subscriptions")
    );
}

/// The codec round-trips every real message (all AVPs decode + re-encode to
/// the identical bytes), proving full wire-format coverage of the trace.
#[test]
fn all_trace_messages_round_trip() {
    for (label, bytes) in [("MAR", MAR), ("SAR", SAR), ("UDR", UDR), ("SNR", SNR)] {
        let msg = decode(bytes);
        let reencoded = msg.encode();
        assert_eq!(
            reencoded.as_ref(),
            bytes,
            "{label} did not re-encode to the original wire bytes"
        );
    }
}
