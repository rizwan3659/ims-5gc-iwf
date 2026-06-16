//! Runtime AVP catalog: resolves the AVP names used in rule documents to
//! their wire definitions (code, vendor, Diameter type).
//!
//! The catalog is **configuration, not code**: it is loaded from a YAML
//! dictionary organized per interface (base / cx / sh / …), so supporting a
//! new interface or AVP is a dictionary edit, not a recompile. When no
//! dictionary file is configured the [`AvpCatalog::builtin`] table (the
//! Cx/Sh subset of TS 29.229 / TS 29.329 the IWF has always known) applies.
//!
//! Dictionary document shape:
//!
//! ```yaml
//! interfaces:
//!   base:
//!     description: "RFC 6733 base protocol"
//!     avps:
//!       - { name: User-Name, code: 1, type: UTF8String }
//!   cx:
//!     application: 16777216
//!     avps:
//!       - { name: Public-Identity, code: 601, vendor: 10415, type: UTF8String }
//! ```
//!
//! Interface sections are organizational: AVP identity in Diameter is
//! (vendor, code), so all sections merge into one name → definition map.
//! The same name may appear in several sections only with an identical
//! definition (e.g. `User-Name` in both cx and sh).

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use iwf_core::error::CoreError;
use iwf_diameter::dictionary as dict;
use serde::Deserialize;

/// Diameter base type of an AVP (RFC 6733 §4.2/§4.3 derived types collapse
/// onto their base: DiameterIdentity/DiameterURI/Time → here `UTF8String` /
/// `OctetString` as the wire form dictates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum AvpKind {
    /// UTF8String (also DiameterIdentity / DiameterURI).
    #[serde(rename = "UTF8String")]
    Utf8String,
    /// OctetString (also Time / Address payloads handled opaquely).
    OctetString,
    /// Unsigned32.
    Unsigned32,
    /// Unsigned64.
    Unsigned64,
    /// Enumerated (signed 32-bit wire form).
    Enumerated,
    /// Grouped.
    Grouped,
}

impl AvpKind {
    /// Whether values are 32/64-bit integers on the wire. The codec cannot
    /// infer this from bytes — a 4-octet Enumerated like `1` is also valid
    /// UTF-8 — so `extract` consults the catalog to render integer AVPs as
    /// their decimal string (needed for `set_var` branching on
    /// Server-Assignment-Type, Data-Reference, …).
    pub fn is_integer(self) -> bool {
        matches!(
            self,
            AvpKind::Unsigned32 | AvpKind::Unsigned64 | AvpKind::Enumerated
        )
    }
}

/// Wire definition of one AVP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvpDef {
    /// AVP Code.
    pub code: u32,
    /// Vendor-Id when vendor-specific (V bit set).
    pub vendor: Option<u32>,
    /// Diameter base type.
    pub kind: AvpKind,
}

/// Name → definition catalog consulted by rule validation and the engine.
#[derive(Debug, Clone)]
pub struct AvpCatalog {
    by_name: HashMap<String, AvpDef>,
}

impl Default for AvpCatalog {
    fn default() -> Self {
        AvpCatalog::builtin()
    }
}

/// Dictionary document root.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DictionaryDoc {
    interfaces: BTreeMap<String, InterfaceSection>,
}

/// One interface section (cx / sh / …). `application` and `description`
/// are informational.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceSection {
    #[serde(default)]
    #[allow(dead_code)] // informational; reserved for trigger cross-checks
    application: Option<u32>,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    avps: Vec<AvpEntry>,
}

/// One AVP row of a dictionary section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AvpEntry {
    name: String,
    code: u32,
    #[serde(default)]
    vendor: Option<u32>,
    #[serde(rename = "type")]
    kind: AvpKind,
}

impl AvpCatalog {
    /// The compiled-in Cx/Sh table (TS 29.229 / TS 29.329 subset), used when
    /// no dictionary file is configured. `config/dictionary.yaml` ships a
    /// superset of this table.
    pub fn builtin() -> Self {
        use AvpKind::*;
        let v3 = Some(dict::VENDOR_3GPP);
        let table: &[(&str, u32, Option<u32>, AvpKind)] = &[
            // RFC 6733 base.
            ("User-Name", dict::AVP_USER_NAME, None, Utf8String),
            ("Session-Id", dict::AVP_SESSION_ID, None, Utf8String),
            ("Origin-Host", dict::AVP_ORIGIN_HOST, None, Utf8String),
            ("Origin-Realm", dict::AVP_ORIGIN_REALM, None, Utf8String),
            (
                "Destination-Realm",
                dict::AVP_DESTINATION_REALM,
                None,
                Utf8String,
            ),
            (
                "Destination-Host",
                dict::AVP_DESTINATION_HOST,
                None,
                Utf8String,
            ),
            ("Result-Code", dict::AVP_RESULT_CODE, None, Unsigned32),
            // Cx (TS 29.229 §6.3).
            ("Public-Identity", dict::AVP_PUBLIC_IDENTITY, v3, Utf8String),
            ("Server-Name", dict::AVP_SERVER_NAME, v3, Utf8String),
            (
                "SIP-Number-Auth-Items",
                dict::AVP_SIP_NUMBER_AUTH_ITEMS,
                v3,
                Unsigned32,
            ),
            (
                "SIP-Authentication-Scheme",
                dict::AVP_SIP_AUTH_SCHEME,
                v3,
                Utf8String,
            ),
            (
                "SIP-Authenticate",
                dict::AVP_SIP_AUTHENTICATE,
                v3,
                OctetString,
            ),
            (
                "SIP-Authorization",
                dict::AVP_SIP_AUTHORIZATION,
                v3,
                OctetString,
            ),
            (
                "SIP-Auth-Data-Item",
                dict::AVP_SIP_AUTH_DATA_ITEM,
                v3,
                Grouped,
            ),
            (
                "Server-Assignment-Type",
                dict::AVP_SERVER_ASSIGNMENT_TYPE,
                v3,
                Enumerated,
            ),
            (
                "User-Authorization-Type",
                dict::AVP_USER_AUTHORIZATION_TYPE,
                v3,
                Enumerated,
            ),
            (
                "Confidentiality-Key",
                dict::AVP_CONFIDENTIALITY_KEY,
                v3,
                OctetString,
            ),
            ("Integrity-Key", dict::AVP_INTEGRITY_KEY, v3, OctetString),
            // Sh (TS 29.329 §6.3).
            ("User-Data", dict::AVP_USER_DATA, v3, OctetString),
            ("User-Identity", dict::AVP_USER_IDENTITY, v3, Grouped),
            ("Data-Reference", dict::AVP_DATA_REFERENCE, v3, Enumerated),
            ("MSISDN", dict::AVP_MSISDN, v3, OctetString),
            ("Subs-Req-Type", dict::AVP_SUBS_REQ_TYPE, v3, Enumerated),
        ];
        let by_name = table
            .iter()
            .map(|&(name, code, vendor, kind)| (name.to_owned(), AvpDef { code, vendor, kind }))
            .collect();
        AvpCatalog { by_name }
    }

    /// Parse and merge a single YAML dictionary document. Conflicting
    /// redefinitions of the same name fail the load, so a bad dictionary can
    /// never silently re-route an AVP.
    pub fn from_yaml(text: &str) -> Result<Self, CoreError> {
        AvpCatalog::from_yaml_documents([text])
    }

    /// Parse and merge **several** dictionary documents into one catalog
    /// (a directory of `*.yaml` files, say). Sections merge across documents
    /// exactly as they do within one; a name may repeat only with an identical
    /// definition, so split-by-interface files compose without surprises.
    pub fn from_yaml_documents<'a, I>(docs: I) -> Result<Self, CoreError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut by_name: HashMap<String, AvpDef> = HashMap::new();
        for text in docs {
            let doc: DictionaryDoc = serde_yaml::from_str(text)
                .map_err(|e| CoreError::Adapter(format!("dictionary YAML parse: {e}")))?;
            for (interface, section) in &doc.interfaces {
                for entry in &section.avps {
                    let def = AvpDef {
                        code: entry.code,
                        vendor: entry.vendor,
                        kind: entry.kind,
                    };
                    if let Some(existing) = by_name.get(&entry.name) {
                        if *existing != def {
                            return Err(CoreError::Adapter(format!(
                                "dictionary: {} redefined with a different definition in interface {interface}",
                                entry.name
                            )));
                        }
                        continue;
                    }
                    by_name.insert(entry.name.clone(), def);
                }
            }
        }
        if by_name.is_empty() {
            return Err(CoreError::Adapter("dictionary defines no AVPs".to_owned()));
        }
        Ok(AvpCatalog { by_name })
    }

    /// Resolve a rule-document AVP name.
    pub fn get(&self, name: &str) -> Option<&AvpDef> {
        self.by_name.get(name)
    }

    /// Number of definitions (diagnostics / startup log).
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the catalog is empty (never true for loaded catalogs).
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// Hot-swappable holder for the active [`AvpCatalog`], shared by the engine
/// (AVP extract/encode) and the [`crate::rule::RuleStore`] (rule validation).
///
/// Readers pay one atomic load; the admin API swaps a new dictionary in
/// atomically after re-validating the active rules against it, so a
/// dictionary that would orphan a live rule never becomes active. Mirrors the
/// `RuleStore`/`ArcSwap` pattern.
#[derive(Debug)]
pub struct CatalogStore {
    current: ArcSwap<AvpCatalog>,
}

impl Default for CatalogStore {
    fn default() -> Self {
        CatalogStore::new(AvpCatalog::builtin())
    }
}

impl CatalogStore {
    /// Holder seeded with `initial`.
    pub fn new(initial: AvpCatalog) -> Self {
        CatalogStore {
            current: ArcSwap::from_pointee(initial),
        }
    }

    /// Current snapshot (cheap; clone of an `Arc`).
    pub fn load(&self) -> Arc<AvpCatalog> {
        self.current.load_full()
    }

    /// Atomically activate `catalog`.
    pub fn store(&self, catalog: AvpCatalog) {
        self.current.store(Arc::new(catalog));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_covers_dsl_names() {
        let c = AvpCatalog::builtin();
        for name in [
            "User-Name",
            "Public-Identity",
            "Server-Name",
            "SIP-Auth-Data-Item",
            "User-Data",
            "MSISDN",
        ] {
            assert!(c.get(name).is_some(), "{name} missing from builtin catalog");
        }
        assert!(c.get("Not-An-AVP").is_none());
        assert!(c
            .get("Server-Assignment-Type")
            .is_some_and(|d| d.kind.is_integer()));
        assert!(c.get("User-Name").is_some_and(|d| !d.kind.is_integer()));
    }

    #[test]
    fn merges_multiple_documents() {
        // Split-by-interface files compose into one catalog.
        let cx = "interfaces: { cx: { avps: [ { name: Public-Identity, code: 601, vendor: 10415, type: UTF8String } ] } }";
        let rx = "interfaces: { rx: { avps: [ { name: Framed-IP-Address, code: 8, type: OctetString } ] } }";
        let c = AvpCatalog::from_yaml_documents([cx, rx]).expect("merge");
        assert_eq!(c.len(), 2);
        assert!(c.get("Public-Identity").is_some());
        assert!(c.get("Framed-IP-Address").is_some());

        // A name shared across files with an identical definition is fine…
        let dup_ok = "interfaces: { sh: { avps: [ { name: Public-Identity, code: 601, vendor: 10415, type: UTF8String } ] } }";
        assert!(AvpCatalog::from_yaml_documents([cx, dup_ok]).is_ok());
        // …but a conflicting redefinition across files is rejected.
        let conflict = "interfaces: { sh: { avps: [ { name: Public-Identity, code: 999, type: UTF8String } ] } }";
        assert!(AvpCatalog::from_yaml_documents([cx, conflict]).is_err());
    }

    #[test]
    fn catalog_store_hot_swaps() {
        let store = CatalogStore::new(AvpCatalog::builtin());
        assert!(store.load().get("User-Name").is_some());
        store.store(
            AvpCatalog::from_yaml(
                "interfaces: { x: { avps: [ { name: Only-This, code: 1, type: UTF8String } ] } }",
            )
            .expect("dict"),
        );
        assert!(store.load().get("Only-This").is_some());
        assert!(
            store.load().get("User-Name").is_none(),
            "replaced wholesale"
        );
    }

    #[test]
    fn loads_interface_sections_and_merges() {
        let c = AvpCatalog::from_yaml(
            r#"
interfaces:
  base:
    avps:
      - { name: User-Name, code: 1, type: UTF8String }
  cx:
    application: 16777216
    avps:
      - { name: User-Name, code: 1, type: UTF8String }     # identical dup OK
      - { name: Vendor-Thing, code: 9001, vendor: 4242, type: Enumerated }
"#,
        )
        .expect("parse");
        assert_eq!(c.len(), 2);
        let def = c.get("Vendor-Thing").expect("Vendor-Thing");
        assert_eq!((def.code, def.vendor), (9001, Some(4242)));
        assert!(def.kind.is_integer());
    }

    #[test]
    fn rejects_conflicting_redefinition() {
        let err = AvpCatalog::from_yaml(
            r#"
interfaces:
  cx:
    avps:
      - { name: User-Name, code: 1, type: UTF8String }
  sh:
    avps:
      - { name: User-Name, code: 2, type: UTF8String }
"#,
        )
        .expect_err("conflict");
        assert!(err.to_string().contains("User-Name"));
    }

    #[test]
    fn rejects_unknown_type_and_empty() {
        assert!(AvpCatalog::from_yaml(
            "interfaces: { cx: { avps: [ { name: X, code: 1, type: Float32 } ] } }",
        )
        .is_err());
        assert!(AvpCatalog::from_yaml("interfaces: {}").is_err());
    }

    #[test]
    fn shipped_dictionary_is_a_superset_of_builtin() {
        let shipped = AvpCatalog::from_yaml(include_str!("../../config/dictionary.yaml"))
            .expect("config/dictionary.yaml valid");
        let builtin = AvpCatalog::builtin();
        for (name, def) in &builtin.by_name {
            assert_eq!(
                shipped.get(name),
                Some(def),
                "{name} missing or different in shipped dictionary"
            );
        }
    }
}
