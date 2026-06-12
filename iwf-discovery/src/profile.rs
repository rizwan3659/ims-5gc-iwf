//! NFProfile structures (TS 29.510 §6.1.6.2.2 `NFProfile`), reduced to the
//! attributes the IWF reads and writes.

use serde::{Deserialize, Serialize};

/// An IP endpoint of an NF service (TS 29.510 §6.1.6.2.5 `IpEndPoint`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IpEndPoint {
    /// IPv4 address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,
    /// IPv6 address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,
    /// Port (defaults to the scheme default when absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// NF service entry (TS 29.510 §6.1.6.2.3 `NFService`, subset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NfService {
    /// Service instance id.
    pub service_instance_id: String,
    /// Service name (e.g. `nudm-uecm`).
    pub service_name: String,
    /// Scheme (`http` / `https`).
    pub scheme: String,
    /// API prefix including authority, e.g. `http://udm-1.5gc:8080`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_prefix: Option<String>,
    /// Explicit IP endpoints. Real cores (Open5GS) advertise the address
    /// here rather than via `apiPrefix`, so resolution must consult both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_end_points: Vec<IpEndPoint>,
    /// Relative priority (lower preferred).
    #[serde(default)]
    pub priority: u16,
    /// Relative capacity (load-balancing weight).
    #[serde(default = "default_capacity")]
    pub capacity: u16,
}

impl NfService {
    /// Build the base URI (`scheme://host:port`) this service is reachable
    /// at, preferring `apiPrefix`, then the first IP endpoint. Returns
    /// `None` when the service advertises no usable address.
    pub fn base_uri(&self) -> Option<String> {
        if let Some(prefix) = &self.api_prefix {
            return Some(prefix.clone());
        }
        let ep = self.ip_end_points.first()?;
        let host = ep
            .ipv4_address
            .clone()
            .or_else(|| ep.ipv6_address.as_ref().map(|a| format!("[{a}]")))?;
        let scheme = if self.scheme.is_empty() {
            "http"
        } else {
            &self.scheme
        };
        let port = ep.port.unwrap_or(if scheme == "https" { 443 } else { 80 });
        Some(format!("{scheme}://{host}:{port}"))
    }
}

fn default_capacity() -> u16 {
    100
}

/// NF profile (TS 29.510 §6.1.6.2.2, subset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NfProfile {
    /// NF instance UUID.
    pub nf_instance_id: String,
    /// NF type string. The IWF registers as the custom type `IWF`
    /// (TS 29.510 allows custom NFTypes as string).
    pub nf_type: String,
    /// `REGISTERED` / `SUSPENDED` / `UNDISCOVERABLE`.
    pub nf_status: String,
    /// Heartbeat interval granted by the NRF, seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heart_beat_timer: Option<u32>,
    /// FQDN of this instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    /// IPv4 addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv4_addresses: Vec<String>,
    /// Exposed services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nf_services: Vec<NfService>,
    /// Capability advertisement: which Diameter applications this IWF
    /// translates (custom vendor extension, namespaced key).
    #[serde(
        rename = "customInfo",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub custom_info: Option<serde_json::Value>,
}

impl NfProfile {
    /// Profile for this IWF instance with its interworking capabilities
    /// advertised in `customInfo`.
    pub fn for_iwf(instance_id: String, fqdn: String) -> Self {
        NfProfile {
            nf_instance_id: instance_id,
            nf_type: "IWF".to_owned(),
            nf_status: "REGISTERED".to_owned(),
            heart_beat_timer: None,
            fqdn: Some(fqdn),
            ipv4_addresses: Vec::new(),
            nf_services: Vec::new(),
            custom_info: Some(serde_json::json!({
                "iwfCapabilities": {
                    "diameterApplications": ["Cx", "Dx", "Sh", "SWx", "Zh"],
                    "sbiConsumes": ["nudm-uecm", "nudm-sdm", "nausf-auth",
                                     "namf-comm", "nudr-dr"],
                }
            })),
        }
    }
}

/// Discovery result (TS 29.510 §6.2.6.2.2 `SearchResult`, subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    /// How long the result may be cached, seconds (`validityPeriod`).
    pub validity_period: u64,
    /// Matching NF instances.
    pub nf_instances: Vec<NfProfile>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_serializes_camel_case() {
        let p = NfProfile::for_iwf("uuid-1".to_owned(), "iwf-0.example.org".to_owned());
        let json = serde_json::to_value(&p).expect("serialize");
        assert_eq!(json["nfInstanceId"], "uuid-1");
        assert_eq!(json["nfType"], "IWF");
        assert_eq!(json["nfStatus"], "REGISTERED");
        assert!(
            json["customInfo"]["iwfCapabilities"]["diameterApplications"]
                .as_array()
                .expect("array")
                .iter()
                .any(|v| v == "Cx")
        );
    }

    #[test]
    fn search_result_round_trip() {
        let raw = serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [{
                "nfInstanceId": "udm-1",
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "nfServices": [{
                    "serviceInstanceId": "s1",
                    "serviceName": "nudm-uecm",
                    "scheme": "http",
                    "apiPrefix": "http://udm-1.5gc:8080",
                    "priority": 1,
                    "capacity": 50
                }]
            }]
        });
        let result: SearchResult = serde_json::from_value(raw).expect("parse");
        assert_eq!(result.validity_period, 3600);
        assert_eq!(result.nf_instances[0].nf_services[0].capacity, 50);
    }

    #[test]
    fn base_uri_prefers_api_prefix() {
        let svc: NfService = serde_json::from_value(serde_json::json!({
            "serviceInstanceId": "s1", "serviceName": "nudm-sdm", "scheme": "https",
            "apiPrefix": "https://udm.5gc:8443",
            "ipEndPoints": [{"ipv4Address": "10.0.0.1", "port": 7777}]
        }))
        .expect("parse");
        assert_eq!(svc.base_uri().as_deref(), Some("https://udm.5gc:8443"));
    }

    #[test]
    fn base_uri_falls_back_to_ip_endpoint() {
        // Open5GS shape: no apiPrefix, address in ipEndPoints.
        let svc: NfService = serde_json::from_value(serde_json::json!({
            "serviceInstanceId": "s1", "serviceName": "nudm-sdm", "scheme": "http",
            "ipEndPoints": [{"ipv4Address": "127.0.0.12", "port": 7777}]
        }))
        .expect("parse");
        assert_eq!(svc.base_uri().as_deref(), Some("http://127.0.0.12:7777"));
    }

    #[test]
    fn base_uri_none_without_address() {
        let svc: NfService = serde_json::from_value(serde_json::json!({
            "serviceInstanceId": "s1", "serviceName": "nudm-sdm", "scheme": "http"
        }))
        .expect("parse");
        assert_eq!(svc.base_uri(), None);
    }
}
