//! Base-protocol message construction and validation:
//! CER/CEA (RFC 6733 §5.3), DWR/DWA (§5.5), DPR/DPA (§5.4).

use crate::avp::AvpValue;
use crate::dictionary as dict;
use crate::error::DiameterError;
use crate::message::{Message, MessageBuilder};

/// Local node identity advertised during capabilities exchange.
#[derive(Debug, Clone)]
pub struct LocalIdentity {
    /// DiameterIdentity of this node (FQDN), e.g. `iwf-0.epc.example.org`.
    pub origin_host: String,
    /// Realm of this node.
    pub origin_realm: String,
    /// Product-Name advertised in CER/CEA.
    pub product_name: String,
    /// Vendor-Id advertised in CER/CEA.
    pub vendor_id: u32,
    /// Auth applications supported (advertised as
    /// Vendor-Specific-Application-Id groups for 3GPP apps).
    pub applications: Vec<u32>,
    /// Origin-State-Id: increments on restart so peers detect reboots.
    pub origin_state_id: u32,
}

impl LocalIdentity {
    fn common(&self, builder: MessageBuilder) -> MessageBuilder {
        builder
            .std(
                dict::AVP_ORIGIN_HOST,
                AvpValue::Utf8(self.origin_host.clone()),
            )
            .std(
                dict::AVP_ORIGIN_REALM,
                AvpValue::Utf8(self.origin_realm.clone()),
            )
    }

    /// Build a Capabilities-Exchange-Request (RFC 6733 §5.3.1).
    pub fn build_cer(&self, hop_by_hop: u32, end_to_end: u32) -> Message {
        let mut b = self
            .common(MessageBuilder::request(dict::CMD_CER, dict::APP_BASE))
            .ids(hop_by_hop, end_to_end)
            .std(dict::AVP_VENDOR_ID, AvpValue::U32(self.vendor_id))
            .std(
                dict::AVP_PRODUCT_NAME,
                AvpValue::Utf8(self.product_name.clone()),
            )
            .std(
                dict::AVP_SUPPORTED_VENDOR_ID,
                AvpValue::U32(dict::VENDOR_3GPP),
            )
            .std(
                dict::AVP_ORIGIN_STATE_ID,
                AvpValue::U32(self.origin_state_id),
            );
        for app in &self.applications {
            b = b.std(
                dict::AVP_VENDOR_SPECIFIC_APP_ID,
                AvpValue::Grouped(vec![
                    crate::avp::avp(dict::AVP_VENDOR_ID, AvpValue::U32(dict::VENDOR_3GPP)),
                    crate::avp::avp(dict::AVP_AUTH_APPLICATION_ID, AvpValue::U32(*app)),
                ]),
            );
        }
        // CER carries no Request flag proxiable semantics (P bit MUST be 0).
        let mut msg = b.build();
        msg.header.flags.0 &= !crate::message::CommandFlags::PROXIABLE;
        msg
    }

    /// Build the Capabilities-Exchange-Answer to `cer` (RFC 6733 §5.3.2).
    pub fn build_cea(&self, cer: &Message, result_code: u32) -> Message {
        let mut b = MessageBuilder::answer_to(&cer.header)
            .std(dict::AVP_RESULT_CODE, AvpValue::U32(result_code));
        b = self.common(b);
        let mut msg = b
            .std(dict::AVP_VENDOR_ID, AvpValue::U32(self.vendor_id))
            .std(
                dict::AVP_PRODUCT_NAME,
                AvpValue::Utf8(self.product_name.clone()),
            )
            .std(
                dict::AVP_ORIGIN_STATE_ID,
                AvpValue::U32(self.origin_state_id),
            )
            .build();
        msg.header.flags.0 &= !crate::message::CommandFlags::PROXIABLE;
        msg
    }

    /// Build a Device-Watchdog-Request (RFC 6733 §5.5.1).
    pub fn build_dwr(&self, hop_by_hop: u32, end_to_end: u32) -> Message {
        let mut msg = self
            .common(MessageBuilder::request(dict::CMD_DWR, dict::APP_BASE))
            .ids(hop_by_hop, end_to_end)
            .std(
                dict::AVP_ORIGIN_STATE_ID,
                AvpValue::U32(self.origin_state_id),
            )
            .build();
        msg.header.flags.0 &= !crate::message::CommandFlags::PROXIABLE;
        msg
    }

    /// Build the Device-Watchdog-Answer to `dwr` (RFC 6733 §5.5.2).
    pub fn build_dwa(&self, dwr: &Message) -> Message {
        let b = MessageBuilder::answer_to(&dwr.header)
            .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS));
        self.common(b)
            .std(
                dict::AVP_ORIGIN_STATE_ID,
                AvpValue::U32(self.origin_state_id),
            )
            .build()
    }

    /// Build a Disconnect-Peer-Request (RFC 6733 §5.4.1).
    pub fn build_dpr(&self, cause: u32, hop_by_hop: u32, end_to_end: u32) -> Message {
        self.common(MessageBuilder::request(dict::CMD_DPR, dict::APP_BASE))
            .ids(hop_by_hop, end_to_end)
            .std(dict::AVP_DISCONNECT_CAUSE, AvpValue::U32(cause))
            .build()
    }

    /// Build the Disconnect-Peer-Answer to `dpr` (RFC 6733 §5.4.2).
    pub fn build_dpa(&self, dpr: &Message) -> Message {
        let b = MessageBuilder::answer_to(&dpr.header)
            .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS));
        self.common(b).build()
    }
}

/// Capabilities extracted from a peer's CER/CEA.
#[derive(Debug, Clone)]
pub struct PeerCapabilities {
    /// Peer's Origin-Host.
    pub origin_host: String,
    /// Peer's Origin-Realm.
    pub origin_realm: String,
    /// Auth Application-Ids the peer advertised (plain + vendor-specific).
    pub applications: Vec<u32>,
}

/// Validate and extract capabilities from a CER or CEA per RFC 6733 §5.3:
/// Origin-Host and Origin-Realm are mandatory; at least one common
/// application must exist (checked by the caller against local apps).
pub fn parse_capabilities(msg: &Message) -> Result<PeerCapabilities, DiameterError> {
    let origin_host = msg
        .find(dict::AVP_ORIGIN_HOST, None)
        .ok_or(DiameterError::MissingAvp("Origin-Host"))?
        .as_utf8()?
        .to_owned();
    let origin_realm = msg
        .find(dict::AVP_ORIGIN_REALM, None)
        .ok_or(DiameterError::MissingAvp("Origin-Realm"))?
        .as_utf8()?
        .to_owned();

    let mut applications = Vec::new();
    for a in msg.find_all(dict::AVP_AUTH_APPLICATION_ID, None) {
        applications.push(a.as_u32()?);
    }
    for group in msg.find_all(dict::AVP_VENDOR_SPECIFIC_APP_ID, None) {
        for member in group.as_grouped()? {
            if member.code == dict::AVP_AUTH_APPLICATION_ID && member.vendor_id.is_none() {
                applications.push(member.as_u32()?);
            }
        }
    }

    Ok(PeerCapabilities {
        origin_host,
        origin_realm,
        applications,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> LocalIdentity {
        LocalIdentity {
            origin_host: "iwf-0.epc.example.org".to_owned(),
            origin_realm: "epc.example.org".to_owned(),
            product_name: "iwf".to_owned(),
            vendor_id: 99999,
            applications: vec![dict::APP_CX, dict::APP_SH],
            origin_state_id: 7,
        }
    }

    #[test]
    fn cer_round_trip_capabilities() {
        let cer = local().build_cer(1, 2);
        let decoded = crate::message::Message::decode(cer.encode()).expect("decode");
        let caps = parse_capabilities(&decoded).expect("caps");
        assert_eq!(caps.origin_host, "iwf-0.epc.example.org");
        assert_eq!(caps.origin_realm, "epc.example.org");
        assert!(caps.applications.contains(&dict::APP_CX));
        assert!(caps.applications.contains(&dict::APP_SH));
        assert!(!decoded.header.flags.0 & crate::message::CommandFlags::PROXIABLE != 0);
    }

    #[test]
    fn dwa_answers_dwr() {
        let me = local();
        let dwr = me.build_dwr(0xAA, 0xBB);
        let dwa = me.build_dwa(&dwr);
        assert_eq!(dwa.header.hop_by_hop, 0xAA);
        assert_eq!(dwa.header.command, dict::CMD_DWR);
        assert!(!dwa.header.flags.request());
        assert_eq!(dwa.result_code(), Some(dict::RC_SUCCESS));
    }

    #[test]
    fn capabilities_require_origin_host() {
        let msg = MessageBuilder::request(dict::CMD_CER, dict::APP_BASE).build();
        assert!(matches!(
            parse_capabilities(&msg),
            Err(DiameterError::MissingAvp("Origin-Host"))
        ));
    }
}
