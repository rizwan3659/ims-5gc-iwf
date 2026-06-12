//! # iwf-benchmark
//!
//! Shared fixtures for the Criterion micro-benchmarks (`benches/codec.rs`)
//! and the TPS load generator (`src/bin/loadgen.rs`).

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use bytes::Bytes;
use iwf_diameter::avp::AvpValue;
use iwf_diameter::dictionary as dict;
use iwf_diameter::message::{Message, MessageBuilder};

/// A representative Cx UAR as produced by an I-CSCF: Session-Id,
/// Origin/Destination, User-Name (IMPI), Public-Identity (IMPU),
/// Visited-Network-Identifier-sized payload.
pub fn sample_uar(hop_by_hop: u32, end_to_end: u32) -> Message {
    MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
        .ids(hop_by_hop, end_to_end)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8(format!("icscf.ims.example.org;{hop_by_hop};{end_to_end}")),
        )
        .std(
            dict::AVP_ORIGIN_HOST,
            AvpValue::Utf8("icscf.ims.example.org".to_owned()),
        )
        .std(
            dict::AVP_ORIGIN_REALM,
            AvpValue::Utf8("ims.example.org".to_owned()),
        )
        .std(
            dict::AVP_DESTINATION_REALM,
            AvpValue::Utf8("epc.example.org".to_owned()),
        )
        .std(
            dict::AVP_AUTH_SESSION_STATE,
            AvpValue::U32(1), // NO_STATE_MAINTAINED
        )
        .std(
            dict::AVP_USER_NAME,
            AvpValue::Utf8("001011234567890@ims.mnc001.mcc001.3gppnetwork.org".to_owned()),
        )
        .tgpp(
            dict::AVP_PUBLIC_IDENTITY,
            AvpValue::Utf8("sip:+14155550100@ims.mnc001.mcc001.3gppnetwork.org".to_owned()),
        )
        .build()
}

/// The same UAR pre-encoded to wire form.
pub fn sample_uar_wire() -> Bytes {
    sample_uar(0x1234_5678, 0x9ABC_DEF0).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_round_trips() {
        let wire = sample_uar_wire();
        let decoded = Message::decode(wire).expect("decode");
        assert_eq!(decoded.header.command, dict::CMD_UAR);
        assert_eq!(decoded.avps.len(), 7);
    }
}
