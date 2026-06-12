//! Property tests: AVP and message codec round-trip, and decoder robustness
//! against arbitrary input (must never panic, only return errors).

use bytes::{Bytes, BytesMut};
use proptest::prelude::*;

use iwf_diameter::avp::{avp, avp_3gpp, Avp, AvpValue};
use iwf_diameter::message::{Message, MessageBuilder};

fn arb_value() -> impl Strategy<Value = AvpValue> {
    prop_oneof![
        "[a-zA-Z0-9@.:;-]{0,64}".prop_map(AvpValue::Utf8),
        any::<u32>().prop_map(AvpValue::U32),
        any::<u64>().prop_map(AvpValue::U64),
        proptest::collection::vec(any::<u8>(), 0..256)
            .prop_map(|v| AvpValue::Octets(Bytes::from(v))),
    ]
}

fn arb_avp() -> impl Strategy<Value = Avp> {
    (1u32..=1000, arb_value(), any::<bool>()).prop_map(|(code, value, vendor)| {
        if vendor {
            avp_3gpp(code, value)
        } else {
            avp(code, value)
        }
    })
}

proptest! {
    #[test]
    fn avp_round_trip(original in arb_avp()) {
        let mut buf = BytesMut::new();
        original.encode_into(&mut buf);
        let frozen = buf.freeze();
        let (decoded, consumed) = Avp::decode_at(&frozen, 0).expect("decode");
        prop_assert_eq!(consumed, frozen.len());
        prop_assert_eq!(decoded.code, original.code);
        prop_assert_eq!(decoded.flags.0, original.flags.0);
        prop_assert_eq!(decoded.vendor_id, original.vendor_id);
        prop_assert_eq!(decoded.data.as_ref(), original.data.as_ref());
    }

    #[test]
    fn message_round_trip(
        command in 257u32..=320,
        application in prop_oneof![Just(0u32), Just(16_777_216), Just(16_777_217)],
        hbh in any::<u32>(),
        e2e in any::<u32>(),
        avps in proptest::collection::vec(arb_avp(), 0..16),
    ) {
        let mut b = MessageBuilder::request(command, application).ids(hbh, e2e);
        for a in &avps {
            b = b.avp(a.clone());
        }
        let msg = b.build();
        let wire = msg.encode();
        prop_assert_eq!(wire.len() % 4, 0);
        let decoded = Message::decode(wire).expect("decode");
        prop_assert_eq!(decoded.header, msg.header);
        prop_assert_eq!(decoded.avps.len(), msg.avps.len());
        for (d, o) in decoded.avps.iter().zip(msg.avps.iter()) {
            prop_assert_eq!(d.code, o.code);
            prop_assert_eq!(d.data.as_ref(), o.data.as_ref());
        }
    }

    /// Fuzz the decoder: arbitrary bytes must yield Ok or Err, never panic.
    #[test]
    fn decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = Message::decode(Bytes::from(data));
    }

    /// Fuzz with a structurally plausible header so the AVP walker runs.
    #[test]
    fn avp_walker_never_panics(mut data in proptest::collection::vec(any::<u8>(), 20..512)) {
        data[0] = 1; // version
        let len = data.len();
        data[1] = ((len >> 16) & 0xFF) as u8;
        data[2] = ((len >> 8) & 0xFF) as u8;
        data[3] = (len & 0xFF) as u8;
        let _ = Message::decode(Bytes::from(data));
    }
}
