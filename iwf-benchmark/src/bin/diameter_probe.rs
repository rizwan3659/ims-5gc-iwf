//! One-shot Diameter probe: opens a connection to the IWF, performs CER/CEA,
//! then sends one of each IMS command — UAR, LIR, MAR (Cx) and UDR, PUR, SNR
//! (Sh) — reading each answer. Used to generate a capturable, inspectable
//! exchange (e.g. under `tcpdump`/Wireshark) for the Cx/Sh flows.
//!
//! Usage: `diameter_probe [host:port]` (default `127.0.0.1:3868`).

#![deny(warnings)]
#![forbid(unsafe_code)]

use iwf_diameter::avp::AvpValue;
use iwf_diameter::base::LocalIdentity;
use iwf_diameter::dictionary as dict;
use iwf_diameter::message::{Message, MessageBuilder};
use iwf_diameter::transport::{read_frame, write_frame, DEFAULT_MAX_FRAME};
use tokio::net::TcpStream;

const REALM: &str = "ims.example.org";
const HOST: &str = "icscf.ims.example.org";
const IMPI: &str = "alice@ims.example.org";
const IMPU: &str = "sip:alice@ims.example.org";

fn common(b: MessageBuilder, hbh: u32, app: u32) -> MessageBuilder {
    let _ = app;
    b.ids(hbh, hbh)
        .std(
            dict::AVP_SESSION_ID,
            AvpValue::Utf8(format!("{HOST};{hbh};1")),
        )
        .std(dict::AVP_ORIGIN_HOST, AvpValue::Utf8(HOST.to_owned()))
        .std(dict::AVP_ORIGIN_REALM, AvpValue::Utf8(REALM.to_owned()))
        .std(
            dict::AVP_DESTINATION_REALM,
            AvpValue::Utf8("epc.example.org".to_owned()),
        )
}

fn disposition(answer: &Message) -> String {
    match answer.result_code() {
        Some(rc) => format!("Result-Code {rc}"),
        None => match answer
            .find(dict::AVP_EXPERIMENTAL_RESULT, None)
            .and_then(|a| a.as_grouped().ok())
        {
            Some(group) => {
                let code = group
                    .iter()
                    .find(|a| a.code == dict::AVP_EXPERIMENTAL_RESULT_CODE)
                    .and_then(|a| a.as_u32().ok());
                format!("Experimental-Result {code:?}")
            }
            None => "no result".to_owned(),
        },
    }
}

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:3868".to_owned());
    let stream = TcpStream::connect(&target).await.expect("connect");
    let (mut reader, mut writer) = stream.into_split();

    let local = LocalIdentity {
        origin_host: HOST.to_owned(),
        origin_realm: REALM.to_owned(),
        product_name: "diameter-probe".to_owned(),
        vendor_id: dict::VENDOR_3GPP,
        applications: vec![dict::APP_CX, dict::APP_SH],
        origin_state_id: 1,
    };
    write_frame(&mut writer, &local.build_cer(1, 1))
        .await
        .expect("CER");
    let cea = read_frame(&mut reader, DEFAULT_MAX_FRAME)
        .await
        .expect("read")
        .expect("CEA");
    let cea = Message::decode(cea).expect("decode CEA");
    println!("CER/CEA            -> {}", disposition(&cea));

    // (label, command, application, builder)
    let messages: Vec<(&str, Message)> = vec![
        (
            "Cx UAR",
            common(
                MessageBuilder::request(dict::CMD_UAR, dict::APP_CX),
                10,
                dict::APP_CX,
            )
            .std(dict::AVP_USER_NAME, AvpValue::Utf8(IMPI.to_owned()))
            .tgpp(dict::AVP_PUBLIC_IDENTITY, AvpValue::Utf8(IMPU.to_owned()))
            .build(),
        ),
        (
            "Cx LIR",
            common(
                MessageBuilder::request(dict::CMD_LIR, dict::APP_CX),
                11,
                dict::APP_CX,
            )
            .tgpp(dict::AVP_PUBLIC_IDENTITY, AvpValue::Utf8(IMPU.to_owned()))
            .build(),
        ),
        (
            "Cx MAR",
            common(
                MessageBuilder::request(dict::CMD_MAR, dict::APP_CX),
                12,
                dict::APP_CX,
            )
            .std(dict::AVP_USER_NAME, AvpValue::Utf8(IMPI.to_owned()))
            .build(),
        ),
        (
            "Sh UDR",
            common(
                MessageBuilder::request(dict::CMD_UDR, dict::APP_SH),
                13,
                dict::APP_SH,
            )
            .std(dict::AVP_USER_NAME, AvpValue::Utf8(IMPI.to_owned()))
            .tgpp(
                dict::AVP_DATA_REFERENCE,
                AvpValue::Enum(dict::data_reference::SCSCF_NAME),
            )
            .build(),
        ),
        (
            "Sh PUR",
            common(
                MessageBuilder::request(dict::CMD_PUR, dict::APP_SH),
                14,
                dict::APP_SH,
            )
            .std(dict::AVP_USER_NAME, AvpValue::Utf8(IMPI.to_owned()))
            .tgpp(
                dict::AVP_USER_DATA,
                AvpValue::Utf8("<repository-data/>".to_owned()),
            )
            .build(),
        ),
        (
            "Sh SNR",
            common(
                MessageBuilder::request(dict::CMD_SNR, dict::APP_SH),
                15,
                dict::APP_SH,
            )
            .tgpp(dict::AVP_PUBLIC_IDENTITY, AvpValue::Utf8(IMPU.to_owned()))
            .build(),
        ),
    ];

    for (label, request) in messages {
        write_frame(&mut writer, &request).await.expect("send");
        let frame = read_frame(&mut reader, DEFAULT_MAX_FRAME)
            .await
            .expect("read")
            .expect("answer");
        let answer = Message::decode(frame).expect("decode");
        println!("{label:<18} -> {}", disposition(&answer));
    }

    // Polite teardown so the capture shows a clean DPR/DPA + FIN.
    write_frame(
        &mut writer,
        &local.build_dpr(dict::disconnect_cause::REBOOTING, 99, 99),
    )
    .await
    .expect("DPR");
    let _ = read_frame(&mut reader, DEFAULT_MAX_FRAME).await;
    println!("DPR/DPA            -> sent");
}
