//! Known-answer tests: RFC 5769 test vectors for MESSAGE-INTEGRITY and FINGERPRINT, plus the TURN
//! attribute and ChannelData encodings.

use super::*;
use stun::integrity::MessageIntegrity;
use stun::message::Getter;
use stun::xoraddr::XorMappedAddress;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const SHORT_TERM_PASSWORD: &str = "VOkJxbRl1RmTxUk/WvJxBt";

/// RFC 5769 §2.1 Sample Request.
fn rfc5769_request() -> Vec<u8> {
    hex("00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
         80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74
         00 24 00 04 6e 00 01 ff 80 29 00 08 93 2f f9 b1 51 26 3b 36
         00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20
         00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2
         80 28 00 04 e5 7a 3b cf")
}

/// RFC 5769 §2.2 Sample IPv4 Response.
fn rfc5769_ipv4_response() -> Vec<u8> {
    hex("01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
         80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
         00 20 00 08 00 01 a1 47 e1 12 a6 43
         00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7
         80 28 00 04 c0 7d 4c 96")
}

/// RFC 5769 §2.3 Sample IPv6 Response.
fn rfc5769_ipv6_response() -> Vec<u8> {
    hex("01 01 00 48 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
         80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
         00 20 00 14 00 02 a1 47 01 13 a9 fa a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9
         00 08 00 14 a3 82 95 4e 4b e6 7b f1 17 84 c9 7c 82 92 c2 75 bf e3 ed 41
         80 28 00 04 c8 fb 0b 4c")
}

/// RFC 5769 §2.4 Sample Request with Long-Term Authentication.
fn rfc5769_long_term_request() -> Vec<u8> {
    hex("00 01 00 60 21 12 a4 42 78 ad 34 33 c6 ad 72 c0 29 da 41 2e
         00 06 00 12 e3 83 9e e3 83 88 e3 83 aa e3 83 83 e3 82 af e3 82 b9 00 00
         00 15 00 1c 66 2f 2f 34 39 39 6b 39 35 34 64 36 4f 4c 33 34 6f 4c 39 46
                     53 54 76 79 36 34 73 41
         00 14 00 0b 65 78 61 6d 70 6c 65 2e 6f 72 67 00
         00 08 00 14 f6 70 24 65 6d d6 4a 3e 02 b8 e0 71 2e 85 c9 a2 8c a8 96 66")
}

const LT_USERNAME: &str = "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}";
const LT_PASSWORD: &str = "TheMatrIX";
const LT_REALM: &str = "example.org";
const LT_NONCE: &str = "f//499k954d6OL34oL9FSTvy64sA";

fn short_term_check(bytes: &[u8], password: &str) -> bool {
    let mut m = parse(bytes).unwrap();
    MessageIntegrity::new_short_term_integrity(password.to_string())
        .check(&mut m)
        .is_ok()
}

#[test]
fn rfc5769_integrity_and_fingerprint_verify() {
    for vector in [
        rfc5769_request(),
        rfc5769_ipv4_response(),
        rfc5769_ipv6_response(),
    ] {
        assert!(short_term_check(&vector, SHORT_TERM_PASSWORD));
        assert!(!short_term_check(&vector, "wrong password"));
        assert!(check_fingerprint_if_present(&parse(&vector).unwrap()).is_ok());
    }
}

#[test]
fn rfc5769_corruption_breaks_integrity_and_fingerprint() {
    let mut v = rfc5769_request();
    v[30] ^= 0x01; // inside SOFTWARE, covered by both
    assert!(!short_term_check(&v, SHORT_TERM_PASSWORD));
    assert!(check_fingerprint_if_present(&parse(&v).unwrap()).is_err());
}

#[test]
fn rfc5769_xor_mapped_addresses_decode() {
    let v4 = parse(&rfc5769_ipv4_response()).unwrap();
    assert_eq!(
        xor_address(&v4, ATTR_XORMAPPED_ADDRESS),
        Some("192.0.2.1:32853".parse().unwrap())
    );
    let v6 = parse(&rfc5769_ipv6_response()).unwrap();
    assert_eq!(
        xor_address(&v6, ATTR_XORMAPPED_ADDRESS),
        Some(
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                .parse()
                .unwrap()
        )
    );
}

#[test]
fn rfc5769_long_term_request_is_reproduced_byte_for_byte() {
    let auth = LongTermAuth::new(
        LT_USERNAME,
        LT_PASSWORD,
        LT_REALM.to_string(),
        LT_NONCE.to_string(),
    );
    let tid = TransactionId(
        rfc5769_long_term_request()[8..20]
            .try_into()
            .expect("12-byte transaction id"),
    );
    let built = build(METHOD_BINDING, CLASS_REQUEST, tid, &[], Some(&auth), false).unwrap();
    assert_eq!(built.raw, rfc5769_long_term_request());

    let mut parsed = parse(&rfc5769_long_term_request()).unwrap();
    assert!(auth.verify(&mut parsed).is_ok());
    let wrong = LongTermAuth::new(LT_USERNAME, "TheMatrIx", LT_REALM.into(), LT_NONCE.into());
    assert!(wrong.verify(&mut parsed).is_err());
    assert_eq!(text(&parsed, ATTR_REALM).as_deref(), Some(LT_REALM));
    assert_eq!(text(&parsed, ATTR_NONCE).as_deref(), Some(LT_NONCE));
}

#[test]
fn built_messages_carry_a_valid_fingerprint_after_integrity() {
    let auth = LongTermAuth::new("user", "pass", "realm".into(), "nonce".into());
    let peer: SocketAddr = "203.0.113.9:4000".parse().unwrap();
    let m = build(
        METHOD_CHANNEL_BIND,
        CLASS_REQUEST,
        TransactionId::new(),
        &[Attr::ChannelNumber(0x4001), Attr::XorPeerAddress(peer)],
        Some(&auth),
        true,
    )
    .unwrap();
    let mut parsed = parse(&m.raw).unwrap();
    assert!(parsed.contains(ATTR_FINGERPRINT));
    assert!(check_fingerprint_if_present(&parsed).is_ok());
    assert!(auth.verify(&mut parsed).is_ok());
    assert_eq!(xor_address(&parsed, ATTR_XOR_PEER_ADDRESS), Some(peer));
    assert_eq!(
        parsed.get(ATTR_CHANNEL_NUMBER).unwrap(),
        vec![0x40, 0x01, 0, 0]
    );
}

#[test]
fn turn_attributes_encode_per_rfc8656() {
    let m = build(
        METHOD_ALLOCATE,
        CLASS_REQUEST,
        TransactionId::new(),
        &[
            Attr::RequestedTransportUdp,
            Attr::Lifetime(Duration::from_secs(600)),
            Attr::Data(vec![1, 2, 3]),
        ],
        None,
        false,
    )
    .unwrap();
    assert_eq!(&m.raw[0..2], &[0x00, 0x03]); // Allocate request
    let parsed = parse(&m.raw).unwrap();
    assert_eq!(
        parsed.get(ATTR_REQUESTED_TRANSPORT).unwrap(),
        vec![17, 0, 0, 0]
    );
    assert_eq!(lifetime(&parsed), Some(Duration::from_secs(600)));
    assert_eq!(data(&parsed), Some(vec![1, 2, 3]));
    let mut x = XorMappedAddress::default();
    assert!(x.get_from(&parsed).is_err());
}

#[test]
fn channel_data_round_trips_with_and_without_stream_padding() {
    let udp = encode_channel_data(0x4000, &[9, 8, 7, 6, 5], false).unwrap();
    assert_eq!(udp, vec![0x40, 0x00, 0x00, 0x05, 9, 8, 7, 6, 5]);
    let tcp = encode_channel_data(0x4000, &[9, 8, 7, 6, 5], true).unwrap();
    assert_eq!(tcp.len(), 12);
    assert_eq!(stream_frame_len(tcp[..4].try_into().unwrap()).unwrap(), 12);
    for frame in [&udp[..], &tcp[..]] {
        match classify(frame).unwrap() {
            Inbound::ChannelData { channel, payload } => {
                assert_eq!((channel, payload), (0x4000, &[9, 8, 7, 6, 5][..]))
            }
            Inbound::Stun => panic!("ChannelData classified as STUN"),
        }
    }
    let stun = rfc5769_request();
    assert!(matches!(classify(&stun).unwrap(), Inbound::Stun));
    assert_eq!(
        stream_frame_len(stun[..4].try_into().unwrap()).unwrap(),
        stun.len()
    );
    assert!(classify(&[0x40, 0x00, 0x00, 0x09, 1]).is_err());
    assert!(classify(&[0x80]).is_err());
}
