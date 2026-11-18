//! The wire format: round trips, and the appended-field convention for later versions.

use citadel_negotiation::frame::{appended_field, decode, encode};
use citadel_negotiation::{
    ApplyEvidence, CapabilityBits, Envelope, Epoch, Frame, Hello, PeerSupport, RejectReason,
    RenegotiationReason, SettingId,
};
use serde::{Deserialize, Serialize};

fn every_frame() -> Vec<Frame> {
    let evidence = ApplyEvidence {
        version: Some(7),
        digest: [9; 32],
    };
    vec![
        Frame::Propose {
            from_epoch: Epoch(3),
            seq: 1,
            value: vec![1, 2],
        },
        Frame::Accept {
            from_epoch: Epoch(3),
            seq: 1,
            agreed: vec![1, 2],
        },
        Frame::Reject {
            from_epoch: Epoch(3),
            seq: 1,
            reason: RejectReason::Crossed,
        },
        Frame::Applied {
            epoch: Epoch(4),
            evidence,
        },
        Frame::Applied {
            epoch: Epoch(4),
            evidence: ApplyEvidence {
                version: None,
                digest: [0; 32],
            },
        },
        Frame::Retire { epoch: Epoch(3) },
        Frame::Cancel {
            from_epoch: Epoch(3),
            seq: 1,
        },
        Frame::Renegotiate {
            reason: RenegotiationReason::HandshakeRequired(SettingId::KEY_PROFILE),
            next: vec![5],
        },
    ]
}

/// What a later version of the envelope could look like: one field appended at the end.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct EnvelopeV2 {
    setting: SettingId,
    n: u64,
    frame: Frame,
    #[serde(default, deserialize_with = "appended_field")]
    route_hint: Option<u32>,
}

#[test]
fn frames_round_trip_and_appended_fields() {
    for (n, frame) in every_frame().into_iter().enumerate() {
        let envelope = Envelope {
            setting: SettingId::MEDIA_TRANSPORT,
            n: n as u64,
            frame,
        };
        let bytes = encode(&envelope).expect("encode");
        assert_eq!(decode::<Envelope>(&bytes).expect("decode"), envelope);

        // A v1 reader reads a v2 envelope and drops the appended field.
        let v2 = EnvelopeV2 {
            setting: envelope.setting,
            n: envelope.n,
            frame: envelope.frame.clone(),
            route_hint: Some(42),
        };
        let v2_bytes = encode(&v2).expect("encode v2");
        assert_eq!(
            decode::<Envelope>(&v2_bytes).expect("v1 reads v2"),
            envelope
        );

        // A v2 reader reads a v1 envelope; the field it does not carry is None.
        let read = decode::<EnvelopeV2>(&bytes).expect("v2 reads v1");
        assert_eq!(read.route_hint, None);
        assert_eq!(read.frame, envelope.frame);
    }
}

#[test]
fn hello_names_what_the_peer_negotiates_in_band() {
    let hello = Hello {
        protocol: 3,
        settings: vec![
            (SettingId::KEY_PROFILE, CapabilityBits::IN_BAND),
            (SettingId::TRANSFER_MODE, CapabilityBits(0)),
        ],
    };
    let read = decode::<Hello>(&encode(&hello).expect("encode")).expect("decode");
    assert_eq!(read, hello);
    assert_eq!(
        read.support_for(SettingId::KEY_PROFILE),
        PeerSupport::InBand
    );
    assert_eq!(
        read.support_for(SettingId::TRANSFER_MODE),
        PeerSupport::Legacy
    );
    assert_eq!(
        read.support_for(SettingId::MEDIA_TRANSPORT),
        PeerSupport::Legacy
    );
}
