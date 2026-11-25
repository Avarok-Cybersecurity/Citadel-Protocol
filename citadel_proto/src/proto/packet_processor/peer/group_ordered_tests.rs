use super::*;
use citadel_types::crypto::SecBuffer;
use citadel_types::proto::{GroupMessageId, MemberState};

const KEY: MessageGroupKey = MessageGroupKey { cid: 7, mgid: 9 };

fn at(seq: u64) -> GroupPosition {
    GroupPosition { seq, chain: None }
}

#[test]
fn a_message_the_channel_no_longer_takes_goes_on_positioned() {
    let id = GroupMessageId::random();
    let message = GroupBroadcast::Message {
        sender: 3,
        key: KEY,
        id,
        message: SecBuffer::from(b"held".to_vec()),
    };
    let payload = to_payload(opened(KEY, at(4), message));
    assert!(
        matches!(&payload, GroupBroadcastPayload::Message { position, .. } if *position == at(4))
    );
    let back = from_payload(KEY, payload);
    assert!(
        matches!(&back, GroupBroadcast::Ordered { key, position, frame } if *key == KEY
            && *position == at(4)
            && matches!(frame.as_ref(), GroupBroadcast::Message { sender: 3, id: i, message, .. }
                if *i == id && message.as_ref() == b"held")),
        "{back:?}"
    );
}

#[test]
fn a_positioned_event_reaches_the_application_with_its_position() {
    let entered = GroupBroadcast::MemberStateChanged {
        key: KEY,
        state: MemberState::EnteredGroup { cids: vec![5] },
    };
    let payload = to_payload(event_at(KEY, Some(at(2)), entered));
    let GroupBroadcastPayload::Event { payload } = payload else {
        panic!("an event became a message");
    };
    assert!(
        matches!(&payload, GroupBroadcast::Ordered { position, frame, .. } if *position == at(2)
            && matches!(frame.as_ref(), GroupBroadcast::MemberStateChanged { .. })),
        "{payload:?}"
    );
    let unpositioned = event_at(
        KEY,
        None,
        GroupBroadcast::MemberStateChanged {
            key: KEY,
            state: MemberState::LeftGroup { cids: vec![5] },
        },
    );
    assert!(matches!(
        unpositioned,
        GroupBroadcast::MemberStateChanged { .. }
    ));
}
