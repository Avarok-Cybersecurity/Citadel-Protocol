//! Scaffolding for tests of replay groups: a server that keeps group logs, and a reader that
//! records what a member's channel hands its application, in order.

use super::group::*;
use super::group_relay::*;
use citadel_io::tokio;
use citadel_sdk::prelude::*;
use std::time::Duration;

/// What the test server keeps of a group's log at most, and what the groups ask for.
pub const LOG: GroupLogLimits = GroupLogLimits {
    max_age: Duration::from_secs(3600),
    max_messages: 4096,
    max_bytes: 1 << 26,
    max_message_bytes: GroupLogLimits::MIN_MESSAGE_BYTES,
};

/// A server that keeps group logs within [`LOG`].
pub fn replay_server() -> (
    NodeFuture<'static, impl NetKernel<StackedRatchet>>,
    std::net::SocketAddr,
    ServerRemote,
) {
    probed_server_with(|builder| {
        let _ = builder.with_group_log_limits(LOG);
    })
}

/// The options of a group created with replay within `limits`.
pub fn replay_options(limits: GroupLogLimits) -> MessageGroupOptions {
    MessageGroupOptions {
        replay: Some(limits),
        ..Default::default()
    }
}

/// One thing a member's channel handed its application.
#[derive(Debug, Clone, PartialEq)]
pub enum Read {
    /// A message: its text (or its length, when it is not text), at its position.
    Message { text: String, at: GroupPosition },
    /// A positioned event.
    Event { at: GroupPosition, event: String },
    /// The channel said positions were lost before `earliest`.
    Broken { last: u64, earliest: u64 },
}

/// Reads `channel` until a message whose text is `last`, recording what it hands on.
pub async fn read_until(channel: &mut GroupChannel, last: &str) -> Vec<Read> {
    let mut read = Vec::new();
    let got = tokio::time::timeout(REJOIN_DEADLINE * 4, async {
        loop {
            let Some(payload) = channel.recv().await else {
                panic!("the member's channel closed; read so far: {read:?}");
            };
            match payload {
                GroupBroadcastPayload::Message {
                    payload, position, ..
                } => {
                    let text = String::from_utf8(payload.as_ref().to_vec())
                        .unwrap_or_else(|_| format!("{} bytes", payload.as_ref().len()));
                    let done = text == last;
                    read.push(Read::Message { text, at: position });
                    if done {
                        return;
                    }
                }
                GroupBroadcastPayload::Event {
                    payload:
                        GroupBroadcast::Ordered {
                            position, frame, ..
                        },
                } => read.push(Read::Event {
                    at: position,
                    event: format!("{frame:?}"),
                }),
                GroupBroadcastPayload::Event {
                    payload:
                        GroupBroadcast::OrderBroken {
                            last,
                            reason: GroupOrderBroken::Trimmed { earliest },
                            ..
                        },
                } => read.push(Read::Broken { last, earliest }),
                GroupBroadcastPayload::Event { payload } => {
                    log::info!(target: "citadel", "[reader] event: {payload:?}")
                }
            }
        }
    })
    .await;
    assert!(got.is_ok(), "'{last}' never arrived; read: {read:?}");
    read
}

/// The positions of what was read, in the order read.
pub fn seqs(read: &[Read]) -> Vec<u64> {
    read.iter()
        .filter_map(|r| match r {
            Read::Message { at, .. } | Read::Event { at, .. } => Some(at.seq),
            Read::Broken { .. } => None,
        })
        .collect()
}

/// The texts of the messages read, in the order read.
pub fn texts(read: &[Read]) -> Vec<String> {
    read.iter()
        .filter_map(|r| match r {
            Read::Message { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// Sends `text` on `channel` and returns the position the server gave it.
pub async fn send_positioned(channel: &mut GroupChannel, text: Vec<u8>) -> GroupPosition {
    channel.send_message(SecBuffer::from(text)).await.unwrap();
    match next_send_answer(channel).await {
        GroupBroadcast::MessageResponse {
            position: Some(position),
            ..
        } => position,
        other => panic!("the message was not positioned: {other:?}"),
    }
}
