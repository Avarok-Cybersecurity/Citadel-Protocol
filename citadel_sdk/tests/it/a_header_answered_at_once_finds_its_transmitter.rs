#![cfg(not(target_family = "wasm"))]
//! A group header answered as soon as it is sent still finds its transmitter.
//!
//! The sender handles a group header's answer under the state container's read lock, and
//! registers the group's transmitter under the same read lock, so nothing but the order of the
//! two steps decides which comes first. When the header went out before the transmitter was
//! registered, an answer read in between found nothing ("header ack for GroupKey { .. } does not
//! map to a transmitter container"), was dropped, and the transfer waited forever: seen once in
//! the workspace's file-manager integration run, with both accounts on one agent.
//!
//! The test makes "in between" certain instead of rare: the sender is held right after it hands
//! the header to the stream, the answer is read while it is held, and only then does the sender
//! go on. With the header sent after the registration, the answer finds the transmitter and the
//! transfer completes; with it sent before, the answer reads `NoTransmitter`, the branch that
//! logs that line.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::transfer::{receiver_verdict, sender_verdict, upload};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
    use citadel_proto::test_hooks::{
        hold_group_header_sent, observe_group_header_acks, GroupHeaderAckRead, GroupHeaderHold,
        HeaderAckFound,
    };
    use citadel_types::proto::ObjectTransferStatus;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Bounds a transfer that is under way: the 2 MB file takes milliseconds on loopback, and a
    /// stall (the defect) is reported as a failure here instead of hanging the run.
    const COMPLETES_WITHIN: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn a_header_answered_at_once_finds_its_transmitter() {
        citadel_logging::setup_log();
        // Both placed before the file is offered: the answer can be read before `check` runs.
        type Hooks = (GroupHeaderHold, UnboundedReceiver<GroupHeaderAckRead>);
        let hooks: Arc<Mutex<Option<Hooks>>> = Arc::new(Mutex::new(None));
        let placed = hooks.clone();
        upload(
            move |session_cid| {
                *placed.lock().unwrap() = Some((
                    hold_group_header_sent(session_cid),
                    observe_group_header_acks(),
                ));
            },
            move |mut upload| async move {
                let (mut hold, mut acks) = hooks
                    .lock()
                    .unwrap()
                    .take()
                    .expect("hooks placed before the send");
                hold.sent().await;
                // The sender is held with its first header on the stream: its answer is read now.
                let read = loop {
                    let read = acks.recv().await.expect("header-ack observer closed");
                    if read.key_cid == upload.session_cid {
                        break read;
                    }
                };
                hold.release();
                assert_eq!(
                    read.found,
                    HeaderAckFound::ItsTransmitter,
                    "the header's answer was read before its transmitter was registered \
                     (\"does not map to a transmitter container\"): the transfer would stall"
                );

                let (sent, before) =
                    tokio::time::timeout(COMPLETES_WITHIN, sender_verdict(&mut upload.handle))
                        .await
                        .expect("the sender's transfer did not finish");
                assert!(
                    matches!(sent, Some(ObjectTransferStatus::TransferComplete)),
                    "the sender ended with {sent:?} after {before:?}"
                );
                let (received, before) =
                    tokio::time::timeout(COMPLETES_WITHIN, receiver_verdict(&mut upload.receiver))
                        .await
                        .expect("the receiver's transfer did not finish");
                assert!(
                    matches!(received, Some(ObjectTransferStatus::ReceptionComplete)),
                    "the receiver ended with {received:?} after {before:?}"
                );
            },
        )
        .await;
    }
}
