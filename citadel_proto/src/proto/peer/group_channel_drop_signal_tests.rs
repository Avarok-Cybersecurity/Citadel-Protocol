//! A dropped group channel must leave the room even when the session's request
//! queue is momentarily full; otherwise the server keeps the member and a later
//! rejoin runs into it.

use super::*;
use crate::constants::MAX_OUTGOING_UNPROCESSED_REQUESTS;
use citadel_io::tokio;

const SESSION_CID: u64 = 10;

#[tokio::test]
async fn leave_room_survives_a_full_session_queue() {
    let (tx, mut rx) = crate::proto::outbound_sender::channel(MAX_OUTGOING_UNPROCESSED_REQUESTS);
    let key = MessageGroupKey {
        cid: SESSION_CID,
        mgid: 7,
    };
    let backlog_ticket = Ticket(99);

    for _ in 0..MAX_OUTGOING_UNPROCESSED_REQUESTS {
        tx.try_send(SessionRequest::Group(Group {
            ticket: backlog_ticket,
            broadcast: GroupBroadcast::End { key },
        }))
        .unwrap();
    }

    let (_payload_tx, payload_rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
    let recv_half = GroupChannelRecvHalf {
        recv: payload_rx,
        tx,
        ticket: Ticket(1),
        session_cid: SESSION_CID,
        key,
    };

    drop(recv_half);

    for _ in 0..MAX_OUTGOING_UNPROCESSED_REQUESTS {
        let request = rx.recv().await.expect("backlog item");
        assert!(matches!(
            request,
            SessionRequest::Group(Group { ticket, .. }) if ticket == backlog_ticket
        ));
    }

    let request = rx
        .recv()
        .await
        .expect("the LeaveRoom signal from the dropped group channel was never delivered");
    assert!(
        matches!(
            &request,
            SessionRequest::Group(Group {
                ticket: Ticket(1),
                broadcast: GroupBroadcast::LeaveRoom { key: k },
            }) if *k == key
        ),
        "unexpected request after the backlog"
    );
}
