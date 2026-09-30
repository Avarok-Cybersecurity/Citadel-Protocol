//! A dropped peer channel must tell the session to disconnect even when the
//! node's request queue is momentarily full. The queue being full means the
//! request handler is behind (a stalled runtime, a slow inline await); it does
//! not mean the peer is still connected. Losing the signal leaves the vconn
//! registered and the next connect to that peer collides with it.

use super::*;
use crate::constants::MAX_OUTGOING_UNPROCESSED_REQUESTS;
use crate::kernel::kernel_communicator::{
    KernelAsyncCallbackHandler, KernelAsyncCallbackHandlerInner,
};
use crate::proto::outbound_sender::BoundedSender;
use crate::proto::peer::peer_layer::PeerSignal;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_user::account_manager::AccountManager;
use citadel_user::backend::BackendType;
use citadel_wire::hypernode_type::NodeType;

const LOCAL_CID: u64 = 10;
const PEER_CID: u64 = 20;

#[tokio::test]
async fn udp_disconnect_survives_a_full_request_queue() {
    let (tx, mut rx) = BoundedSender::new(MAX_OUTGOING_UNPROCESSED_REQUESTS);
    let account_manager = AccountManager::<StackedRatchet, StackedRatchet>::new(
        BackendType::InMemory,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let node_remote = NodeRemote::new(
        tx,
        KernelAsyncCallbackHandler {
            inner: Arc::new(citadel_io::Mutex::new(KernelAsyncCallbackHandlerInner {
                map: Default::default(),
            })),
        },
        account_manager,
        NodeType::default(),
    );

    for _ in 0..MAX_OUTGOING_UNPROCESSED_REQUESTS {
        node_remote
            .try_send(NodeRequest::GetActiveSessions)
            .unwrap();
    }

    let (_udp_tx, udp_rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
    let recv_half = PeerChannelRecvHalf::<StackedRatchet> {
        receiver: ReceiverType::UnorderedUnreliable { rx: udp_rx },
        target_cid: PEER_CID,
        vconn_type: VirtualConnectionType::LocalGroupPeer {
            session_cid: LOCAL_CID,
            peer_cid: PEER_CID,
        },
        channel_id: Ticket(1),
        is_alive: Arc::new(AtomicBool::new(true)),
        node_remote,
        disconnect_token: None,
    };

    drop(recv_half);

    for _ in 0..MAX_OUTGOING_UNPROCESSED_REQUESTS {
        let (request, _) = rx.recv().await.expect("backlog item");
        assert!(matches!(request, NodeRequest::GetActiveSessions));
    }

    let (request, _) = rx
        .recv()
        .await
        .expect("the DisconnectUDP signal from the dropped channel was never delivered");
    assert!(
        matches!(
            request,
            NodeRequest::PeerCommand(PeerCommand {
                session_cid: LOCAL_CID,
                command: PeerSignal::DisconnectUDP {
                    peer_conn_type: PeerConnectionType::LocalGroupPeer {
                        session_cid: LOCAL_CID,
                        peer_cid: PEER_CID,
                    },
                    ..
                },
            })
        ),
        "unexpected request after the backlog: {request:?}"
    );
}
