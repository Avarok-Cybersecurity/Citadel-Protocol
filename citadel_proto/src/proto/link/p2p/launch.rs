//! `launch_link` (S-P1): what both key-exchange arms did once their channel existed, written
//! once. It picks the request's ticket, builds the kernel's `PeerChannelCreated`, stamps the
//! plan and the class gates, and starts the pair's path work: the campaign under
//! `LinkManagerMode::Legacy`, the link manager under `Managed`.

use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_io::tokio::sync::oneshot;
use citadel_types::proto::{SessionSecuritySettings, UdpMode};
use netbeam::sync::RelativeNodeType;

use super::start::ManagedPair;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::{NodeResult, PeerChannelCreated};
use crate::proto::peer::channel::{PeerChannel, UdpChannel};
use crate::proto::peer::class_gates::ClassGates;
use crate::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream;
use crate::proto::peer::kex_path::{self, KexPath};
use crate::proto::peer::p2p_campaign;
use crate::proto::peer::p2p_path::CampaignEndGuard;
use crate::proto::peer::p2p_plan::{execution_plan, P2pPlan};
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::peer_layer::PeerConnectionType;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::OutgoingPeerConnectionAttempt;

/// Everything a key-exchange arm hands over once the pair's channel exists.
pub(crate) struct LaunchedPair<R: Ratchet, T: PlatformOps> {
    pub(crate) session: CitadelSession<R, T>,
    /// This side's view of the connection (the arm's `conn.reverse()`).
    pub(crate) peer_connection_type: PeerConnectionType,
    /// The exchange packet's ticket.
    pub(crate) ticket: Ticket,
    pub(crate) peer_nat_info: PeerNatInfo,
    pub(crate) channel: PeerChannel<R>,
    pub(crate) udp_rx_opt: Option<oneshot::Receiver<UdpChannel<R>>>,
    pub(crate) hole_punch_compat_stream: ReliableOrderedCompatStream<R>,
    pub(crate) endpoint_ratchet: R,
    pub(crate) peer_cid: u64,
    pub(crate) sync_instant: Instant,
    pub(crate) node_type: RelativeNodeType,
    /// The settings the exchange's state was built with.
    pub(crate) kem_settings: SessionSecuritySettings,
    /// This side's own dial, when it dialled (its kernel ticket and offered settings).
    pub(crate) outgoing: Option<OutgoingPeerConnectionAttempt>,
    /// Both NATs are unpredictable: no punch can work.
    pub(crate) needs_turn: bool,
    pub(crate) cancel_rx: oneshot::Receiver<()>,
    pub(crate) kex_path: Option<KexPath>,
    pub(crate) peer_protocol_version: Option<u32>,
    pub(crate) turn: Option<citadel_wire::udp_traversal::turn_relay::TurnRelayConfig>,
}

/// Starts the pair's link: the kernel gets its channel (released as the campaign always did),
/// and the path work begins in the background.
pub(crate) fn launch_link<R: Ratchet, T: PlatformOps>(pair: LaunchedPair<R, T>) {
    let LaunchedPair {
        session,
        peer_connection_type,
        ticket,
        peer_nat_info,
        channel,
        udp_rx_opt,
        hole_punch_compat_stream,
        endpoint_ratchet,
        peer_cid,
        sync_instant,
        node_type,
        kem_settings,
        outgoing,
        needs_turn,
        cancel_rx,
        kex_path,
        peer_protocol_version,
        turn,
    } = pair;
    let udp_mode = if udp_rx_opt.is_some() {
        UdpMode::Enabled
    } else {
        UdpMode::Disabled
    };
    // The dialler answers its own request's ticket; a side that did not dial answers the
    // exchange's.
    let (init_ticket, session_security_settings) = match outgoing {
        Some(OutgoingPeerConnectionAttempt {
            ticket: stored_ticket,
            session_security_settings: stored_settings,
        }) => (stored_ticket, stored_settings),
        None => {
            log::trace!(target: "citadel", "Using the exchange's ticket for peer {peer_cid} (no dial of our own)");
            (ticket, kem_settings)
        }
    };
    let managed = managed_pair(
        &session,
        &channel,
        peer_connection_type,
        ticket,
        &peer_nat_info,
        &endpoint_ratchet,
        udp_mode,
        session_security_settings,
        sync_instant,
    );
    let guard = CampaignEndGuard::start(channel.p2p_path_cell());
    let channel_signal = NodeResult::PeerChannelCreated(PeerChannelCreated {
        ticket: init_ticket,
        channel: channel.into(),
        udp_rx_opt,
    });
    let stamped = kex_path::stamped_plan(kex_path.as_ref(), peer_protocol_version);
    guard
        .cell()
        .set_gates(ClassGates::from_stamped(stamped.as_ref()));
    let plan = execution_plan(stamped.as_ref(), needs_turn, turn.clone());
    let managed = managed.map(|pending| pending.with_plan(plan.clone(), needs_turn, turn));
    // The channel is usable over the relay now; the campaign releases it (the receiver at once,
    // the initiator once the receiver's vconn provably exists) and upgrades it in the background.
    p2p_campaign::spawn(p2p_campaign::Campaign {
        session,
        peer_connection_type,
        ticket,
        peer_nat_info,
        channel_signal,
        hole_punch_compat_stream,
        endpoint_ratchet,
        peer_cid,
        sync_instant,
        node_type,
        udp_mode,
        session_security_settings,
        cancel_rx,
        plan,
        direct_impossible: needs_turn,
        guard,
        managed,
    });
}

/// The pair's manager, on a `Managed` node, for the campaign to hand over to if the peer is
/// `Managed` too. `None` on a `Legacy` node, and for a channel without a connection id (a peer
/// below `NEGOTIATION_SINCE`, which is below `LINK_MODE_SINCE` too).
#[allow(clippy::too_many_arguments)]
fn managed_pair<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    channel: &PeerChannel<R>,
    peer_connection_type: PeerConnectionType,
    ticket: Ticket,
    peer_nat_info: &PeerNatInfo,
    endpoint_ratchet: &R,
    udp_mode: UdpMode,
    security: SessionSecuritySettings,
    sync_time: Instant,
) -> Option<PendingPair<R, T>> {
    let policy = *session.session_manager.link_manager().policy()?;
    let connection = citadel_link::ConnectionId(channel.connection_id()?.0);
    Some(PendingPair(ManagedPair {
        policy,
        session: session.as_weak(),
        session_cid: session.session_cid.clone(),
        rebinder: session.session_manager.local_rebinder(),
        peer_connection_type,
        ticket,
        connection,
        security,
        udp_mode,
        peer_nat_info: peer_nat_info.clone(),
        local_nat: session.local_nat_type.class(),
        endpoint_ratchet: endpoint_ratchet.clone(),
        turn: None,
        plan: P2pPlan {
            steps: Vec::new(),
            turn_configured: false,
        },
        direct_impossible: false,
        sync_time,
        cell: channel.p2p_path_cell(),
    }))
}

/// A managed pair whose plan is not yet made (the plan needs the gates the guard records).
struct PendingPair<R: Ratchet, T: PlatformOps>(ManagedPair<R, T>);

impl<R: Ratchet, T: PlatformOps> PendingPair<R, T> {
    fn with_plan(
        self,
        plan: P2pPlan,
        direct_impossible: bool,
        turn: Option<citadel_wire::udp_traversal::turn_relay::TurnRelayConfig>,
    ) -> ManagedPair<R, T> {
        ManagedPair {
            plan,
            direct_impossible,
            turn,
            ..self.0
        }
    }
}
