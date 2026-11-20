//! The lane's wire frames and the state its driver and handles share.

use super::reason::{DisconnectReason, PeerClosing};
use crate::proto::disconnect_tracker::DisconnectToken;
use crate::proto::remote::{NodeRemote, Ticket};
use crate::proto::state_container::VirtualConnectionType;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::{mpsc, watch};
use citadel_io::Mutex;
use citadel_negotiation::{ConnectionId, Envelope, Hello, SettingId, REORDER_WINDOW};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Marks a message on the reliable stream as a lane frame. Application messages carry their
/// channel's ticket, which is drawn at random and never this value.
pub(crate) const LANE_TICKET: Ticket = Ticket(u128::MAX);

/// What the lane carries. Bincode, like every frame of the negotiation crate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum LaneFrame {
    Hello(Hello),
    Negotiation(Envelope),
    /// "I am about to close this connection, for this reason."
    Closing(DisconnectReason),
    /// "I have recorded your reason": the closing side may now disconnect.
    ClosingSeen,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LaneState {
    pub(crate) peer_hello: Option<Hello>,
    pub(crate) closing_seen: bool,
    /// The connection's reliable stream has ended.
    pub(crate) closed: bool,
}

pub(crate) enum Route {
    /// Frames for a setting nobody has taken yet, bounded by [`REORDER_WINDOW`].
    Waiting(Vec<Envelope>),
    Taken(mpsc::UnboundedSender<Envelope>),
}

pub(crate) struct LaneShared<R: Ratchet> {
    pub(crate) connection: ConnectionId,
    pub(crate) state: watch::Sender<LaneState>,
    /// This side's Hello, once decided; the driver sends it before any other frame.
    pub(crate) local: watch::Sender<Option<Hello>>,
    pub(crate) outbound: mpsc::UnboundedSender<LaneFrame>,
    pub(crate) routes: Mutex<HashMap<SettingId, Route>>,
    pub(crate) closing: PeerClosing,
    pub(crate) node_remote: NodeRemote<R>,
    pub(crate) vconn_type: VirtualConnectionType,
    pub(crate) disconnect_token: Option<DisconnectToken>,
}

impl<R: Ratchet> std::fmt::Debug for LaneShared<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NegotiationLane")
            .field("connection", &self.connection)
            .finish()
    }
}

impl<R: Ratchet> LaneShared<R> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        connection: ConnectionId,
        outbound: mpsc::UnboundedSender<LaneFrame>,
        closing: PeerClosing,
        node_remote: NodeRemote<R>,
        vconn_type: VirtualConnectionType,
        disconnect_token: Option<DisconnectToken>,
    ) -> Self {
        Self {
            connection,
            state: watch::channel(LaneState::default()).0,
            local: watch::channel(None).0,
            outbound,
            routes: Mutex::new(HashMap::new()),
            closing,
            node_remote,
            vconn_type,
            disconnect_token,
        }
    }

    /// Hands a peer's frame to the setting's taker, or holds it until one takes the setting.
    pub(crate) fn route(&self, envelope: Envelope) {
        let mut routes = self.routes.lock();
        let route = routes
            .entry(envelope.setting)
            .or_insert_with(|| Route::Waiting(Vec::new()));
        match route {
            Route::Taken(tx) => {
                let _ = tx.send(envelope);
            }
            Route::Waiting(held) if (held.len() as u64) < REORDER_WINDOW => held.push(envelope),
            Route::Waiting(_) => {
                log::warn!(target: "citadel", "negotiation lane: dropping a frame for {:?}, which nobody has taken", envelope.setting);
            }
        }
    }

    /// Resolves with the lane's state once `done` holds for it. Each wait clones the state out
    /// of the watch before it awaits, so the future holds no lock across an await.
    pub(crate) async fn reached(
        &self,
        done: impl Fn(&LaneState) -> bool,
    ) -> Result<LaneState, crate::error::NetworkError> {
        let mut state = self.state.subscribe();
        loop {
            let now = state.borrow_and_update().clone();
            if done(&now) {
                return Ok(now);
            }
            state
                .changed()
                .await
                .map_err(|err| crate::error::NetworkError::msg(err.to_string()))?;
        }
    }

    pub(crate) fn update(&self, change: impl FnOnce(&mut LaneState)) {
        self.state.send_modify(change);
    }
}
