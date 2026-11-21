//! The in-channel negotiation lane: control frames that ride a P2P connection's reliable,
//! ordered message stream beside the application's messages, never delivered to it.
//!
//! A lane frame is a [`UserMessage`](crate::proto::session::UserMessage) whose ticket is
//! `LANE_TICKET`. The peer's SDK takes every such frame off the stream before the application
//! sees it (see `driver`). The first frame each side
//! sends is its [`Hello`]: the one the application gave [`PeerChannel::open_negotiation`], or an
//! empty one (nothing negotiated in band) once it splits the channel without opening the lane.
//!
//! [`PeerChannel::open_negotiation`]: crate::prelude::PeerChannel::open_negotiation

use super::reason::DisconnectReason;
use super::shared::{LaneFrame, LaneShared, Route};
use crate::error::NetworkError;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc;
use citadel_negotiation::ports::{BoxFuture, SendError, SignalPort};
use citadel_negotiation::{ConnectionId, Envelope, Hello, SettingId};
use std::sync::Arc;
use std::time::Duration;

/// A P2P connection's negotiation lane, from [`PeerChannel::open_negotiation`](crate::prelude::PeerChannel::open_negotiation).
pub struct NegotiationLane<R: Ratchet> {
    pub(crate) shared: Arc<LaneShared<R>>,
}

impl<R: Ratchet> Clone for NegotiationLane<R> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

/// One setting's half of the lane: the port the negotiator's frames go out through, and the
/// peer's frames for that setting, in the order they arrived.
pub struct SettingLane {
    pub port: LanePort,
    pub frames: mpsc::UnboundedReceiver<Envelope>,
}

impl<R: Ratchet> NegotiationLane<R> {
    /// The connection this lane belongs to (`DisconnectToken::connection_id`).
    pub fn connection(&self) -> ConnectionId {
        self.shared.connection
    }

    /// The peer's Hello. Fails if the connection ends before the peer's Hello arrives.
    pub async fn peer_hello(&self) -> Result<Hello, NetworkError> {
        let state = self
            .shared
            .reached(|s| s.peer_hello.is_some() || s.closed)
            .await?;
        state
            .peer_hello
            .ok_or_else(|| NetworkError::msg("the connection ended before the peer's Hello"))
    }

    /// Whether this side's Hello offers `setting` in band.
    pub fn local_offers(&self, setting: SettingId) -> bool {
        self.shared.local.borrow().as_ref().is_some_and(|hello| {
            hello.support_for(setting) == citadel_negotiation::PeerSupport::InBand
        })
    }

    /// Takes one setting's frames and port. Once per setting, and only for a setting this side's
    /// Hello offers in band.
    pub fn take_setting(&self, setting: SettingId) -> Result<SettingLane, NetworkError> {
        if !self.local_offers(setting) {
            return Err(NetworkError::msg(format!(
                "{setting:?} is not in this side's Hello"
            )));
        }
        let (tx, frames) = mpsc::unbounded_channel();
        let mut routes = self.shared.routes.lock();
        let held = match routes.insert(setting, Route::Taken(tx.clone())) {
            Some(Route::Taken(previous)) => {
                let _ = routes.insert(setting, Route::Taken(previous));
                return Err(NetworkError::msg(format!("{setting:?} was already taken")));
            }
            Some(Route::Waiting(held)) => held,
            None => Vec::new(),
        };
        for envelope in held {
            let _ = tx.send(envelope);
        }
        let port = LanePort {
            connection: self.shared.connection,
            outbound: self.shared.outbound.clone(),
        };
        Ok(SettingLane { port, frames })
    }

    /// Tells the peer, over the lane, why this side is about to close the connection, and waits
    /// (at most `ack_deadline`) for the peer to record it. The peer then reports the connection's
    /// end with that reason whatever the `Disconnect` that follows carries.
    pub async fn announce_closing(
        &self,
        reason: DisconnectReason,
        ack_deadline: Duration,
    ) -> Result<(), NetworkError> {
        let shared = &self.shared;
        shared
            .outbound
            .send(LaneFrame::Closing(reason))
            .map_err(|_| NetworkError::msg("the negotiation lane has ended"))?;
        let seen = shared.reached(|s| s.closing_seen || s.closed);
        if citadel_io::time::timeout(ack_deadline, seen).await.is_err() {
            log::warn!(target: "citadel", "negotiation lane: the peer did not record the closing reason within {ack_deadline:?}; disconnecting anyway");
        }
        Ok(())
    }

    /// Closes the connection on purpose: [`Self::announce_closing`], then a `Disconnect` that
    /// carries the reason too.
    pub async fn close_with_reason(
        &self,
        reason: DisconnectReason,
        ack_deadline: Duration,
    ) -> Result<(), NetworkError> {
        self.announce_closing(reason, ack_deadline).await?;
        let shared = &self.shared;
        let peer_conn_type = shared
            .vconn_type
            .try_as_peer_connection()
            .ok_or_else(|| NetworkError::msg("a negotiation lane is always a P2P connection"))?;
        let request = crate::proto::peer::disconnect_request::p2p_disconnect_request(
            peer_conn_type,
            shared.disconnect_token,
            Some(reason),
        );
        shared.node_remote.send(request).await.map(|_| ())
    }
}

/// The [`SignalPort`] over one connection's lane. A frame is accepted once queued behind this
/// side's Hello; `Err` means the connection's lane has ended.
#[derive(Clone, Debug)]
pub struct LanePort {
    connection: ConnectionId,
    outbound: mpsc::UnboundedSender<LaneFrame>,
}

impl LanePort {
    /// Queues `envelope` for the peer at once; the [`SignalPort`] impl is this, as a future.
    pub fn post(&self, conn: ConnectionId, envelope: Envelope) -> Result<(), SendError> {
        if conn != self.connection {
            return Err(SendError(format!(
                "this port belongs to {:?}, not {conn:?}",
                self.connection
            )));
        }
        self.outbound
            .send(LaneFrame::Negotiation(envelope))
            .map_err(|_| SendError("the negotiation lane has ended".into()))
    }
}

impl SignalPort for LanePort {
    fn send(
        &self,
        conn: ConnectionId,
        envelope: Envelope,
    ) -> BoxFuture<'static, Result<(), SendError>> {
        Box::pin(std::future::ready(self.post(conn, envelope)))
    }
}
