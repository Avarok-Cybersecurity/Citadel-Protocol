//! The task that runs one connection's lane: it takes lane frames off the reliable stream before
//! the application sees them, and sends this side's lane frames, Hello first.

use super::shared::{LaneFrame, LaneShared, LANE_TICKET};
use crate::error::NetworkError;
use crate::proto::session::UserMessage;
use crate::proto::state_container::VirtualConnectionType;
use crate::{ProtocolMessengerRx, ProtocolMessengerTx};
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::{mpsc, Mutex};
use citadel_negotiation::frame::{decode, encode};
use citadel_types::crypto::{SecBuffer, SecurityLevel};
use futures::StreamExt;
use std::sync::Arc;

/// The connection's one messenger sender, shared by the application's send half and the lane,
/// so both draw message ids from the same dense sequence.
pub(crate) type SharedMessengerTx<R> = Arc<Mutex<ProtocolMessengerTx<R>>>;

pub(crate) struct Driver<R: Ratchet> {
    pub(crate) shared: Arc<LaneShared<R>>,
    pub(crate) tx: SharedMessengerTx<R>,
    pub(crate) target: VirtualConnectionType,
    pub(crate) security_level: SecurityLevel,
}

impl<R: Ratchet> Driver<R> {
    /// Runs until the reliable stream ends or the application drops its receive half.
    pub(crate) async fn run(
        self,
        mut inbound: ProtocolMessengerRx<R>,
        app: mpsc::UnboundedSender<SecBuffer>,
        mut outbound: mpsc::UnboundedReceiver<LaneFrame>,
    ) {
        let mut local = self.shared.local.subscribe();
        let mut hello_sent = false;
        loop {
            if !hello_sent {
                let decided = local.borrow_and_update().clone();
                if let Some(hello) = decided {
                    hello_sent = true;
                    if self.shared.capable {
                        self.send(&LaneFrame::Hello(hello)).await;
                    }
                    continue;
                }
            }
            citadel_io::tokio::select! {
                biased;
                _ = app.closed() => break,
                message = inbound.next() => match message {
                    None => break,
                    Some(message) if message.ticket == LANE_TICKET => self.on_frame(message.packet).await,
                    Some(message) => {
                        if app.send(message.packet).is_err() {
                            break;
                        }
                    }
                },
                changed = local.changed(), if !hello_sent => {
                    if changed.is_err() {
                        break;
                    }
                },
                frame = outbound.recv(), if hello_sent => match frame {
                    Some(frame) if self.shared.capable => self.send(&frame).await,
                    Some(_) => {}
                    None => break,
                },
            }
        }
        self.shared.update(|state| state.closed = true);
    }

    async fn on_frame(&self, bytes: SecBuffer) {
        let frame: LaneFrame = match decode(bytes.as_ref()) {
            Ok(frame) => frame,
            Err(err) => {
                log::warn!(target: "citadel", "negotiation lane: unreadable frame from the peer: {err:?}");
                return;
            }
        };
        match frame {
            LaneFrame::Hello(hello) => self.shared.update(|state| {
                if state.peer_hello.is_none() {
                    state.peer_hello = Some(hello);
                }
            }),
            LaneFrame::Negotiation(envelope) => self.shared.route(envelope),
            LaneFrame::Closing(reason) => {
                self.shared.closing.record(reason);
                self.send(&LaneFrame::ClosingSeen).await;
            }
            LaneFrame::ClosingSeen => self.shared.update(|state| state.closing_seen = true),
        }
    }

    async fn send(&self, frame: &LaneFrame) {
        if let Err(err) = self.try_send(frame).await {
            log::warn!(target: "citadel", "negotiation lane: could not send {frame:?}: {err:?}");
        }
    }

    async fn try_send(&self, frame: &LaneFrame) -> Result<(), NetworkError> {
        let bytes = encode(frame).map_err(|err| NetworkError::msg(err.0))?;
        let message = UserMessage {
            ticket: LANE_TICKET,
            packet: SecBuffer::from(bytes),
            target: self.target,
            security_level: self.security_level,
        };
        self.tx
            .lock()
            .await
            .send(message)
            .await
            .map_err(|err| NetworkError::msg(err.to_string()))
    }
}
