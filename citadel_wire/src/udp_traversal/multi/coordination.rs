//! The signalling half of the dual-stack hole punch: the messages the two
//! sides exchange over the reliable channel to agree on one socket pair and to
//! finish together.
//!
//! Exactly one side becomes the winner, by taking the `NetMutex` first. It
//! sends `Winner` naming the pair, submits its own socket, and then waits for
//! `WinnerCanEnd`. The other side, the loser, is "commanded" by that `Winner`,
//! finds or rebuilds the named socket, and releases the winner with
//! `WinnerCanEnd`. `AllFailed` says that every local puncher has failed.

use crate::udp_traversal::HolePunchID;
use citadel_io::tokio::sync::Mutex;
use netbeam::multiplex::MultiplexedConn;
use netbeam::sync::channel::bi_channel::{ChannelRecvHalf, ChannelSendHalf};
use netbeam::sync::network_endpoint::NetworkEndpoint;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[allow(variant_size_differences)]
pub(super) enum DualStackCandidateSignal {
    Winner(HolePunchID, HolePunchID),
    WinnerCanEnd,
    AllFailed,
}

type SignalTx = ChannelSendHalf<DualStackCandidateSignal, MultiplexedConn>;
type SignalRx = ChannelRecvHalf<DualStackCandidateSignal, MultiplexedConn>;

pub(super) struct Coordination {
    conn_tx: SignalTx,
    conn_rx: Mutex<SignalRx>,
    /// `(local, remote)` as commanded by the remote winner. `Some` on the loser.
    pub(super) commanded_winner: Mutex<Option<(HolePunchID, HolePunchID)>>,
    failure_occurred: AtomicBool,
}

impl Coordination {
    pub(super) async fn open(app: &NetworkEndpoint) -> Result<Self, anyhow::Error> {
        let (conn_tx, conn_rx) = app.bi_channel::<DualStackCandidateSignal>().await?.split();
        Ok(Self {
            conn_tx,
            conn_rx: Mutex::new(conn_rx),
            commanded_winner: Mutex::new(None),
            failure_occurred: AtomicBool::new(false),
        })
    }

    /// Winner only: tell the loser which pair to use, as `(loser's id, winner's id)`.
    pub(super) async fn announce_winner(
        &self,
        remote_id: HolePunchID,
        local_id: HolePunchID,
    ) -> Result<(), anyhow::Error> {
        self.send(DualStackCandidateSignal::Winner(remote_id, local_id))
            .await
    }

    /// Records a failure on either side. The first one tells the remote with
    /// `AllFailed`; the second one means both sides have failed.
    pub(super) async fn signal_all_failed(&self) -> Result<(), anyhow::Error> {
        let no_failure_yet = !self.failure_occurred.fetch_or(true, Ordering::SeqCst);
        if no_failure_yet {
            log::trace!(target: "citadel", "All hole-punchers have failed locally. Will send AllFailed signal");
            self.send(DualStackCandidateSignal::AllFailed).await
        } else {
            // In this case, remote already failed, so we know that since they
            // failed, and now that we failed, we can end.
            log::error!(target: "citadel", "Remote has already failed, and locally failed, therefore returning");
            Err(anyhow::Error::msg(
                "All local and remote hold punchers failed",
            ))
        }
    }

    /// Every local puncher has resolved with an error.
    pub(super) async fn on_local_all_failed(&self) -> Result<(), anyhow::Error> {
        // All failed locally, but, remote may claim that it has a valid socket.
        // This exits if remote already failed too.
        self.signal_all_failed().await
    }

    /// Consumes signals until the remote releases the winner.
    pub(super) async fn read_signals(&self) -> Result<(), anyhow::Error> {
        let mut conn_rx = self.conn_rx.lock().await;
        loop {
            match receive(&mut conn_rx).await? {
                DualStackCandidateSignal::Winner(local_id, peer_id) => {
                    log::trace!(target: "citadel", "[READER] Remote commanded local to use peer={peer_id:?} and local={local_id:?}");
                    *self.commanded_winner.lock().await = Some((local_id, peer_id));
                }
                DualStackCandidateSignal::AllFailed => {
                    log::warn!(target: "citadel", "Remote claims all hole punchers failed");
                    self.signal_all_failed().await?;
                    // If we reach here, this node is still resolving futures.
                }
                DualStackCandidateSignal::WinnerCanEnd => {
                    return Ok(());
                }
            }
        }
    }

    /// Winner only, after submitting its socket.
    pub(super) async fn await_winner_can_end(&self) -> Result<(), anyhow::Error> {
        log::trace!(target: "citadel", "Winner: awaiting WinnerCanEnd signal");
        let mut conn_rx = self.conn_rx.lock().await;
        let signal = receive(&mut conn_rx).await?;
        if let DualStackCandidateSignal::WinnerCanEnd = signal {
            log::trace!(target: "citadel", "Received WinnerCanEnd signal");
        } else {
            log::warn!(target: "citadel", "Received unexpected signal: {signal:?}");
        }
        Ok(())
    }

    /// Loser only, after submitting its socket.
    pub(super) async fn release_winner(&self) -> Result<(), anyhow::Error> {
        log::trace!(target: "citadel", "Loser: sending WinnerCanEnd signal");
        self.send(DualStackCandidateSignal::WinnerCanEnd).await
    }

    async fn send(&self, signal: DualStackCandidateSignal) -> Result<(), anyhow::Error> {
        self.conn_tx.send_item(signal).await
    }
}

async fn receive(conn: &mut SignalRx) -> Result<DualStackCandidateSignal, anyhow::Error> {
    conn.recv()
        .await
        .ok_or_else(|| anyhow::Error::msg("recv from bichannel failed: stream ended"))?
}

#[cfg(test)]
#[path = "coordination_tests.rs"]
mod tests;
