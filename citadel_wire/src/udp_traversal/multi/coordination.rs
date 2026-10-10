//! The signalling half of the dual-stack hole punch: the messages the two
//! sides exchange over the reliable channel to agree on one socket pair and to
//! finish together.
//!
//! Exactly one side becomes the winner, by taking the `NetMutex` first. It
//! sends `Winner` naming the pair, submits its own socket, and then waits for
//! `WinnerCanEnd`. The other side, the loser, is "commanded" by that `Winner`,
//! finds or rebuilds the named socket, and releases the winner with
//! `WinnerCanEnd`. `AllFailed` says that every local puncher has failed.
//!
//! Every rule below exists because breaking it fails one side while both hold
//! a working socket. The other side has then already returned, so a retry
//! cannot recover either:
//!
//! - A loser that has been commanded does not send `AllFailed`: its rebuilder
//!   decides from then on, and usually recovers the commanded socket.
//! - A winner waits for `WinnerCanEnd` itself, not merely the next signal.
//!   `AllFailed` can cross a `Winner` in flight.
//! - A `WinnerCanEnd` that the reader consumed still releases the winner.
//! - A loser that could not deliver `WinnerCanEnd` still succeeds: it holds the
//!   commanded socket, and the winner only leaves after committing its own.
//! - Receiving `AllFailed` records that the remote failed. It is not echoed:
//!   the echo claimed a local failure that had not happened, and ended the
//!   remote's reader before it could take this side's `Winner`.

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
    local_failed: AtomicBool,
    remote_failed: AtomicBool,
    winner_can_end: AtomicBool,
}

impl Coordination {
    pub(super) async fn open(app: &NetworkEndpoint) -> Result<Self, anyhow::Error> {
        let (conn_tx, conn_rx) = app.bi_channel::<DualStackCandidateSignal>().await?.split();
        Ok(Self {
            conn_tx,
            conn_rx: Mutex::new(conn_rx),
            commanded_winner: Mutex::new(None),
            local_failed: AtomicBool::new(false),
            remote_failed: AtomicBool::new(false),
            winner_can_end: AtomicBool::new(false),
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

    /// Every local puncher has resolved with an error. Errors once both sides
    /// have failed.
    pub(super) async fn on_local_all_failed(&self) -> Result<(), anyhow::Error> {
        if let Some(commanded) = *self.commanded_winner.lock().await {
            log::trace!(target: "citadel", "All hole-punchers have failed locally, but remote commanded {commanded:?}; the rebuilder decides");
            return Ok(());
        }

        self.local_failed.store(true, Ordering::SeqCst);
        log::trace!(target: "citadel", "All hole-punchers have failed locally. Will send AllFailed signal");
        self.send(DualStackCandidateSignal::AllFailed).await?;
        self.fail_if_both_failed()
    }

    /// Neither side has a socket, so no winner can appear.
    pub(super) fn both_failed(&self) -> bool {
        self.local_failed.load(Ordering::SeqCst) && self.remote_failed.load(Ordering::SeqCst)
    }

    fn fail_if_both_failed(&self) -> Result<(), anyhow::Error> {
        if self.both_failed() {
            log::warn!(target: "citadel", "Remote has already failed, and locally failed, therefore returning");
            Err(anyhow::Error::msg(
                "All local and remote hold punchers failed",
            ))
        } else {
            Ok(())
        }
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
                    self.remote_failed.store(true, Ordering::SeqCst);
                    // Otherwise this node is still resolving, and may yet win.
                    self.fail_if_both_failed()?;
                }
                DualStackCandidateSignal::WinnerCanEnd => {
                    self.winner_can_end.store(true, Ordering::SeqCst);
                    return Ok(());
                }
            }
        }
    }

    /// Winner only, after submitting its socket.
    pub(super) async fn await_winner_can_end(&self) -> Result<(), anyhow::Error> {
        log::trace!(target: "citadel", "Winner: awaiting WinnerCanEnd signal");
        let mut conn_rx = self.conn_rx.lock().await;
        if self.winner_can_end.load(Ordering::SeqCst) {
            log::trace!(target: "citadel", "WinnerCanEnd was already received by the reader");
            return Ok(());
        }

        loop {
            match receive(&mut conn_rx).await? {
                DualStackCandidateSignal::WinnerCanEnd => {
                    log::trace!(target: "citadel", "Received WinnerCanEnd signal");
                    return Ok(());
                }
                signal => {
                    log::trace!(target: "citadel", "Winner: ignoring {signal:?} while awaiting WinnerCanEnd");
                }
            }
        }
    }

    /// Loser only, after submitting its socket. Cannot fail the loser.
    pub(super) async fn release_winner(&self) {
        log::trace!(target: "citadel", "Loser: sending WinnerCanEnd signal");
        if let Err(err) = self.send(DualStackCandidateSignal::WinnerCanEnd).await {
            log::warn!(target: "citadel", "Loser: the winner had already ended ({err}); keeping the commanded socket");
        }
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
