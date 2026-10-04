//! An immediate, authenticated C2S round trip: the liveness check a connection supervisor runs
//! instead of waiting out the keep-alive schedule (every 15 minutes, 45 to time out).
//!
//! The client seals a `KEEP_ALIVE` packet with `cmd_aux` [`PROBE`] and a random nonce in
//! `context_info`, under the C2S ratchet. The server validates it like any keep-alive and answers
//! at once with [`PROBE_REPLY`], echoing the nonce under the same ratchet; it touches none of the
//! keep-alive bookkeeping. The client matches the nonce and reports the round trip.
//!
//! A server below [`SERVER_PROBE_SINCE`] would read a probe as a plain keep-alive and start a
//! second keep-alive cycle, so a client never sends one to it: [`probe_server`] answers
//! `Error` for such a server, or for one whose version is unknown.
//!
//! [`probe_server`]: crate::proto::session::CitadelSession::probe_server

use crate::constants::{protocol_version_at_least, SERVER_PROBE_SINCE};
use crate::proto::remote::Ticket;
use citadel_io::time::{Duration, Instant};
use citadel_io::tokio::sync::oneshot;
use citadel_io::NetworkError;
use std::collections::HashMap;
use std::sync::Arc;

/// `KEEP_ALIVE` `cmd_aux` of a probe; a scheduled keep-alive carries 0.
pub(crate) const PROBE: u8 = 1;
/// `KEEP_ALIVE` `cmd_aux` of the server's answer to a probe.
pub(crate) const PROBE_REPLY: u8 = 2;

/// How a probe ended.
#[derive(Debug, Clone)]
pub enum ServerProbeOutcome {
    /// The server answered; the round trip took this long.
    Ok(Duration),
    /// No answer within the caller's timeout.
    Timeout,
    /// The probe could not be sent: no such connected session, a server too old to answer one,
    /// or the outbound stream is gone.
    Error(NetworkError),
}

/// The outcome of [`NodeRequest::ProbeServer`](crate::proto::node_request::NodeRequest).
#[derive(Debug)]
pub struct ServerProbeResult {
    pub ticket: Ticket,
    pub session_cid: u64,
    pub outcome: ServerProbeOutcome,
}

/// Whether a server at `adjacent_version` answers probes.
pub(crate) fn server_answers_probes(adjacent_version: Option<u32>) -> bool {
    protocol_version_at_least(adjacent_version, SERVER_PROBE_SINCE)
}

/// The probes a client session has in flight, by nonce.
#[derive(Clone, Default)]
pub(crate) struct ServerProbes(Arc<citadel_io::Mutex<HashMap<u128, oneshot::Sender<()>>>>);

impl ServerProbes {
    /// Registers a probe under a fresh nonce. Dropping the returned probe forgets it.
    pub(crate) fn begin(&self) -> PendingProbe {
        let (tx, rx) = oneshot::channel();
        let mut pending = self.0.lock();
        let nonce = loop {
            let nonce = fresh_nonce();
            if !pending.contains_key(&nonce) {
                break nonce;
            }
        };
        let _ = pending.insert(nonce, tx);
        PendingProbe {
            nonce,
            rx,
            probes: self.clone(),
            started: Instant::now(),
        }
    }

    /// A reply arrived. `false` when no probe waits on `nonce` (it timed out, or never existed).
    pub(crate) fn answer(&self, nonce: u128) -> bool {
        let waiter = self.0.lock().remove(&nonce);
        waiter.is_some_and(|tx| tx.send(()).is_ok())
    }

    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        self.0.lock().len()
    }
}

/// One probe, from the moment it is registered until it is answered, times out or is dropped.
pub(crate) struct PendingProbe {
    nonce: u128,
    rx: oneshot::Receiver<()>,
    probes: ServerProbes,
    started: Instant,
}

impl PendingProbe {
    pub(crate) fn nonce(&self) -> u128 {
        self.nonce
    }

    /// Waits for the reply, up to `timeout` from when the probe was registered.
    pub(crate) async fn outcome(mut self, timeout: Duration) -> ServerProbeOutcome {
        let remaining = timeout.saturating_sub(self.started.elapsed());
        match citadel_io::time::timeout(remaining, &mut self.rx).await {
            // An answer that was read only after the budget ran out did not come within it.
            Ok(Ok(())) => match self.started.elapsed() {
                rtt if rtt <= timeout => ServerProbeOutcome::Ok(rtt),
                _ => ServerProbeOutcome::Timeout,
            },
            Ok(Err(_)) => ServerProbeOutcome::Error(citadel_io::error!(
                citadel_io::ErrorCode::ServerProbeAbandoned
            )),
            Err(_) => ServerProbeOutcome::Timeout,
        }
    }
}

impl Drop for PendingProbe {
    fn drop(&mut self) {
        let _ = self.probes.0.lock().remove(&self.nonce);
    }
}

fn fresh_nonce() -> u128 {
    use citadel_io::RngCore;
    let mut bytes = [0u8; 16];
    #[cfg(not(target_family = "wasm"))]
    let mut rng = citadel_io::thread_rng();
    #[cfg(target_family = "wasm")]
    let mut rng = citadel_io::ThreadRng;
    rng.fill_bytes(&mut bytes);
    u128::from_le_bytes(bytes)
}

#[cfg(test)]
#[path = "server_probe_tests.rs"]
mod tests;
