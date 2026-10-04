//! A validated `KEEP_ALIVE` that is a liveness probe or its reply (see `proto::server_probe`).
//! Neither touches the keep-alive bookkeeping: a probe is answered at once, a reply wakes the
//! probe waiting on its nonce.

use super::includes::*;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::server_probe::{PROBE, PROBE_REPLY};
use citadel_crypt::ratchets::Ratchet;

/// Whether a validated `KEEP_ALIVE` with this `cmd_aux` belongs to a probe.
pub(crate) fn is_probe(cmd_aux: u8) -> bool {
    matches!(cmd_aux, PROBE | PROBE_REPLY)
}

pub(crate) fn process<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cmd_aux: u8,
    nonce: u128,
    ratchet: &R,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    match (cmd_aux, session.is_server) {
        (PROBE, true) => {
            let timestamp = session.time_tracker.get_global_time_ns();
            let reply = packet_crafter::keep_alive::craft_keep_alive_packet_with(
                ratchet,
                timestamp,
                security_level,
                PROBE_REPLY,
                nonce,
            );
            Ok(PrimaryProcessorResult::ReplyToSender(reply))
        }
        (PROBE_REPLY, false) => {
            if !session.server_probes.answer(nonce) {
                log::trace!(target: "citadel", "A probe reply arrived after its probe timed out");
            }
            Ok(PrimaryProcessorResult::Void)
        }
        (cmd_aux, is_server) => {
            log::warn!(target: "citadel", "Dropping a probe packet (cmd_aux {cmd_aux}) sent to the wrong side (is_server={is_server})");
            Ok(PrimaryProcessorResult::Void)
        }
    }
}
