//! The client session's side of a liveness probe (see `proto::server_probe`).

use crate::error::NetworkError;
use crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::node_result::NodeResult;
use crate::proto::packet_crafter;
use crate::proto::remote::Ticket;
use crate::proto::server_probe::{
    server_answers_probes, ServerProbeOutcome, ServerProbeResult, PROBE,
};
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Duration;
use citadel_io::{error, ErrorCode};
use citadel_types::crypto::SecurityLevel;

impl<R: Ratchet, T: PlatformOps> CitadelSession<R, T> {
    /// Sends a probe now and reports how it ended to the kernel under `ticket`, within `timeout`.
    /// Every path ends in exactly one [`NodeResult::ServerProbe`].
    pub(crate) fn probe_server(&self, ticket: Ticket, timeout: Duration) {
        let session_cid = self.session_cid.get().unwrap_or(0);
        let kernel_tx = self.kernel_tx.clone();
        let report = move |outcome: ServerProbeOutcome| {
            let result = ServerProbeResult {
                ticket,
                session_cid,
                outcome,
            };
            if kernel_tx
                .unbounded_send(NodeResult::ServerProbe(result))
                .is_err()
            {
                log::warn!(target: "citadel", "Kernel gone before a server probe's outcome could be delivered");
            }
        };
        match self.send_probe() {
            Ok(probe) => {
                spawn!(async move { report(probe.outcome(timeout).await) });
            }
            Err(err) => report(ServerProbeOutcome::Error(err)),
        }
    }

    fn send_probe(&self) -> Result<crate::proto::server_probe::PendingProbe, NetworkError> {
        let session_cid = self.session_cid.get().unwrap_or(0);
        if self.is_server || !self.state.is_connected() {
            return Err(error!(ErrorCode::ServerProbeNotConnected, session_cid));
        }
        let adjacent_version = inner_state!(self.state_container).adjacent_protocol_version;
        if !server_answers_probes(adjacent_version) {
            return Err(error!(
                ErrorCode::ServerProbeUnsupported,
                citadel_io::Dbg(adjacent_version)
            ));
        }
        let to_primary_stream = self
            .to_primary_stream
            .clone()
            .ok_or_else(|| error!(ErrorCode::ServerProbeNotConnected, session_cid))?;
        let probe = self.server_probes.begin();
        if let Some(pinger) = inner!(self.ws_pinger).as_ref() {
            let _ = pinger.ping();
        }
        let timestamp = self.time_tracker.get_global_time_ns();
        EndpointCryptoAccessor::C2S(self.state_container.clone()).borrow_hr(None, |hr, _| {
            let packet = packet_crafter::keep_alive::craft_keep_alive_packet_with(
                hr,
                timestamp,
                SecurityLevel::Standard,
                PROBE,
                probe.nonce(),
            );
            to_primary_stream
                .unbounded_send(packet)
                .map_err(|err| error!(ErrorCode::KeepAliveSendFailed, err.to_string()))
        })??;
        Ok(probe)
    }
}
