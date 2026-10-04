//! [`ProtocolRemoteExt::probe_server`](crate::prelude::ProtocolRemoteExt::probe_server).

use crate::prelude::*;
use futures::StreamExt;
use std::time::Duration;

pub(crate) async fn probe_server<R: Ratchet, Rem: Remote<R>>(
    remote: &Rem,
    cid: u64,
    timeout: Duration,
) -> ServerProbeOutcome {
    let request = NodeRequest::ProbeServer(ProbeServer {
        session_cid: cid,
        timeout,
    });
    let mut results = match remote.send_callback_subscription(request).await {
        Ok(results) => results,
        Err(err) => return ServerProbeOutcome::Error(err),
    };
    while let Some(result) = results.next().await {
        if let NodeResult::ServerProbe(result) = result {
            return result.outcome;
        }
    }
    ServerProbeOutcome::Error(citadel_io::error!(
        citadel_io::ErrorCode::RemoteKernelStreamDied,
        "probe_server"
    ))
}
