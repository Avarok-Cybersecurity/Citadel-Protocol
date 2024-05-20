use tokio::time::Duration;

use crate::constants::{
    DRILL_UPDATE_FREQUENCY_DIVINE_BASE, DRILL_UPDATE_FREQUENCY_HIGH_BASE,
    DRILL_UPDATE_FREQUENCY_LOW_BASE, DRILL_UPDATE_FREQUENCY_MEDIUM_BASE,
    DRILL_UPDATE_FREQUENCY_ULTRA_BASE,
};
use crate::error::NetworkError;
use crate::prelude::{NodeResult, ReKeyResult, ReKeyReturnType, Ticket, VirtualTargetType};
use crate::proto::outbound_sender::UnboundedSender;
use crate::proto::transfer_stats::TransferStats;
use citadel_crypt::stacked_ratchet::constructor::StackedRatchetConstructor;
use std::collections::HashMap;

#[derive(Default)]
pub struct RatchetUpdateState {
    pub alice_hyper_ratchet: Option<StackedRatchetConstructor>,
    pub p2p_updates: HashMap<u64, StackedRatchetConstructor>,
    // if this is present (in the case of manual mode), an alert will be sent
    // to the kernel once the re-key has finished
    pub current_local_requests: HashMap<VirtualTargetType, Ticket>,
}

impl RatchetUpdateState {
    pub(crate) fn on_complete(
        &mut self,
        v_conn_type: VirtualTargetType,
        to_kernel_tx: &UnboundedSender<NodeResult>,
        status: ReKeyReturnType,
    ) -> Result<(), NetworkError> {
        if let Some(ticket) = self.current_local_requests.remove(&v_conn_type) {
            to_kernel_tx
                .unbounded_send(NodeResult::ReKeyResult(ReKeyResult {
                    ticket,
                    status,
                    implicated_cid: v_conn_type.get_implicated_cid(),
                }))
                .map_err(|err| NetworkError::Generic(err.to_string()))
        } else {
            Ok(())
        }
    }
}

/// Calculates the frequency, in nanoseconds per update
pub fn calculate_update_frequency(security_level: u8, _transfer_stats: &TransferStats) -> Duration {
    match security_level {
        0 => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_LOW_BASE),

        1 => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_MEDIUM_BASE),

        2 => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_HIGH_BASE),

        3 => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_ULTRA_BASE),

        _ => Duration::from_nanos(DRILL_UPDATE_FREQUENCY_DIVINE_BASE),
    }
}
