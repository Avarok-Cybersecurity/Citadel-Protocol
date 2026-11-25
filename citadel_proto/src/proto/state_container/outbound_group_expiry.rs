//! When the sender gives up on an outbound file-transfer group, and how the transfer then ends.
//!
//! A group is registered before its header is sent, so its answer always finds it. The answer
//! can still be lost; then nothing else would ever end the transfer. So a group whose header is
//! not answered within [`FILE_GROUP_HEADER_ACK_DEADLINE`] fails the transfer, and a group that was
//! answered but then falls silent is held to the same rule the receiver holds its open groups to
//! (see `inbound_group_bounds`). Either way the sender's handle receives
//! [`ObjectTransferStatus::Failed`] with `ErrorCode::FileTransferStalled`.

use super::inbound_group_bounds::{reclaims, INBOUND_GROUP_SILENCE_CEILING};
use super::includes::*;
use crate::constants::GROUP_EXPIRE_TIME_MS;
use crate::proto::session_queue_handler::QueueWorkerResult;
use citadel_io::{error, ErrorCode};
use citadel_types::proto::timing::FILE_GROUP_HEADER_ACK_DEADLINE;
use std::time::Duration;

/// The longest an answered group may stay silent whatever else the session carries: the ceiling
/// the receiver holds its own open groups to.
const OUTBOUND_GROUP_SILENCE_CEILING: Duration = INBOUND_GROUP_SILENCE_CEILING;

/// What one check sees of an outbound group.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OutboundGroupObservation {
    /// An earlier group of the session is still in flight, so this one's header may be queued
    /// behind that group's payload on the session's one primary stream.
    pub(crate) behind_another: bool,
    /// The receiver answered this group's header.
    pub(crate) header_answered: bool,
    /// How long the header has waited for its answer while first in line.
    pub(crate) header_waited: Duration,
    /// No wave ack (or, before the first, no answer) for [`GROUP_EXPIRE_TIME_MS`].
    pub(crate) silent: bool,
    /// The same, past [`OUTBOUND_GROUP_SILENCE_CEILING`].
    pub(crate) silent_past_ceiling: bool,
    /// The whole session has been silent for [`GROUP_EXPIRE_TIME_MS`].
    pub(crate) session_silent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutboundGroupVerdict {
    Keep,
    HeaderUnanswered,
    Silent,
}

/// Whether an outbound group is kept or its transfer failed, and why.
pub(crate) fn outbound_group_verdict(seen: OutboundGroupObservation) -> OutboundGroupVerdict {
    if !seen.header_answered {
        return if !seen.behind_another && seen.header_waited >= FILE_GROUP_HEADER_ACK_DEADLINE {
            OutboundGroupVerdict::HeaderUnanswered
        } else {
            OutboundGroupVerdict::Keep
        };
    }
    if reclaims(seen.silent, seen.silent_past_ceiling, seen.session_silent) {
        OutboundGroupVerdict::Silent
    } else {
        OutboundGroupVerdict::Keep
    }
}

impl<R: Ratchet> StateContainerInner<R> {
    /// The periodic check on an outbound group: `Complete` once the group is gone, whether it
    /// completed or its transfer was failed here; `Incomplete` while it is kept.
    pub(crate) fn check_outbound_group(
        &mut self,
        key: GroupKey,
        file_key: FileKey,
        ticket: Ticket,
        session_cid: Option<u64>,
    ) -> QueueWorkerResult {
        let Some(seen) = self.observe_outbound_group(&key) else {
            return QueueWorkerResult::Complete;
        };
        let why = match outbound_group_verdict(seen) {
            OutboundGroupVerdict::Keep => return QueueWorkerResult::Incomplete,
            OutboundGroupVerdict::HeaderUnanswered => "its header went unanswered",
            OutboundGroupVerdict::Silent => "its acks stopped",
        };
        let err = error!(ErrorCode::FileTransferStalled, key.group_id);
        log::error!(target: "citadel", "Outbound {file_key:?} ended, {why}: {err}");
        if let Some(mut transfer) = self.outbound_files.remove(&file_key) {
            transfer.halt();
        }
        self.drop_outbound_groups_of(&file_key);
        if !self.fail_object_transfer_handle_with_error(&file_key, &err) {
            log::warn!(target: "citadel", "No ObjectTransferHandle to fail for {file_key:?}");
        }
        let reported = self
            .kernel_tx
            .unbounded_send(NodeResult::InternalServerError(InternalServerError {
                ticket_opt: Some(ticket),
                cid_opt: session_cid,
                message: err.to_string(),
            }));
        if reported.is_err() {
            log::error!(target: "citadel", "[File] Unable to send kernel error signal. Ending session");
            QueueWorkerResult::EndSession
        } else {
            QueueWorkerResult::Complete
        }
    }

    /// `None` once the group is gone. While its header is unanswered and another group of the
    /// session is ahead of it, its header clock is restarted: the wait behind that group is not
    /// the receiver's to answer for.
    fn observe_outbound_group(&self, key: &GroupKey) -> Option<OutboundGroupObservation> {
        // Read under a scoped `Ref`, dropped before the map is iterated or written.
        let (registered_at, header_answered, header_waited, silent, silent_past_ceiling) = {
            let group = self.outbound_transmitters.get(key)?;
            let transmitter = group.burst_transmitter.group_transmitter.as_ref()?;
            (
                group.transmission_start_time,
                group.header_answered,
                group.header_clock_from.elapsed(),
                transmitter.has_expired(GROUP_EXPIRE_TIME_MS),
                transmitter.has_expired(OUTBOUND_GROUP_SILENCE_CEILING),
            )
        };
        let behind_another = !header_answered
            && self
                .outbound_transmitters
                .iter()
                .any(|other| other.key() != key && other.transmission_start_time < registered_at);
        if behind_another {
            if let Some(mut group) = self.outbound_transmitters.get_mut(key) {
                group.header_clock_from = Instant::now();
            }
        }
        Some(OutboundGroupObservation {
            behind_another,
            header_answered,
            header_waited,
            silent,
            silent_past_ceiling,
            session_silent: self.meta_expiry_state.expired(),
        })
    }
}

#[cfg(test)]
#[path = "outbound_group_expiry_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "outbound_group_expiry_worker_tests.rs"]
mod worker_tests;
