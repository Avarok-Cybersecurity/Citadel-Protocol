use bytes::BytesMut;

use ez_pqcrypto::prelude::Error;
use hyxe_user::misc::AccountError;

use crate::hdp::hdp_packet_processor::includes::SecBuffer;
use crate::hdp::hdp_server::Ticket;
use crate::hdp::outbound_sender::{SendError, TrySendError};
use crate::error::NetworkError;
use std::ops::{FromResidual, Try, ControlFlow};

pub mod includes {
    pub use std::cell::RefMut;
    pub use std::net::{IpAddr, SocketAddr};

    pub use bytes::Bytes;
    pub use log::{trace, warn};
    pub use rand::prelude::ThreadRng;
    pub use rand::RngCore;
    pub use tokio::time::{Duration, Instant};
    pub use zerocopy::LayoutVerified;

    pub use ez_pqcrypto::PostQuantumContainer;
    pub use hyxe_crypt::drill::Drill;
    pub use hyxe_crypt::drill::SecurityLevel;
    pub use hyxe_crypt::sec_bytes::SecBuffer;
    pub use hyxe_user::client_account::ClientNetworkAccount;
    pub use hyxe_user::hypernode_account::HyperNodeAccountInformation;
    pub use hyxe_user::misc::AccountError;
    pub use hyxe_user::network_account::NetworkAccount;

    pub use crate::constants::KEEP_ALIVE_INTERVAL_MS;
    pub use crate::hdp::{hdp_packet_crafter, validation};
    pub use crate::hdp::hdp_packet::{HdpHeader, HdpPacket};
    pub(crate) use crate::hdp::hdp_packet::packet_flags;
    pub use crate::hdp::hdp_server::HdpServerResult;
    pub use crate::hdp::hdp_session::{HdpSession, HdpSessionInner, SessionState};
    pub use crate::inner_arg::{ExpectedInnerTargetMut, InnerParameterMut};

    pub use super::GroupProcessorResult;
    pub use super::PrimaryProcessorResult;
    pub use super::super::state_container::VirtualConnectionType;
}

///
pub mod raw_primary_packet;
///
pub mod drill_update_packet;
///
pub mod disconnect_packet;
///
pub mod connect_packet;
///
pub mod register_packet;
///
pub mod keep_alive_packet;
///
pub mod primary_group_packet;
///
pub mod wave_group_packet;
///
pub mod deregister_packet;
///
pub mod preconnect_packet;
///
pub mod file_packet;
///
pub mod peer;

/// Allows the [HdpSession] to read results from the packet processor herein
#[derive(PartialEq)]
pub enum PrimaryProcessorResult {
    /// Do nothing
    Void,
    /// Returns some data to the sender
    ReplyToSender(BytesMut),
    /// Tells the system to shutdown
    EndSession(&'static str),
}

/// This gives a set of possible responses/actions
#[derive(PartialEq)]
pub enum GroupProcessorResult {
    /// Do nothing
    Void,
    /// Signals the session to shutdown.
    ShutdownSession(String),
    /// Sends a packet back to the sender
    ReplyToSender(BytesMut),
    /// Send an error to the kernel level
    Error(String),
    /// Send a reconstructed packet to the kernel
    SendToKernel(Ticket, SecBuffer)
}

impl Try for PrimaryProcessorResult {
    type Output = Self;
    type Residual = Self;

    fn from_output(output: Self::Output) -> Self {
        output
    }

    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        if self != PrimaryProcessorResult::Void {
            ControlFlow::Continue(self)
        } else {
            ControlFlow::Break(self)
        }
    }
}

impl FromResidual<PrimaryProcessorResult> for PrimaryProcessorResult {
    fn from_residual(residual: PrimaryProcessorResult) -> Self {
        residual
    }
}

impl<T, E: Into<PrimaryProcessorResult>> FromResidual<Result<T, E>> for PrimaryProcessorResult {
    fn from_residual(residual: Result<T, E>) -> Self {
        match residual {
            Err(err) => err.into(),
            _ => PrimaryProcessorResult::Void
        }
    }
}

impl FromResidual<GroupProcessorResult> for GroupProcessorResult {
    fn from_residual(residual: GroupProcessorResult) -> Self {
        residual
    }
}

impl<T> FromResidual<Option<T>> for PrimaryProcessorResult {
    fn from_residual(residual: Option<T>) -> Self {
        match residual {
            None => {
                log::warn!("[X-03] NoneError");
                PrimaryProcessorResult::Void
            }

            _ => {
                PrimaryProcessorResult::Void
            }
        }
    }
}

impl<T> From<TrySendError<T>> for PrimaryProcessorResult {
    fn from(_: TrySendError<T>) -> Self {
        PrimaryProcessorResult::EndSession("Outbound sender disconnected")
    }
}

impl<T> From<SendError<T>> for PrimaryProcessorResult {
    fn from(_: SendError<T>) -> Self {
        PrimaryProcessorResult::EndSession("Outbound sender disconnected")
    }
}

impl From<Error> for PrimaryProcessorResult {
    fn from(_: Error) -> Self {
        PrimaryProcessorResult::Void
    }
}

impl<T: Into<String>> From<hyxe_user::misc::AccountError<T>> for PrimaryProcessorResult {
    fn from(_: AccountError<T>) -> Self {
        PrimaryProcessorResult::Void
    }
}

impl<T: Into<String>> From<hyxe_crypt::misc::CryptError<T>> for PrimaryProcessorResult {
    fn from(_: hyxe_crypt::misc::CryptError<T>) -> Self {
        PrimaryProcessorResult::Void
    }
}

impl From<NetworkError> for PrimaryProcessorResult {
    fn from(err: NetworkError) -> Self {
        log::error!("Err occured on session, will propagate shutdown: {}", &err);
        PrimaryProcessorResult::EndSession("NetworkError triggered shutdown of session")
    }
}

impl Try for GroupProcessorResult {
    type Output = Self;
    type Residual = Self;

    fn from_output(output: Self::Output) -> Self {
        output
    }

    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        if self != GroupProcessorResult::Void {
            ControlFlow::Continue(self)
        } else {
            ControlFlow::Break(self)
        }
    }
}

impl<T> FromResidual<Option<T>> for GroupProcessorResult {
    fn from_residual(residual: Option<T>) -> Self {
        match residual {
            None => {
                log::warn!("[X-03] NoneError");
                GroupProcessorResult::Void
            }

            _ => {
                GroupProcessorResult::Void
            }
        }
    }
}

impl Into<PrimaryProcessorResult> for GroupProcessorResult {
    fn into(self) -> PrimaryProcessorResult {
        match self {
            GroupProcessorResult::Void => PrimaryProcessorResult::Void,
            GroupProcessorResult::ShutdownSession(_reason) => PrimaryProcessorResult::EndSession("Group processor signalled shutdown"),
            GroupProcessorResult::ReplyToSender(bytes) => PrimaryProcessorResult::ReplyToSender(bytes),
            GroupProcessorResult::Error(_err) => PrimaryProcessorResult::EndSession("Group processor signalled shutdown"),
            _ => PrimaryProcessorResult::Void
        }
    }
}