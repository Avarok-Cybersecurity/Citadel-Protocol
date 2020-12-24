use bytes::BytesMut;
use crate::hdp::hdp_server::Ticket;
use crate::hdp::outbound_sender::{SendError, TrySendError};
use ez_pqcrypto::prelude::Error;
use hyxe_user::misc::AccountError;
use crate::hdp::hdp_packet_processor::includes::SecBuffer;

pub mod includes {
    pub use crate::inner_arg::{InnerParameterMut, ExpectedInnerTargetMut};
    pub use std::cell::RefMut;
    pub use std::net::{IpAddr, SocketAddr};
    pub use super::super::state_container::VirtualConnectionType;
    pub use bytes::Bytes;
    pub use hyxe_crypt::sec_bytes::SecBuffer;
    pub use log::{trace, warn};
    pub use rand::prelude::ThreadRng;
    pub use rand::RngCore;
    pub use tokio::time::{Duration, Instant};
    pub use zerocopy::LayoutVerified;
    pub use hyxe_crypt::drill::SecurityLevel;
    pub use secstr::SecVec;

    pub use ez_pqcrypto::PostQuantumContainer;
    pub use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    pub use hyxe_crypt::drill::Drill;
    pub use hyxe_user::hypernode_account::HyperNodeAccountInformation;
    pub use hyxe_user::misc::AccountError;
    pub use hyxe_user::network_account::NetworkAccount;
    pub use hyxe_user::client_account::ClientNetworkAccount;

    pub use crate::constants::KEEP_ALIVE_INTERVAL_MS;
    pub use crate::hdp::{hdp_packet_crafter, validation};
    pub use crate::hdp::hdp_packet::{HdpHeader, HdpPacket};
    pub(crate) use crate::hdp::hdp_packet::packet_flags;
    pub use crate::hdp::hdp_server::HdpServerResult;
    pub use crate::hdp::hdp_session::{HdpSession, HdpSessionInner, SessionState};

    pub use super::GroupProcessorResult;
    pub use super::PrimaryProcessorResult;
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
pub mod peer_cmd_packet;
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
    /// Sends data to kernel
    /// Replies to the sender, then closes the session
    FinalReply(BytesMut),
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

impl std::ops::Try for PrimaryProcessorResult {
    type Ok = Self;
    type Error = Self;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        if self != PrimaryProcessorResult::Void {
            Ok(self)
        } else {
            Err(self)
        }
    }

    fn from_error(v: Self::Error) -> Self {
        v
    }

    fn from_ok(v: Self::Ok) -> Self {
        v
    }
}



impl From<std::option::NoneError> for PrimaryProcessorResult {
    fn from(_: std::option::NoneError) -> Self {
        PrimaryProcessorResult::Void
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

impl<T: std::fmt::Display> From<hyxe_user::misc::AccountError<T>> for PrimaryProcessorResult {
    fn from(_: AccountError<T>) -> Self {
        PrimaryProcessorResult::Void
    }
}

impl<T: std::fmt::Display> From<hyxe_crypt::misc::CryptError<T>> for PrimaryProcessorResult {
    fn from(_: hyxe_crypt::misc::CryptError<T>) -> Self {
        PrimaryProcessorResult::Void
    }
}

impl std::ops::Try for GroupProcessorResult {
    type Ok = Self;
    type Error = Self;

    fn into_result(self) -> Result<Self::Ok, GroupProcessorResult> {
        if self != GroupProcessorResult::Void {
            Ok(self)
        } else {
            Err(self)
        }
    }

    fn from_error(v: GroupProcessorResult) -> Self {
        v
    }

    fn from_ok(v: Self::Ok) -> Self {
        v
    }
}

impl From<std::option::NoneError> for GroupProcessorResult {
    fn from(_: std::option::NoneError) -> Self {
        GroupProcessorResult::Void
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