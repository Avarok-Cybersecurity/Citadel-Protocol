use std::ops::Deref;
use std::sync::Arc;

use serde::Serialize;

use crate::command_handlers::connect::ConnectResponse;
use crate::command_handlers::disconnect::DisconnectResponse;
use crate::command_handlers::list_accounts::ActiveAccounts;
use crate::command_handlers::list_sessions::ActiveSessions;
use crate::command_handlers::peer::PeerList;
use crate::command_handlers::register::RegisterResponse;
use crate::console_error::ConsoleError;
use ser::string;
use hyxe_user::fcm::fcm_packet_processor::{FcmProcessorResult, FcmResult};
use hyxe_user::fcm::data_structures::FcmTicket;
use hyxe_user::fcm::data_structures::base64_string;

pub mod ffi_entry;

pub mod command_handler;
pub mod ser;

#[derive(Clone)]
pub struct FFIIO {
    // to send data from rust to native
    to_ffi_frontier: Arc<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>>
}

impl Deref for FFIIO {
    type Target = Arc<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>>;

    fn deref(&self) -> &Self::Target {
        &self.to_ffi_frontier
    }
}

impl From<Arc<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>>> for FFIIO {
    fn from(to_ffi_frontier: Arc<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>>) -> Self {
        Self { to_ffi_frontier }
    }
}

impl From<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>> for FFIIO {
    fn from(to_ffi_frontier: Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + Sync + 'static>) -> Self {
        Self { to_ffi_frontier: Arc::new(to_ffi_frontier) }
    }
}
// When this crate returns data to the FFI interface, the following combinations exist:
// We don't use tickets when passing between FFI Boundaries; we simply use the inner u64
// respresentation
#[derive(Debug, Serialize)]
#[serde(tag="type", content="info")]
pub enum KernelResponse {
    Confirmation,
    Message(#[serde(with = "base64_string")] Vec<u8>),
    // ticket, implicated_cid, icid (0 if HyperLAN server), peer_cid
    NodeMessage(#[serde(serialize_with = "string")] u64,#[serde(serialize_with = "string")] u64,#[serde(serialize_with = "string")] u64,#[serde(serialize_with = "string")] u64, #[serde(with = "base64_string")] Vec<u8>),
    ResponseTicket(#[serde(serialize_with = "string")] u64),
    ResponseHybrid(#[serde(serialize_with = "string")] u64, #[serde(with = "base64_string")] Vec<u8>),
    DomainSpecificResponse(DomainResponse),
    KernelShutdown(#[serde(with = "base64_string")] Vec<u8>),
    Error(#[serde(serialize_with = "string")] u64, #[serde(with = "base64_string")] Vec<u8>),
}

impl KernelResponse {
    pub fn serialize_json(&self) -> Option<Vec<u8>> {
        serde_json::to_vec(&self).ok()
    }
}

// Some branches have a very specific return type. Handle these types with
#[derive(Debug, Serialize)]
#[serde(tag="dtype")]
pub enum DomainResponse {
    GetActiveSessions(ActiveSessions),
    GetAccounts(ActiveAccounts),
    Register(RegisterResponse),
    Connect(ConnectResponse),
    Disconnect(DisconnectResponse),
    PeerList(PeerList),
    Fcm(FcmResponse)
}

#[derive(Serialize, Debug)]
pub enum FcmResponse {
    Message(FcmTicket, #[serde(with = "base64_string")] Vec<u8>),
    MessageSent(FcmTicket),
    MessageReceived(FcmTicket)
}

impl From<Result<Option<KernelResponse>, ConsoleError>> for KernelResponse {
    fn from(res: Result<Option<KernelResponse>, ConsoleError>) -> Self {
        match res {
            Ok(resp_opt) => {
                match resp_opt {
                    Some(resp) => {
                        resp
                    }

                    None => {
                        KernelResponse::Confirmation
                    }
                }
            }

            Err(err) => {
                KernelResponse::Error(0, err.into_string().into_bytes())
            }
        }
    }
}

impl From<FcmProcessorResult> for KernelResponse {
    fn from(res: FcmProcessorResult) -> Self {
        match res {
            FcmProcessorResult::Void => {
                KernelResponse::Confirmation
            }

            FcmProcessorResult::Err(err) => {
                KernelResponse::Error(0, err.into_bytes())
            }

            FcmProcessorResult::Value(fcm_res) => {
                match fcm_res {
                    FcmResult::GroupHeader { ticket, message } => {
                        KernelResponse::DomainSpecificResponse(DomainResponse::Fcm(FcmResponse::Message(ticket, message)))
                    }
                    FcmResult::GroupHeaderAck { ticket } => {
                        KernelResponse::DomainSpecificResponse(DomainResponse::Fcm(FcmResponse::MessageReceived(ticket)))
                    }
                    FcmResult::MessageSent { ticket } => {
                        KernelResponse::DomainSpecificResponse(DomainResponse::Fcm(FcmResponse::MessageSent(ticket)))
                    }
                }
            }
        }
    }
}