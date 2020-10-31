use std::sync::Arc;
use crate::console_error::ConsoleError;
use std::ops::Deref;
use crate::command_handlers::list_sessions::ActiveSessions;
use crate::command_handlers::connect::ConnectResponse;
use crate::command_handlers::register::RegisterResponse;
use crate::command_handlers::list_accounts::ActiveAccounts;
use serde::Serialize;
use crate::command_handlers::disconnect::DisconnectResponse;
use crate::command_handlers::peer::PeerList;

pub mod ffi_entry;

pub mod command_handler;

#[derive(Clone)]
pub struct FFIIO {
    // to send data from rust to native
    to_ffi_frontier: Arc<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + 'static>>
}

unsafe impl Send for FFIIO {}
/// Safety note: For JNI, each thread gets its thread-local pointer to the JVM. For now, we are okay.
/// however, in the future, to_ffi_frontier should be protected with a Mutex to cover all cases.
unsafe impl Sync for FFIIO {}

impl Deref for FFIIO {
    type Target = Arc<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + 'static>>;

    fn deref(&self) -> &Self::Target {
        &self.to_ffi_frontier
    }
}

impl From<Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send + 'static>> for FFIIO {
    fn from(input: Box<dyn Fn(Result<Option<KernelResponse>, ConsoleError>) + Send>) -> Self {
        Self { to_ffi_frontier: Arc::new(input) }
    }
}
// When this crate returns data to the FFI interface, the following combinations exist:
// We don't use tickets when passing between FFI Boundaries; we simply use the inner u64
// respresentation
#[derive(Debug, Serialize)]
#[serde(tag="type", content="info")]
pub enum KernelResponse {
    Confirmation,
    Message(String),
    // ticket, implicated_cid, icid (0 if HyperLAN server), peer_cid
    NodeMessage(u64, u64, u64, u64, String),
    ResponseTicket(u64),
    ResponseHybrid(u64, String),
    DomainSpecificResponse(DomainResponse),
    Error(u64, String),
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
    PeerList(PeerList)
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
                KernelResponse::Error(0, err.into_string())
            }
        }
    }
}