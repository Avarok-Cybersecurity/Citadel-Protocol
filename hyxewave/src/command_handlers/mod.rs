mod imports {
    pub use std::path::PathBuf;
    pub use std::str::FromStr;
    pub use std::sync::atomic::Ordering;

    pub use clap::ArgMatches;
    pub use prettytable::*;

    pub use hyxe_net::constants::{DO_CONNECT_EXPIRE_TIME_MS, DO_REGISTER_EXPIRE_TIME_MS};
    pub use hyxe_net::hdp::hdp_packet_processor::includes::{Bytes, Duration, HyperNodeAccountInformation, IpAddr, SecurityLevel};
    pub use hyxe_net::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
    pub use hyxe_net::hdp::hdp_server::{HdpServerRemote, HdpServerRequest};
    pub use hyxe_net::hdp::peer::peer_layer::{HypernodeConnectionType, PeerConnectionType, PeerResponse, PeerSignal};
    pub use hyxe_net::hdp::state_container::{VirtualConnectionType, VirtualTargetType};
    pub use hyxe_user::proposed_credentials::ProposedCredentials;

    pub use crate::console::console_context::ConsoleContext;
    pub use crate::console::virtual_terminal::AppThreadSafe;
    pub use crate::console_error::ConsoleError;
    pub use crate::constants::{CREATE_GROUP_TIMEOUT, DEREGISTER_TIMEOUT, DISCONNECT_TIMEOUT, GET_REGISTERED_USERS_TIMEOUT, POST_REGISTER_TIMEOUT};
    pub use crate::ticket_event::CallbackStatus;
    pub use crate::mail::IncomingPeerRequest;
    pub use crate::shutdown_sequence;
    pub use hyxe_user::prelude::ClientNetworkAccount;
    pub use hyxe_net::hdp::hdp_server::Ticket;
    pub use crate::ffi::KernelResponse;
    pub use crate::kernel::KernelSession;
    pub use crate::ffi::{DomainResponse, FFIIO};
    pub use serde::Serialize;
    pub use crate::ffi::ser::{string, string_vec};
    pub use super::super::console::virtual_terminal::INPUT_ROUTER;
    use hyxe_user::account_manager::AccountManager;

    pub async fn get_cid_from_str(acc_mgr: &AccountManager, input: &str) -> Result<ClientNetworkAccount, ConsoleError> {
        let is_numeric = input.chars().all(|c| char::is_numeric(c));
        if is_numeric {
            acc_mgr.get_client_by_cid(u64::from_str(input).map_err(|err| ConsoleError::Generic(err.to_string()))?).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.ok_or(ConsoleError::Default("Username does not map to a local client"))
        } else {
            acc_mgr.get_client_by_username(input).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.ok_or(ConsoleError::Default("Username does not map to a local client"))
        }
    }

    pub async fn get_peer_cid_from_cnac(acc_mgr: &AccountManager, ctx_user: u64, target_cid: &str) -> Result<u64, ConsoleError> {
        let is_numeric = target_cid.chars().all(|c| char::is_numeric(c));

        let res = if is_numeric {
            let target_cid = u64::from_str(target_cid).map_err(|err| ConsoleError::Generic(err.to_string()))?;
            acc_mgr.get_persistence_handler().get_hyperlan_peer_by_cid(ctx_user, target_cid).await
        } else {
            acc_mgr.get_persistence_handler().get_hyperlan_peer_by_username(ctx_user, target_cid).await
        };

        res.map_err(|err| ConsoleError::Generic(err.into_string()))?.ok_or(ConsoleError::Default("Peer not found")).map(|r| r.cid)
    }

    pub fn parse_security_level(arg_matches: &ArgMatches) -> Result<SecurityLevel, ConsoleError> {
        if let Ok(security_level) = usize::from_str(arg_matches.value_of("security").unwrap()) {
            if let Some(security_level) = SecurityLevel::for_value(security_level) {
                return Ok(security_level);
            }
        }

        Err(ConsoleError::Default("Invalid security level. Please enter a value 0 (LOW) <= n <= 256 (HIGHEST)"))
    }
}

pub mod group;

pub mod send;

pub mod waitfor;

pub mod quit;

pub mod list_sessions;

pub mod list_accounts;

pub mod list_algorithms;

pub mod switch;

pub mod connect;

pub mod register;

pub mod deregister;

pub mod peer;

pub mod disconnect;

pub mod os;

pub mod fcm_process;

pub mod ticket;

pub mod resync;