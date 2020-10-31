use std::str::FromStr;

use async_trait::async_trait;
use tokio::time::Duration;

use hyxe_crypt::drill::SecurityLevel;
use hyxe_user::hypernode_account::HyperNodeAccountInformation;

use crate::error::NetworkError;
use crate::hdp::hdp_server::{HdpServerRemote, HdpServerRequest, HdpServerResult};
use crate::proposed_credentials::ProposedCredentials;
use crate::hdp::state_container::VirtualConnectionType;
use crate::hdp::hdp_packet_processor::includes::IpAddr;

/// The [Kernel] is the thread-safe interface between the single-threaded async
/// [HdpServer] and the multithreaded higher-level
#[async_trait]
pub trait Kernel where Self: Send + Sync {
    /// when the kernel executes, it will be given a handle to the server
    async fn on_start(&mut self, server_remote: HdpServerRemote) -> Result<(), NetworkError>;
    /// When the server processes a valid entry, the value is sent here
    async fn on_server_message_received(&mut self, message: HdpServerResult) -> Result<(), NetworkError>;
    /// The [KernelExecutor] must know when to stop the underlying server for a safe shutdown. In the event loop,
    /// `can_run` is polled periodically to determine if the Kernel even needs the server to keep running
    async fn can_run(&self) -> bool;
    /// When it's time to shutdown, this function is called
    async fn on_stop(&mut self) -> Result<(), NetworkError>;
}

/// Dummy kernel. The bool, if true, will register before connecting
pub struct DummyKernel(pub Option<HdpServerRemote>, pub String, pub Option<ProposedCredentials>, pub bool);

#[async_trait]
impl Kernel for DummyKernel {
    async fn on_start(&mut self, server_remote: HdpServerRemote) -> Result<(), NetworkError> {
        log::info!("DummyKernel has started!");
        if !self.1.contains("127.0.0.1") && self.3 {
            log::info!("Local is {} ... Attempting to register to 127.0.0.1 ...", &self.1);
            let _ticket = server_remote.unbounded_send(HdpServerRequest::RegisterToHypernode(IpAddr::from_str("127.0.0.1").unwrap(), self.2.clone().unwrap(), None));
        }

        if !self.3 {
            log::info!("Will connect directly ...");
            let _ticket = server_remote.unbounded_send(HdpServerRequest::ConnectToHypernode(IpAddr::from_str("127.0.0.1").unwrap(), 1234, self.2.take().unwrap(), SecurityLevel::LOW, None, None, None));
        }

        self.0 = Some(server_remote);

        Ok(())
    }

    async fn on_server_message_received(&mut self, message: HdpServerResult) -> Result<(), NetworkError> {
        match message {
            HdpServerResult::RegisterOkay(_ticket, cnac, message) => {
                let welcome_message = String::from_utf8(message).unwrap();
                log::info!("REGISTER SUCCESS! CNAC ID: {}. Welcome message:\n|:::|{}|:::|", cnac.get_id(), welcome_message);
                let remote = self.0.as_ref().unwrap();
                log::info!("Attempting to connect now ...");
                let _ticket = remote.unbounded_send(HdpServerRequest::ConnectToHypernode(IpAddr::from_str("127.0.0.1").unwrap(), cnac.get_id(), self.2.take().unwrap(), SecurityLevel::LOW, None, None, None));
            }

            HdpServerResult::ConnectSuccess(ticket, cid, _ip, _is_personal, _cxn_type, welcome_message) => {
                log::info!("Connection {:?} w/ CID {} success! Welcome message: {}", ticket, cid, welcome_message);
                tokio::time::delay_for(Duration::from_millis(2000)).await;
                //let _dc_ticket = self.0.as_ref().unwrap().send(HdpServerRequest::Disconnect(cid, VirtualConnectionType::HyperLANPeerToHyperLANServer(cid)));
                //let _dou_ticket = self.0.as_ref().unwrap().send(HdpServerRequest::UpdateDrill(cid));
                let _deregister_ticket = self.0.as_ref().unwrap().unbounded_send(HdpServerRequest::DeregisterFromHypernode(cid, VirtualConnectionType::HyperLANPeerToHyperLANServer(cid)));
            }

            HdpServerResult::Disconnect(ticket, _cid,_succeeded, _virt_opt, reason) => {
                log::info!("Connection {:?} disconnected. Reason: {}", ticket, reason);
            }

            message => {
                log::info!("Message from HdpServer received: {:?}", message);
            }
        }

        Ok(())
    }

    async fn can_run(&self) -> bool {
        true
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        log::info!("Kernel has received a shutdown signal. Ending ...");
        Ok(())
    }
}