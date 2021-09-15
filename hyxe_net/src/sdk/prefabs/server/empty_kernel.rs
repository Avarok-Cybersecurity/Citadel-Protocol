use crate::prelude::NetKernel;
use crate::hdp::hdp_server::HdpServerRemote;
use crate::error::NetworkError;
use crate::hdp::hdp_packet_processor::includes::HdpServerResult;
use async_trait::async_trait;

/// A kernel that does nothing to events in the protocol, nor does it cause any requests. A server that allows any and all connections with no special handlers would benefit from the use of this kernel.
/// This should never be used for peers/clients, since to do so would deny the possibility of making outgoing connections
pub struct EmptyKernel;

#[async_trait]
impl NetKernel for EmptyKernel {
    fn load_remote(&mut self, _server_remote: HdpServerRemote) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_server_message_received(&self, _message: HdpServerResult) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_stop(self) -> Result<(), NetworkError> {
        Ok(())
    }
}