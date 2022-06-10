use hyxe_net::prelude::*;

/// A kernel that does nothing to events in the protocol, nor does it cause any requests. A server that allows any and all connections with no special handlers would benefit from the use of this kernel.
/// This should never be used for interacting with peers/clients from the server, since to do so would deny the possibility of interacting with channels.
#[derive(Default)]
pub struct EmptyKernel;

#[async_trait]
impl NetKernel for EmptyKernel {
    fn load_remote(&mut self, _server_remote: NodeRemote) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(&self, _message: NodeResult) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}