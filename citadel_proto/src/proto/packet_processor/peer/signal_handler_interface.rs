use crate::error::NetworkError;
use async_trait::async_trait;

#[async_trait]
#[allow(dead_code)]
// TODO: 'structify' PeerSignal in order to implement this trait
// for all specific types
pub trait SignalHandler {
    async fn on_local_outbound_send(self) -> Result<(), NetworkError>;
    async fn on_server_received(self) -> Result<(), NetworkError>;
    async fn on_target_received(self) -> Result<(), NetworkError>;
}
