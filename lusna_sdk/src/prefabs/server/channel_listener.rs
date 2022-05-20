use std::marker::PhantomData;
use crate::prelude::{ConnectSuccess, NetworkError, NetKernel, NodeRemote, HdpServerResult};
use crate::prefabs::ClientServerRemote;
use futures::Future;
use hyxe_net::prelude::async_trait;

/// A kernel that executes a user-provided function each time
/// a client makes a connection
pub struct ChannelListenerKernel<F, Fut> {
    on_channel_received: F,
    node_remote: Option<NodeRemote>,
    _pd: PhantomData<Fut>
}

impl<F, Fut> ChannelListenerKernel<F, Fut>
    where
        F: Fn(ConnectSuccess, ClientServerRemote) -> Fut + Send + Sync + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + Sync + 'static {

    pub fn new(on_channel_received: F) -> Self {
        Self { on_channel_received, node_remote: None, _pd: Default::default() }
    }
}

#[async_trait]
impl<F, Fut> NetKernel for ChannelListenerKernel<F, Fut>
    where
        F: Fn(ConnectSuccess, ClientServerRemote) -> Fut + Send + Sync + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + Sync + 'static {

    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
        self.node_remote = Some(server_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
        match message {
            HdpServerResult::ConnectSuccess(_, cid, _, _, conn_type,_,services,_,channel, udp_channel_rx) => {
                let client_server_remote = ClientServerRemote { inner: self.node_remote.clone().unwrap(), conn_type };
                (&self.on_channel_received)(ConnectSuccess {
                    channel,
                    udp_channel_rx,
                    services,
                    cid
                }, client_server_remote).await
            },

            other => {
                log::info!("Unhandled server signal: {:?}", other);
                Ok(())
            }
        }
    }

    async fn on_stop(self) -> Result<(), NetworkError> {
        Ok(())
    }
}