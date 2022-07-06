use crate::prefabs::ClientServerRemote;
use crate::prelude::{ConnectSuccess, NetKernel, NetworkError, NodeRemote, NodeResult};
use futures::Future;
use hyxe_net::prelude::async_trait;
use std::marker::PhantomData;

/// A kernel that executes a user-provided function each time
/// a client makes a connection
pub struct ClientConnectListenerKernel<F, Fut> {
    on_channel_received: F,
    node_remote: Option<NodeRemote>,
    _pd: PhantomData<Fut>,
}

impl<F, Fut> ClientConnectListenerKernel<F, Fut>
where
    F: Fn(ConnectSuccess, ClientServerRemote) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), NetworkError>> + Send + Sync,
{
    pub fn new(on_channel_received: F) -> Self {
        Self {
            on_channel_received,
            node_remote: None,
            _pd: Default::default(),
        }
    }
}

#[async_trait]
impl<F, Fut> NetKernel for ClientConnectListenerKernel<F, Fut>
where
    F: Fn(ConnectSuccess, ClientServerRemote) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), NetworkError>> + Send + Sync,
{
    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
        self.node_remote = Some(server_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError> {
        match message {
            NodeResult::ConnectSuccess(
                _,
                cid,
                _,
                _,
                conn_type,
                services,
                _,
                channel,
                udp_channel_rx,
            ) => {
                let client_server_remote = ClientServerRemote {
                    inner: self.node_remote.clone().unwrap(),
                    conn_type,
                };
                (&self.on_channel_received)(
                    ConnectSuccess {
                        channel,
                        udp_channel_rx,
                        services,
                        cid,
                    },
                    client_server_remote,
                )
                .await
            }

            other => {
                log::trace!(target: "lusna", "Unhandled server signal: {:?}", other);
                Ok(())
            }
        }
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}
