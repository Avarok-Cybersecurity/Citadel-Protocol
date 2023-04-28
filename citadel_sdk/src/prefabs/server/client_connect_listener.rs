use crate::prefabs::ClientServerRemote;
use crate::prelude::*;
use citadel_proto::prelude::async_trait;
use futures::Future;
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
    F: Fn(ConnectionSuccess, ClientServerRemote) -> Fut + Send + Sync,
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
    F: Fn(ConnectionSuccess, ClientServerRemote) -> Fut + Send + Sync,
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
            NodeResult::ConnectSuccess(ConnectSuccess {
                ticket: _,
                implicated_cid: cid,
                remote_addr: _,
                is_personal: _,
                v_conn_type: conn_type,
                services,
                welcome_message: _,
                channel,
                udp_rx_opt: udp_channel_rx,
            }) => {
                let client_server_remote = ClientServerRemote {
                    inner: self.node_remote.clone().unwrap(),
                    unprocessed_signals_rx: Default::default(),
                    conn_type,
                };
                (self.on_channel_received)(
                    ConnectionSuccess {
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
                log::trace!(target: "citadel", "Unhandled server signal: {:?}", other);
                Ok(())
            }
        }
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}
