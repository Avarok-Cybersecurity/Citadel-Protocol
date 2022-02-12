use async_trait::async_trait;
use crate::prelude::{NodeRemote, HdpServerResult};
use std::net::SocketAddr;
use crate::error::NetworkError;
use tokio::sync::mpsc::UnboundedSender;

pub use crate::hdp::hdp_node::HdpServer;

#[async_trait]
pub trait TestingCoKernel: Send + Sync + 'static {
    /// A socket address is only passed if the receiving node is a peer
    async fn on_start(&self, server_remote: NodeRemote, server_address: Option<SocketAddr>, stop_server_tx: Option<UnboundedSender<()>>) -> Result<(), NetworkError>;
    async fn on_server_message_received(&self, message: HdpServerResult) -> Result<(), NetworkError>;
    async fn on_stop(self) -> Result<(), NetworkError>;
}

pub mod base_kernel {
    use async_trait::async_trait;
    use crate::prelude::*;
    use tokio::sync::oneshot::{Sender, Receiver};
    use std::net::SocketAddr;
    use crate::test_common::TestingCoKernel;
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
    use parking_lot::Mutex;

    pub struct TestingServerKernel<CoKernel>(pub Mutex<Option<Sender<SocketAddr>>>, pub Mutex<Option<UnboundedReceiver<()>>>, pub CoKernel, Option<NodeRemote>);

    pub fn generate_endpoint_test_kernels<ServerCoKernel: TestingCoKernel, ClientCoKernel: TestingCoKernel>(s: ServerCoKernel, c: ClientCoKernel) -> (TestingServerKernel<ServerCoKernel>, TestingClientKernel<ClientCoKernel>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (tx_stop, rx_stop) = tokio::sync::mpsc::unbounded_channel();

        (TestingServerKernel(Mutex::new(Some(tx)), Mutex::new(Some(rx_stop)), s, None), TestingClientKernel(Mutex::new(Some(rx)), Mutex::new(Some(tx_stop)), None,c))
    }

    #[async_trait]
    impl<CoKernel: TestingCoKernel> NetKernel for TestingServerKernel<CoKernel> {
        fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
            self.3 = Some(server_remote);
            Ok(())
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            let server_remote = self.3.clone().unwrap();
            self.0.lock().take().unwrap().send(server_remote.local_node_type().bind_addr().unwrap()).unwrap();

            let mut remote2 = server_remote.clone();
            let mut shutdown_rx = self.1.lock().take().unwrap();

            let _ = tokio::spawn(async move {
                shutdown_rx.recv().await.unwrap();
                remote2.shutdown().await.unwrap()
            });

            self.2.on_start(server_remote, None, None).await
        }

        async fn on_node_event_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
            self.2.on_server_message_received(message).await
        }

        async fn on_stop(self) -> Result<(), NetworkError> {
            self.2.on_stop().await
        }
    }

    pub struct TestingClientKernel<CoKernel>(pub Mutex<Option<Receiver<SocketAddr>>>, pub Mutex<Option<UnboundedSender<()>>>, Option<NodeRemote>, pub CoKernel);

    #[async_trait]
    impl<CoKernel: TestingCoKernel> NetKernel for TestingClientKernel<CoKernel> {
        fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
            self.2 = Some(server_remote);
            Ok(())
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            let (server_remote, server_addr, stop_server_tx) = {
                let rx = {
                    self.0.lock().take().unwrap()
                };

                let server_addr = rx.await.unwrap();
                log::info!("Server addr obtained: {}", server_addr);
                let stop_server_tx = self.1.lock().take().unwrap();
                let server_remote = self.2.clone().unwrap();
                (server_remote, server_addr, stop_server_tx)
            };

            self.3.on_start(server_remote, Some(server_addr), Some(stop_server_tx)).await
        }

        async fn on_node_event_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
            self.3.on_server_message_received(message).await
        }

        async fn on_stop(self) -> Result<(), NetworkError> {
            self.3.on_stop().await
        }
    }
}