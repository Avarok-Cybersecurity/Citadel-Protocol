use net_sync::reliable_conn::ReliableOrderedConnectionToTarget;
use std::pin::Pin;
use futures::Future;
use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedUdpSocket;
use std::task::{Context, Poll};
use crate::nat_identification::NatType;
use std::time::Duration;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::udp_traversal::multi::DualStackUdpHolePuncher;
use net_sync::sync::network_endpoint::NetworkEndpoint;

pub struct UdpHolePuncher<'a> {
    driver: Pin<Box<dyn Future<Output=Result<HolePunchedUdpSocket, anyhow::Error>> + 'a>>
}

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(3500);

impl<'a> UdpHolePuncher<'a> {
    pub fn new<T: ReliableOrderedConnectionToTarget + 'static>(conn: &'a NetworkEndpoint<T>, encrypted_config_container: EncryptedConfigContainer) -> Self {
        Self::new_timeout(conn, encrypted_config_container, DEFAULT_TIMEOUT)
    }

    pub fn new_timeout<T: ReliableOrderedConnectionToTarget + 'static>(conn: &'a NetworkEndpoint<T>, encrypted_config_container: EncryptedConfigContainer, timeout: Duration) -> Self {
        Self { driver: Box::pin(async move {
            tokio::time::timeout(timeout, driver(conn, encrypted_config_container)).await?
        }) }
    }
}

impl Future for UdpHolePuncher<'_> {
    type Output = Result<HolePunchedUdpSocket, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.driver.as_mut().poll(cx)
    }
}

async fn driver<T: ReliableOrderedConnectionToTarget + 'static>(conn: &NetworkEndpoint<T>, encrypted_config_container: EncryptedConfigContainer) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    let ref nat_type = NatType::identify().await.map_err(|err| anyhow::Error::msg(err.to_string()))?;
    log::info!("[driver] Local NAT type: {:?}", &nat_type);
    let internal_bind_port = conn.local_addr()?.port();

    let (peer_nat_type, peer_internal_bind_port ) = conn.sync_exchange_payload((nat_type.clone(), internal_bind_port)).await?;
    log::info!("[driver] Synchronized; will now execute dualstack hole-puncher ...");
    DualStackUdpHolePuncher::new(conn.node_type(), encrypted_config_container, &conn.subscribe_internal().await?, nat_type, &peer_nat_type, peer_internal_bind_port, 0)?.await
}

pub trait EndpointHolePunchExt {
    fn begin_udp_hole_punch(&self, encrypted_config_container: EncryptedConfigContainer) -> UdpHolePuncher;
}

impl<T: ReliableOrderedConnectionToTarget + 'static> EndpointHolePunchExt for NetworkEndpoint<T> {
    fn begin_udp_hole_punch(&self, encrypted_config_container: EncryptedConfigContainer) -> UdpHolePuncher {
        UdpHolePuncher::new(self, encrypted_config_container)
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::future::Future;
    use std::task::{Context, Poll};
    use net_sync::sync::test_utils::create_streams;
    use crate::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        //std::env::set_var("RUST_LOG", "error");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn dual_hole_puncher_join() {
        setup_log();

        let (server_stream, client_stream) = create_streams().await;

        let server = AssertSendSafeFuture::new(async move { server_stream.clone().net_join(async move {
                let res = server_stream.begin_udp_hole_punch(Default::default()).await.unwrap();
                log::info!("Server res: {:?}", res);
                res
            }).await
        });

        let client = AssertSendSafeFuture::new(async move { client_stream.clone().net_join(async move {
            let res = client_stream.begin_udp_hole_punch(Default::default()).await.unwrap();
            log::info!("Client res: {:?}", res);
            res
        }).await});

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);
        let (res0, res1) = tokio::join!(server, client);
        log::info!("JOIN complete!");
        let (res0, res1) = (res0.unwrap(), res1.unwrap());
        let (res0, res1) = (res0.unwrap(), res1.unwrap());
        assert!(res0.value.is_some() && res1.value.is_some());
    }

    #[tokio::test]
    async fn dual_hole_puncher_select_ok() {
        setup_log();

        let (server_stream, client_stream) = create_streams().await;

        let server = AssertSendSafeFuture::new(async move { server_stream.clone().net_select_ok(async move {
            server_stream.begin_udp_hole_punch(Default::default()).await
        }).await});

        let client = AssertSendSafeFuture::new(async move { client_stream.clone().net_select_ok(async move {
            client_stream.begin_udp_hole_punch(Default::default()).await
        }).await});

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);
        let (res0, res1) = tokio::join!(server, client);
        log::info!("SELECT_OK complete!");
        let (res0, res1) = (res0.unwrap(), res1.unwrap());
        let (res0, res1) = (res0.unwrap(), res1.unwrap());
        assert!(res0.result.is_some() || res1.result.is_some());
    }

    struct AssertSendSafeFuture<'a, Out: 'a>(Pin<Box<dyn Future<Output=Out> + 'a>>);

    unsafe impl<'a, Out: 'a> Send for AssertSendSafeFuture<'a, Out> {}

    impl<'a, Out: 'a> AssertSendSafeFuture<'a, Out> {
        /// Wraps a future, asserting it is safe to use in a multithreaded context at the possible cost of race conditions, locks, etc
        pub fn new(fx: impl Future<Output=Out> + 'a) -> Self {
            Self(Box::pin(fx))
        }
    }

    impl<'a, Out: 'a> Future for AssertSendSafeFuture<'a, Out> {
        type Output = Out;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.0.as_mut().poll(cx)
        }
    }
}