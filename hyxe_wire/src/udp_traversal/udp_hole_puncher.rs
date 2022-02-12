use std::pin::Pin;
use futures::Future;
use crate::udp_traversal::targetted_udp_socket_addr::HolePunchedUdpSocket;
use std::task::{Context, Poll};
use crate::nat_identification::NatType;
use std::time::Duration;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::udp_traversal::multi::DualStackUdpHolePuncher;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::reliable_conn::ConnAddr;

pub struct UdpHolePuncher<'a> {
    driver: Pin<Box<dyn Future<Output=Result<HolePunchedUdpSocket, anyhow::Error>> + Send + 'a>>
}

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(3500);

impl<'a> UdpHolePuncher<'a> {
    pub fn new(conn: &'a NetworkEndpoint, encrypted_config_container: EncryptedConfigContainer) -> Self {
        Self::new_timeout(conn, encrypted_config_container, DEFAULT_TIMEOUT)
    }

    pub fn new_timeout(conn: &'a NetworkEndpoint, encrypted_config_container: EncryptedConfigContainer, timeout: Duration) -> Self {
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

async fn driver(conn: &NetworkEndpoint, encrypted_config_container: EncryptedConfigContainer) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    let local_addr = conn.local_addr()?;
    let peer_addr = conn.peer_addr()?;
    let internal_bind_port = local_addr.port();

    let ref nat_type = NatType::identify(local_addr.ip()).await.map_err(|err| anyhow::Error::msg(err.to_string()))?;
    log::info!("[driver] Local NAT type: {:?}", &nat_type);


    let (peer_nat_type, peer_internal_bind_port ) = conn.sync_exchange_payload((nat_type.clone(), internal_bind_port)).await?;
    log::info!("[driver] Synchronized; will now execute dualstack hole-puncher ...");
    DualStackUdpHolePuncher::new(conn.node_type(), encrypted_config_container, &conn.initiate_subscription().await?, local_addr, peer_addr, nat_type, &peer_nat_type, peer_internal_bind_port, 0)?.await
}

pub trait EndpointHolePunchExt {
    fn begin_udp_hole_punch(&self, encrypted_config_container: EncryptedConfigContainer) -> UdpHolePuncher;
}

impl EndpointHolePunchExt for NetworkEndpoint {
    fn begin_udp_hole_punch(&self, encrypted_config_container: EncryptedConfigContainer) -> UdpHolePuncher {
        UdpHolePuncher::new(self, encrypted_config_container)
    }
}

#[cfg(test)]
mod tests {
    use crate::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
    use netbeam::sync::test_utils::create_streams_with_addrs;

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

        let (server_stream, client_stream) = create_streams_with_addrs().await;

        let server = async move { server_stream.clone().net_join(async move {
                let res = server_stream.begin_udp_hole_punch(Default::default()).await.unwrap();
                log::info!("Server res: {:?}", res);
                res
            }).await
        };

        let client = async move { client_stream.clone().net_join(async move {
            let res = client_stream.begin_udp_hole_punch(Default::default()).await.unwrap();
            log::info!("Client res: {:?}", res);
            res
        }).await};

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

        let (server_stream, client_stream) = create_streams_with_addrs().await;

        let server = async move { server_stream.clone().net_select_ok(async move {
            server_stream.begin_udp_hole_punch(Default::default()).await
        }).await};

        let client = async move { client_stream.clone().net_select_ok(async move {
            client_stream.begin_udp_hole_punch(Default::default()).await
        }).await};

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);
        let (res0, res1) = tokio::join!(server, client);
        log::info!("SELECT_OK complete!");
        let (res0, res1) = (res0.unwrap(), res1.unwrap());
        let (res0, res1) = (res0.unwrap(), res1.unwrap());
        assert!(res0.result.is_some() || res1.result.is_some());
    }
}