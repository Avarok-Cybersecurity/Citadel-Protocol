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
use tokio::net::UdpSocket;
use crate::udp_traversal::hole_punch_config::HolePunchConfig;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;

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
    let ref local_nat_type = NatType::identify().await.map_err(|err| anyhow::Error::msg(err.to_string()))?;

    // exchange information
    let ref stream = conn.initiate_subscription().await?;
    stream.send_serialized(local_nat_type).await?;
    let ref peer_nat_type = stream.recv_serialized::<NatType>().await?;

    log::info!("[driver] Local NAT type: {:?}", local_nat_type);
    let local_initial_socket = get_optimal_bind_socket(local_nat_type, peer_nat_type)?;
    let internal_bind_port = local_initial_socket.local_addr()?.port();

    // exchange internal bind port, also synchronizing the beginning of the hole punch process
    // while doing so
    let peer_internal_bind_port = conn.sync_exchange_payload(internal_bind_port).await?;

    // the next functions takes everything insofar obtained into account without causing collisions with any existing
    // connections (e.g., no conflicts with the primary stream existing in conn)
    let hole_punch_config = HolePunchConfig::new(local_nat_type, &peer_nat_type, local_initial_socket, peer_internal_bind_port)?;
    log::info!("[driver] Synchronized; will now execute dualstack hole-puncher ... config: {:?}", hole_punch_config);
    let res = DualStackUdpHolePuncher::new(conn.node_type(), encrypted_config_container, hole_punch_config, conn)?.await;
    res
}

/// since the NAT traversal process always ensures that both public-facing and loopback
/// cases are covered, we can start by binding to 0.0.0.0, knowing that 127.0.0.1 will
/// also be covered automatically
///
/// Suppose A binds to ipv6 addr, and B binds to ipv4 addr, then B cannot send packets to
/// A. Only A can send to B via ipv4-mapped-v6 addrs. In order for B to send packets back to A,
/// B will need the ipv4 address of A.
fn get_optimal_bind_socket(local_nat_info: &NatType, peer_nat_info: &NatType) -> Result<UdpSocket, anyhow::Error> {
    let mut local_has_an_external_ipv6_addr = false;
    let mut peer_has_an_external_ipv6_addr = false;

    if let Some(other_info) = local_nat_info.ip_addr_info() {
        if other_info.external_ipv6.is_some() {
            local_has_an_external_ipv6_addr = true;
        }
    }

    if let Some(other_info) = peer_nat_info.ip_addr_info() {
        if other_info.external_ipv6.is_some() {
            peer_has_an_external_ipv6_addr = true;
        }
    }

    let local_allows_ipv6 = local_nat_info.is_ipv6_compatible();
    let peer_allows_ipv6 = peer_nat_info.is_ipv6_compatible();

    // only bind to ipv6 if v6 is enabled locally, and, there both nodes have an external ipv6 addr,
    // AND, the peer allows ipv6, then go with ipv6
    if local_allows_ipv6 && local_has_an_external_ipv6_addr && peer_has_an_external_ipv6_addr && peer_allows_ipv6 {
        // bind to IN_ADDR6_ANY. Allows both conns from loopback and public internet
        crate::socket_helpers::get_udp_socket("[::]:0")
    } else {
        // bind to IN_ADDR4_ANY. Allows both conns from loopback and public internet
        crate::socket_helpers::get_udp_socket("0.0.0.0:0")
    }
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
    use netbeam::sync::test_utils::create_streams_with_addrs_and_lag;
    use rstest::rstest;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[rstest]
    #[case(0)]
    #[case(50)]
    #[case(100)]
    #[tokio::test]
    async fn dual_hole_puncher(#[case] lag: usize) {
        setup_log();

        let (server_stream, client_stream) = create_streams_with_addrs_and_lag(lag).await;

        let server = async move {
            let res = server_stream.begin_udp_hole_punch(Default::default()).await;
            log::info!("Server res: {:?}", res);
            res.unwrap()
        };

        let client = async move {
            let res = client_stream.begin_udp_hole_punch(Default::default()).await;
            log::info!("Client res: {:?}", res);
            res.unwrap()
        };

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);
        let (res0, res1) = tokio::join!(server, client);
        log::info!("JOIN complete! {:?} | {:?}", res0, res1);
        let (res0, res1) = (res0.unwrap(), res1.unwrap());

        let dummy_bytes = b"Hello, world!";

        log::info!("A");
        res0.socket.send_to(dummy_bytes as &[u8], res0.addr.send_address).await.unwrap();
        log::info!("B");
        let buf = &mut [0u8; 20];
        let len = res1.socket.recv(buf).await.unwrap();
        log::info!("C");
        assert_eq!(&buf[..len], dummy_bytes);
        log::info!("D");
    }
}