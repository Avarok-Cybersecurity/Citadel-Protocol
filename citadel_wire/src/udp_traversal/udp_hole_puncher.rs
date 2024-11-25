use crate::nat_identification::{NatType, IDENTIFY_TIMEOUT};
use crate::udp_traversal::hole_punch_config::HolePunchConfig;
use crate::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use crate::udp_traversal::multi::DualStackUdpHolePuncher;
use crate::udp_traversal::targetted_udp_socket_addr::HolePunchedUdpSocket;
use citadel_io::tokio::net::UdpSocket;
use futures::Future;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::subscription::Subscribable;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

pub struct UdpHolePuncher<'a> {
    driver: Pin<Box<dyn Future<Output = Result<HolePunchedUdpSocket, anyhow::Error>> + Send + 'a>>,
}

const DEFAULT_TIMEOUT: Duration =
    Duration::from_millis((IDENTIFY_TIMEOUT.as_millis() + 5000) as u64);

impl<'a> UdpHolePuncher<'a> {
    pub fn new(
        conn: &'a NetworkEndpoint,
        encrypted_config_container: HolePunchConfigContainer,
    ) -> Self {
        Self::new_timeout(conn, encrypted_config_container, DEFAULT_TIMEOUT)
    }

    pub fn new_timeout(
        conn: &'a NetworkEndpoint,
        encrypted_config_container: HolePunchConfigContainer,
        timeout: Duration,
    ) -> Self {
        Self {
            driver: Box::pin(
                async move { driver(conn, encrypted_config_container, timeout).await },
            ),
        }
    }
}

impl Future for UdpHolePuncher<'_> {
    type Output = Result<HolePunchedUdpSocket, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.driver.as_mut().poll(cx)
    }
}

const MAX_RETRIES: usize = 3;

#[cfg_attr(
    feature = "localhost-testing",
    tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err(Debug))
)]
async fn driver(
    conn: &NetworkEndpoint,
    encrypted_config_container: HolePunchConfigContainer,
    timeout: Duration,
) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    let mut retries = 0;
    loop {
        let task = tokio::time::timeout(
            timeout,
            driver_inner(conn, encrypted_config_container.clone()),
        );
        match task.await {
            Ok(Ok(res)) => return Ok(res),
            Ok(Err(err)) => {
                log::warn!(target: "citadel", "Hole puncher failed: {err:?}");
            }
            Err(_) => {
                log::warn!(target: "citadel", "Hole puncher timed-out");
            }
        }

        retries += 1;

        if retries >= MAX_RETRIES {
            return Err(anyhow::Error::msg("Max retries reached for UDP Traversal"));
        }
    }
}

async fn driver_inner(
    conn: &NetworkEndpoint,
    mut encrypted_config_container: HolePunchConfigContainer,
) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    log::trace!(target: "citadel", "[driver] Starting hole puncher ...");
    // create stream
    let stream = &(conn.initiate_subscription().await?);
    let stun_servers = encrypted_config_container.take_stun_servers();
    let local_nat_type = &(NatType::identify(stun_servers)
        .await
        .map_err(|err| anyhow::Error::msg(err.to_string()))?);

    stream.send_serialized(local_nat_type).await?;
    let peer_nat_type = &(stream.recv_serialized::<NatType>().await?);

    let local_initial_socket = get_optimal_bind_socket(local_nat_type, peer_nat_type)?;
    let internal_bind_addr_optimal = local_initial_socket.local_addr()?;
    let mut sockets = vec![local_initial_socket];
    let mut internal_addresses = vec![internal_bind_addr_optimal];
    if internal_bind_addr_optimal.is_ipv6() {
        let additional_socket = crate::socket_helpers::get_udp_socket("0.0.0.0:0")?;
        internal_addresses.push(additional_socket.local_addr()?);
        sockets.push(additional_socket);
    }

    // exchange internal bind port, also synchronizing the beginning of the hole punch process
    // while doing so
    let peer_internal_bind_addrs = conn.sync_exchange_payload(internal_addresses).await?;
    log::trace!(target: "citadel", "\n~~~~~~~~~~~~\n [driver] Local NAT type: {:?}\n Peer NAT type: {:?}", local_nat_type, peer_nat_type);
    log::trace!(target: "citadel", "[driver] Local internal bind addr: {internal_bind_addr_optimal:?}\nPeer internal bind addr: {peer_internal_bind_addrs:?}");
    log::trace!(target: "citadel", "\n~~~~~~~~~~~~\n");
    // the next functions takes everything insofar obtained into account without causing collisions with any existing
    // connections (e.g., no conflicts with the primary stream existing in conn)
    let hole_punch_config = HolePunchConfig::new(peer_nat_type, &peer_internal_bind_addrs, sockets);

    let conn = conn.clone();
    log::trace!(target: "citadel", "[driver] Synchronized; will now execute dualstack hole-puncher ... config: {:?}", hole_punch_config);
    let res = DualStackUdpHolePuncher::new(
        conn.node_type(),
        encrypted_config_container,
        hole_punch_config,
        conn,
    )?
    .await;

    log::info!(target: "citadel", "Hole Punch Status: {res:?}");

    res.map_err(|err| {
        anyhow::Error::msg(format!(
            "**HOLE-PUNCH-ERR**: {err:?} | local_nat_type: {local_nat_type:?} | peer_nat_type: {peer_nat_type:?}",
        ))
    })
}

/// since the NAT traversal process always ensures that both public-facing and loopback
/// cases are covered, we can start by binding to 0.0.0.0, knowing that 127.0.0.1 will
/// also be covered automatically
///
/// Suppose A binds to ipv6 addr, and B binds to ipv4 addr, then B cannot send packets to
/// A. Only A can send to B via ipv4-mapped-v6 addrs. In order for B to send packets back to A,
/// B will need the ipv4 address of A.
pub fn get_optimal_bind_socket(
    local_nat_info: &NatType,
    peer_nat_info: &NatType,
) -> Result<UdpSocket, anyhow::Error> {
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

    // only bind to ipv6 if v6 is enabled locally, and, both nodes have an external ipv6 addr,
    // AND, the peer allows ipv6, then go with ipv6
    if local_allows_ipv6
        && local_has_an_external_ipv6_addr
        && peer_has_an_external_ipv6_addr
        && peer_allows_ipv6
    {
        // bind to IN_ADDR6_ANY. Allows both conns from loopback and public internet
        crate::socket_helpers::get_udp_socket("[::]:0")
    } else {
        crate::socket_helpers::get_udp_socket("0.0.0.0:0")
    }
}

pub trait EndpointHolePunchExt {
    fn begin_udp_hole_punch(
        &self,
        encrypted_config_container: HolePunchConfigContainer,
    ) -> UdpHolePuncher;
}

impl EndpointHolePunchExt for NetworkEndpoint {
    fn begin_udp_hole_punch(
        &self,
        encrypted_config_container: HolePunchConfigContainer,
    ) -> UdpHolePuncher {
        UdpHolePuncher::new(self, encrypted_config_container)
    }
}

#[cfg(test)]
mod tests {
    use crate::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
    use citadel_io::tokio;
    use netbeam::sync::test_utils::create_streams_with_addrs_and_lag;
    use rstest::rstest;

    #[rstest]
    #[case(0)]
    #[case(50)]
    #[case(70)]
    #[tokio::test]
    async fn test_dual_hole_puncher(#[case] lag: usize) {
        citadel_logging::setup_log();

        let (server_stream, client_stream) = create_streams_with_addrs_and_lag(lag).await;

        let server = async move {
            let res = server_stream.begin_udp_hole_punch(Default::default()).await;
            log::trace!(target: "citadel", "Server res: {:?}", res);
            res.unwrap()
        };

        let client = async move {
            let res = client_stream.begin_udp_hole_punch(Default::default()).await;
            log::trace!(target: "citadel", "Client res: {:?}", res);
            res.unwrap()
        };

        let server = citadel_io::tokio::task::spawn(server);
        let client = citadel_io::tokio::task::spawn(client);
        let (res0, res1) = citadel_io::tokio::join!(server, client);
        log::trace!(target: "citadel", "JOIN complete! {:?} | {:?}", res0, res1);
        let (_res0, _res1) = (res0.unwrap(), res1.unwrap());

        // due to the error "An existing connection was forcibly closed by the remote host",
        // we must gate this test on localhost-testing + NOT windows
        #[cfg(not(target_os = "windows"))]
        {
            let dummy_bytes = b"Hello, world!";

            log::trace!(target: "citadel", "A");
            _res0
                .send_to(dummy_bytes as &[u8], _res0.addr.send_address)
                .await
                .unwrap();
            log::trace!(target: "citadel", "B");
            let buf = &mut [0u8; 4096];
            let (len, _addr) = _res1.recv_from(buf).await.unwrap();
            //assert_eq!(res1.addr.receive_address, addr);
            log::trace!(target: "citadel", "C");
            assert_ne!(len, 0);
            _res1
                .send_to(dummy_bytes, _res1.addr.send_address)
                .await
                .unwrap();
            let (len, _addr) = _res0.recv_from(buf).await.unwrap();
            assert_ne!(len, 0);
            //assert_eq!(res0.addr.receive_address, addr);
            log::trace!(target: "citadel", "D");
        }
    }
}
