use crate::nat_identification::NatType;
use crate::udp_traversal::hole_punch_config::HolePunchConfig;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::udp_traversal::multi::DualStackUdpHolePuncher;
use crate::udp_traversal::targetted_udp_socket_addr::HolePunchedUdpSocket;
use futures::Future;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::subscription::Subscribable;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::UdpSocket;

pub struct UdpHolePuncher<'a> {
    driver: Pin<Box<dyn Future<Output = Result<HolePunchedUdpSocket, anyhow::Error>> + Send + 'a>>,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(5000);

impl<'a> UdpHolePuncher<'a> {
    pub fn new(
        conn: &'a NetworkEndpoint,
        encrypted_config_container: EncryptedConfigContainer,
    ) -> Self {
        Self::new_timeout(conn, encrypted_config_container, DEFAULT_TIMEOUT)
    }

    pub fn new_timeout(
        conn: &'a NetworkEndpoint,
        encrypted_config_container: EncryptedConfigContainer,
        timeout: Duration,
    ) -> Self {
        Self {
            driver: Box::pin(async move {
                // for debugging purposes
                if std::env::var("debug_cause_timeout").unwrap_or_default() != "ON" {
                    tokio::time::timeout(timeout, driver(conn, encrypted_config_container)).await?
                } else {
                    log::warn!(target: "citadel", "DEBUG_CAUSE_TIMEOUT enabled");
                    Err(anyhow::Error::msg("DEBUG_CAUSE_TIMEOUT invoked"))
                }
            }),
        }
    }
}

impl Future for UdpHolePuncher<'_> {
    type Output = Result<HolePunchedUdpSocket, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.driver.as_mut().poll(cx)
    }
}

#[cfg_attr(
    feature = "localhost-testing",
    tracing::instrument(target = "citadel", skip_all, ret, err(Debug))
)]
async fn driver(
    conn: &NetworkEndpoint,
    encrypted_config_container: EncryptedConfigContainer,
) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    // create stream
    let stream = &(conn.initiate_subscription().await?);
    let local_nat_type = &(NatType::identify()
        .await
        .map_err(|err| anyhow::Error::msg(err.to_string()))?);

    stream.send_serialized(local_nat_type).await?;
    let peer_nat_type = &(stream.recv_serialized::<NatType>().await?);

    log::trace!(target: "citadel", "[driver] Local NAT type: {:?} | Peer NAT type: {:?}", local_nat_type, peer_nat_type);
    let local_initial_socket = get_optimal_bind_socket(local_nat_type, peer_nat_type)?;
    let internal_bind_port = local_initial_socket.local_addr()?.port();

    // exchange internal bind port, also synchronizing the beginning of the hole punch process
    // while doing so
    let peer_internal_bind_port = conn.sync_exchange_payload(internal_bind_port).await?;

    // the next functions takes everything insofar obtained into account without causing collisions with any existing
    // connections (e.g., no conflicts with the primary stream existing in conn)
    let hole_punch_config = HolePunchConfig::new(
        local_nat_type,
        peer_nat_type,
        local_initial_socket,
        peer_internal_bind_port,
    )?;
    log::trace!(target: "citadel", "[driver] Synchronized; will now execute dualstack hole-puncher ... config: {:?}", hole_punch_config);
    let res = DualStackUdpHolePuncher::new(
        conn.node_type(),
        encrypted_config_container,
        hole_punch_config,
        conn,
    )?
    .await;
    res.map_err(|err| {
        anyhow::Error::msg(format!(
            "**HOLE-PUNCH-ERR**: {:?} | local_nat_type: {:?} | peer_nat_type: {:?}",
            err, local_nat_type, peer_nat_type
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

    // only bind to ipv6 if v6 is enabled locally, and, there both nodes have an external ipv6 addr,
    // AND, the peer allows ipv6, then go with ipv6
    if local_allows_ipv6
        && local_has_an_external_ipv6_addr
        && peer_has_an_external_ipv6_addr
        && peer_allows_ipv6
    {
        // bind to IN_ADDR6_ANY. Allows both conns from loopback and public internet
        crate::socket_helpers::get_udp_socket("[::]:0")
    } else {
        // bind to IN_ADDR4_ANY. Allows both conns from loopback and public internet
        crate::socket_helpers::get_udp_socket("0.0.0.0:0")
    }
}

pub trait EndpointHolePunchExt {
    fn begin_udp_hole_punch(
        &self,
        encrypted_config_container: EncryptedConfigContainer,
    ) -> UdpHolePuncher;
}

impl EndpointHolePunchExt for NetworkEndpoint {
    fn begin_udp_hole_punch(
        &self,
        encrypted_config_container: EncryptedConfigContainer,
    ) -> UdpHolePuncher {
        UdpHolePuncher::new(self, encrypted_config_container)
    }
}

#[cfg(test)]
mod tests {
    use crate::udp_traversal::udp_hole_puncher::EndpointHolePunchExt;
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

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);
        let (res0, res1) = tokio::join!(server, client);
        log::trace!(target: "citadel", "JOIN complete! {:?} | {:?}", res0, res1);
        let (res0, res1) = (res0.unwrap(), res1.unwrap());

        let dummy_bytes = b"Hello, world!";

        log::trace!(target: "citadel", "A");
        res0.socket
            .send_to(dummy_bytes as &[u8], res0.addr.send_address)
            .await
            .unwrap();
        log::trace!(target: "citadel", "B");
        let buf = &mut [0u8; 4096];
        let (len, _addr) = res1.socket.recv_from(buf).await.unwrap();
        //assert_eq!(res1.addr.receive_address, addr);
        log::trace!(target: "citadel", "C");
        assert_ne!(len, 0);
        res1.socket
            .send_to(dummy_bytes, res1.addr.send_address)
            .await
            .unwrap();
        let (len, _addr) = res0.socket.recv_from(buf).await.unwrap();
        assert_ne!(len, 0);
        //assert_eq!(res0.addr.receive_address, addr);
        log::trace!(target: "citadel", "D");
    }
}
