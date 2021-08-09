use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use crate::udp_traversal::linear::RelativeNodeType;
use std::pin::Pin;
use futures::Future;
use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedUdpSocket;
use std::task::{Context, Poll};
use crate::nat_identification::NatType;
use std::time::Duration;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::udp_traversal::multi::DualStackUdpHolePuncher;
use crate::sync::sync_start::NetSyncStart;

pub struct UdpHolePuncher<'a> {
    driver: Pin<Box<dyn Future<Output=Result<HolePunchedUdpSocket, anyhow::Error>> + 'a>>
}

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(3500);

impl<'a> UdpHolePuncher<'a> {
    pub fn new<T: ReliableOrderedConnectionToTarget + 'a>(conn: T, node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer) -> Self {
        Self::new_timeout(conn, node_type, encrypted_config_container, DEFAULT_TIMEOUT)
    }

    pub fn new_timeout<T: ReliableOrderedConnectionToTarget + 'a>(conn: T, node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer, timeout: Duration) -> Self {
        Self { driver: Box::pin(async move {
            tokio::time::timeout(timeout, driver(conn, node_type, encrypted_config_container)).await?
        }) }
    }
}

impl Future for UdpHolePuncher<'_> {
    type Output = Result<HolePunchedUdpSocket, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.driver.as_mut().poll(cx)
    }
}

async fn driver<'a, T: ReliableOrderedConnectionToTarget + 'a>(ref conn: T, node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    let ref nat_type = NatType::identify().await.map_err(|err| anyhow::Error::msg(err.to_string()))?;
    log::info!("Local NAT type: {:?}", &nat_type);
    let internal_bind_port = conn.local_addr()?.port();

    let future = |(peer_nat, peer_internal_port)| async move {
        DualStackUdpHolePuncher::new(node_type, encrypted_config_container, conn, &nat_type, &peer_nat, peer_internal_port, 0)?.await
    };

    NetSyncStart::new(conn, node_type, future, (nat_type.clone(), internal_bind_port)).await?
}

/*
/// Executed right after waiting for the synchronization time
/// Using DualStack over unistack for increased likelihood of NAT traversal
#[allow(dead_code)]
async fn handle_post_synchronization_phase_unistack<T: ReliableOrderedConnectionToTarget + 'static>(ref conn: T, mut hole_puncher: SingleUDPHolePuncher) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    // now, begin the hole-punch
    let method3 = async move {
        let res = hole_puncher.try_method(NatTraversalMethod::Method3).await.map_err(|err| anyhow::Error::msg(err.to_string()));
        let candidate = res.as_ref().ok().map(|r| r.addr);
        conn.send_to_peer(&bincode2::serialize(&PostHolePunch { candidate }).unwrap()).await?;
        res
    };

    let adjacent_status_listener = async move {
        // wait to listen for the post hole punch status from the peer
        bincode2::deserialize::<PostHolePunch>(&conn.recv().await?)
    };

    let (local_hole_punch_status, adjacent_hole_punch_status) = tokio::join!(method3, adjacent_status_listener);
    let adjacent_hole_punch_status = adjacent_hole_punch_status?;

    if local_hole_punch_status.is_ok() || adjacent_hole_punch_status.candidate.is_some() {
        // This implies at least one bidirectional connection exists. We must now establish only one of them (they may both be the same, or, they may both be different)

        //it's possible local failed but remote succeeded, in which case
        local_hole_punch_status
    } else {
        // neither side succeeded. Hole punching failed
        Err(anyhow::Error::msg("Both sides failed to hole-punch"))
    }
}*/