use serde::{Serialize, Deserialize};
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use crate::udp_traversal::linear::RelativeNodeType;
use std::pin::Pin;
use futures::Future;
use crate::udp_traversal::hole_punched_udp_socket_addr::{HolePunchedUdpSocket, HolePunchedSocketAddr};
use std::task::{Context, Poll};
use crate::nat_identification::NatType;
use crate::time_tracker::TimeTracker;
use std::time::Duration;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::udp_traversal::multi::DualStackUdpHolePuncher;

#[derive(Serialize, Deserialize)]
pub(crate) struct NatSyn {
    nat_type: NatType,
    internal_bind_port: u16
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NatSynAck {
    nat_type: NatType,
    internal_bind_port: u16
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NatAck {
    sync_time: i64
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PostHolePunch {
    /// if is_some, then hole punch was a success
    pub(crate) candidate: Option<HolePunchedSocketAddr>
}

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
    let nat_type = NatType::identify().await.map_err(|err| anyhow::Error::msg(err.to_string()))?;
    log::info!("Local NAT type: {:?}", &nat_type);
    let tt = TimeTracker::new();
    let internal_bind_port = conn.local_addr()?.port();

    match node_type {
        RelativeNodeType::Receiver => {
            // The receiver sends the information
            let now = tt.get_global_time_ns();
            conn.send_to_peer(&bincode2::serialize(&NatSyn { nat_type: nat_type.clone(), internal_bind_port }).unwrap()).await?;
            // now, wait for a NatSynAck
            let nat_syn_ack: NatSynAck = bincode2::deserialize(&conn.recv().await?)?;
            let rtt = tt.get_global_time_ns() - now;

            let sync_time = tt.get_global_time_ns() + rtt;

            // we will wait rtt before starting the simultaneous hole-punch process
            conn.send_to_peer(&bincode2::serialize(&NatAck { sync_time }).unwrap()).await?;

            tokio::time::sleep(Duration::from_nanos(rtt as _)).await;

            DualStackUdpHolePuncher::new(RelativeNodeType::Receiver, encrypted_config_container, conn, &nat_type, &nat_syn_ack.nat_type, nat_syn_ack.internal_bind_port, 0)?.await
            //handle_post_synchronization_phase(conn, hole_puncher).await
        }

        RelativeNodeType::Initiator => {
            // the initiator has to wait for the NatSyn
            let nat_syn: NatSyn = bincode2::deserialize(&conn.recv().await?)?;

            // now, send a syn ack
            conn.send_to_peer(&bincode2::serialize(&NatSynAck {nat_type: nat_type.clone(), internal_bind_port}).unwrap()).await?;
            // now, await for a nat ack
            let nat_ack: NatAck = bincode2::deserialize(&conn.recv().await?)?;

            let delta = i64::abs(nat_ack.sync_time - tt.get_global_time_ns());
            tokio::time::sleep(Duration::from_nanos(delta as _)).await;

            DualStackUdpHolePuncher::new(RelativeNodeType::Initiator, encrypted_config_container, conn, &nat_type, &nat_syn.nat_type, nat_syn.internal_bind_port, 0)?.await

            // now, begin the hole-punch
            //handle_post_synchronization_phase(conn, hole_puncher).await
        }
    }
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