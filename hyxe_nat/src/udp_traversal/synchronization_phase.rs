use serde::{Serialize, Deserialize};
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use crate::udp_traversal::linear::{RelativeNodeType, LinearUDPHolePuncher};
use std::pin::Pin;
use futures::Future;
use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedUdpSocket;
use std::task::{Context, Poll};
use crate::nat_identification::NatType;
use crate::time_tracker::TimeTracker;
use std::time::Duration;
use std::net::SocketAddr;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::udp_traversal::NatTraversalMethod;

#[derive(Serialize, Deserialize)]
pub(crate) struct NatSyn {
    nat_type: NatType
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NatSynAck {
    nat_type: NatType
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NatAck {
    sync_time: i64
}

pub struct UdpHolePuncher<'a> {
    driver: Pin<Box<dyn Future<Output=Result<HolePunchedUdpSocket, anyhow::Error>> + 'a>>
}

impl<'a> UdpHolePuncher<'a> {
    pub fn new<T: ReliableOrderedConnectionToTarget + 'a>(conn: T, node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer) -> Self {
        Self { driver: Box::pin(driver(conn, node_type, encrypted_config_container)) }
    }
}

impl<'a> Future for UdpHolePuncher<'a> {
    type Output = Result<HolePunchedUdpSocket, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.driver.as_mut().poll(cx)
    }
}

async fn driver<T: ReliableOrderedConnectionToTarget>(conn: T, node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    let nat_type = NatType::identify().await.map_err(|err| anyhow::Error::msg(err.to_string()))?;
    log::info!("Local NAT type: {:?}", &nat_type);
    let tt = TimeTracker::new();
    match node_type {
        RelativeNodeType::Receiver => {
            // The receiver sends the information
            let now = tt.get_global_time_ns();
            conn.send_to_peer(&bincode2::serialize(&NatSyn { nat_type: nat_type.clone() }).unwrap()).await?;
            // now, wait for a NatSynAck
            let nat_syn_ack: NatSynAck = bincode2::deserialize(&conn.recv().await?)?;
            let rtt = tt.get_global_time_ns() - now;

            let sync_time = tt.get_global_time_ns() + rtt;

            let peer_ip_info = nat_syn_ack.nat_type.ip_addr_info().ok_or_else(|| anyhow::Error::msg("Peer internal IP absent"))?;

            let peer_external_addr = conn.peer_addr()?;
            let peer_internal_addr = SocketAddr::new(peer_ip_info.internal_ipv4, peer_external_addr.port());
            let local_bind_addr = conn.local_addr()?;
            let mut hole_puncher = LinearUDPHolePuncher::new_receiver(nat_type, encrypted_config_container, nat_syn_ack.nat_type.clone(), local_bind_addr, peer_external_addr, peer_internal_addr)?;

            log::info!("Will bind to: {:?} | Will connect to both external={:?} and internal = {:?}", local_bind_addr, peer_external_addr, peer_internal_addr);
            // we will wait rtt before starting the simultaneous hole-punch process
            conn.send_to_peer(&bincode2::serialize(&NatAck{ sync_time }).unwrap()).await?;

            tokio::time::sleep(Duration::from_nanos(rtt as _)).await;

            // now, begin the hole-punch
            Ok(hole_puncher.try_method(NatTraversalMethod::Method3).await.map_err(|err| anyhow::Error::msg(err.to_string()))?)

        }

        RelativeNodeType::Initiator => {
            // the initiator has to wait for the NatSyn
            let nat_syn: NatSyn = bincode2::deserialize(&conn.recv().await?)?;

            let peer_ip_info = nat_syn.nat_type.ip_addr_info().ok_or_else(|| anyhow::Error::msg("Peer internal IP absent"))?;
            let peer_external_addr = conn.peer_addr()?;
            let peer_internal_addr = SocketAddr::new(peer_ip_info.internal_ipv4, peer_external_addr.port());
            let local_bind_addr = conn.local_addr()?;
            let mut hole_puncher = LinearUDPHolePuncher::new_receiver(nat_type.clone(), encrypted_config_container, nat_syn.nat_type.clone(), local_bind_addr, peer_external_addr, peer_internal_addr)?;

            // now, send a syn ack
            conn.send_to_peer(&bincode2::serialize(&NatSynAck{nat_type}).unwrap()).await?;
            // now, await for a nat ack
            let nat_ack: NatAck = bincode2::deserialize(&conn.recv().await?)?;

            let delta = i64::abs(nat_ack.sync_time - tt.get_global_time_ns());
            tokio::time::sleep(Duration::from_nanos(delta as _)).await;

            // now, begin the hole-punch
            Ok(hole_puncher.try_method(NatTraversalMethod::Method3).await.map_err(|err| anyhow::Error::msg(err.to_string()))?)
        }
    }
}