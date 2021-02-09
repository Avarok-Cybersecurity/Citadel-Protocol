use std::io::Write;
use std::iter::FromIterator;
use std::net::SocketAddr;

use async_trait::async_trait;
use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use bytes::BufMut;
use tokio::net::UdpSocket;
use tokio::time::Duration;

use crate::error::FirewallError;
use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedSocketAddr;
use crate::udp_traversal::linear::{LinearUdpHolePunchImpl, RelativeNodeType};
use crate::udp_traversal::linear::nat_payloads::{SYN, SYN_ACK};
use futures::StreamExt;

/// Method three: "Both sides send packets with short TTL values followed by packets with long TTL
// values". Source: page 7 of https://thomaspbraun.com/pdfs/NAT_Traversal/NAT_Traversal.pdf
pub struct Method3 {
    this_node_type: RelativeNodeType
}


impl Method3 {
    /// Make sure to complete the pre-process stage before calling this
    /// NOTE: Socket should have SO_REUSEADDR=true
    pub fn new(this_node_type: RelativeNodeType) -> Self {
        Self { this_node_type }
    }

    /// The initiator must pass a vector correlating to the target endpoints. Each provided socket will attempt to reach out to the target endpoint (1-1)
    async fn execute_initiator(&self, sockets: &mut Vec<UdpSocket>, endpoints: &Vec<SocketAddr>) -> Result<Vec<HolePunchedSocketAddr>, FirewallError> {
        // We will begin sending packets right away, assuming the pre-process synchronization occurred
        // 400ms window
        const BYTES_PER_SOCKET_MESSAGE: usize = SYN.len() + 2; // 2 bytes per u16

        let mut messages_syn = Vec::with_capacity(sockets.len() * BYTES_PER_SOCKET_MESSAGE).writer();
        for sck in sockets.iter_mut() {
            // set TTL low
            sck.set_ttl(2).unwrap();
            messages_syn.write(SYN).unwrap();
            messages_syn.write_u16::<NetworkEndian>(sck.local_addr().unwrap().port()).unwrap();
        }

        let messages_syn = messages_syn.into_inner();
        let messages_syn = messages_syn.chunks(BYTES_PER_SOCKET_MESSAGE).collect::<Vec<&[u8]>>();

        let mut sleep = tokio::time::interval(Duration::from_millis(20));

        for _ in 0..5 {
            let _ = sleep.tick().await;
            for ((socket, message), endpoint) in sockets.iter_mut().zip(messages_syn.iter()).zip(endpoints.iter()) {
                log::info!("Sending short TTL {:?} to {}", *message, endpoint);
                socket.send_to(*message, endpoint).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?;
            }
        }

        // set TTL long. 400ms window
        for sck in sockets.iter_mut() {
            sck.set_ttl(120).unwrap();
        }

        let mut iter = tokio::time::interval(Duration::from_millis(20));
        for _ in 0..5 {
            let _ = iter.tick().await;
            for ((socket, endpoint), message) in sockets.iter_mut().zip(endpoints.iter()).zip(messages_syn.iter()) {
                log::info!("Sending long TTL {:?} to {}", *message, endpoint);
                socket.send_to(*message, endpoint).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?;
            }
        }

        let mut ret = Vec::with_capacity(sockets.len());
        let futures_iter = sockets.into_iter().zip(endpoints.into_iter()).map(|(socket, endpoint)| tokio::time::timeout(Duration::from_millis(500), Self::recv_until_initiator(SYN_ACK, SYN_ACK.len(), 2, socket, endpoint)))
            .collect::<Vec<_>>();

        let futures_ordered_concurrent = futures::stream::FuturesOrdered::from_iter(futures_iter);

        let results = futures_ordered_concurrent.collect::<Vec<Result<Result<HolePunchedSocketAddr, FirewallError>, _>>>()
            .await;

        for res in results.into_iter() {
            ret.push(res.map_err(|err| FirewallError::HolePunch(err.to_string()))??);
        }

        Ok(ret)
    }

    /// The expected SocketAddr is provided here. Whereas the IP addr should be obtained during the pre-process phase,
    /// the port should be obtained during the sharing of ports in the DO_CONNECT stage. In this function, since we do
    /// not yet know if there will be port-translation, we wait for an IP address equal to the provided sockets. We then
    /// return a HolePunched IP Address
    async fn execute_receiver(&self, sockets: &mut Vec<UdpSocket>, endpoints: &Vec<SocketAddr>) -> Result<Vec<HolePunchedSocketAddr>, FirewallError> {
        // create buffer for later use. We send SYN_ACKS as a receiver back to the initiator
        const BYTES_PER_SOCKET_MESSAGE: usize = SYN_ACK.len() + 2; // 2 bytes per u16
        let mut messages_syn_ack = Vec::with_capacity(sockets.len() * BYTES_PER_SOCKET_MESSAGE).writer();

        for sck in sockets.iter_mut() {
            // set TTL low
            sck.set_ttl(2).unwrap();
            messages_syn_ack.write(SYN_ACK).unwrap();
            messages_syn_ack.write_u16::<NetworkEndian>(sck.local_addr().unwrap().port()).unwrap();
        }

        let messages_syn_ack = messages_syn_ack.into_inner();
        let messages_syn_ack = messages_syn_ack.chunks(BYTES_PER_SOCKET_MESSAGE).collect::<Vec<&[u8]>>();

        // wait until the initiator sends a SYN packet
        let socket_count = sockets.len();
        let futures_iter = sockets.into_iter().enumerate().map(|(idx, socket)| tokio::time::timeout(Duration::from_millis(1000), Self::recv_until_receiver(SYN, SYN.len(), 2, socket, &endpoints[idx])))
            .collect::<Vec<_>>();

        let futures_ordered_concurrent = futures::stream::FuturesOrdered::from_iter(futures_iter);

        let mut hole_punched_addrs: Vec<HolePunchedSocketAddr> = Vec::with_capacity(socket_count);
        let results = futures_ordered_concurrent.collect::<Vec<Result<Result<HolePunchedSocketAddr, FirewallError>, _>>>()
            .await;

        for (res, socket) in results.into_iter().zip(sockets.into_iter()) {
            let hole_punched_addr = res.map_err(|err| FirewallError::HolePunch(err.to_string()))??;

            // set TTL low
            socket.set_ttl(2).unwrap();
            hole_punched_addrs.push(hole_punched_addr);
        }

        // We will begin sending packets right away, assuming the pre-process synchronization occurred
        // 400ms window
        let mut iter = tokio::time::interval(Duration::from_millis(20));
        for _ in 0..5 {
            let _ = iter.tick().await;
            for ((socket, hole_punched_addr), message) in sockets.into_iter().zip(hole_punched_addrs.iter()).zip(messages_syn_ack.iter()) {
                log::info!("Sending short TTL {:?} to {}", *message, hole_punched_addr.natted);
                socket.send_to(*message, hole_punched_addr.natted).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?;
            }
        }

        for sck in sockets.into_iter() {
            // set TTL long
            sck.set_ttl(120).unwrap();
        }

        // 400ms window
        let mut iter = tokio::time::interval(Duration::from_millis(20));
        for _ in 0..5 {
            let _ = iter.tick().await;
            for ((socket, hole_punched_addr), message) in sockets.into_iter().zip(hole_punched_addrs.iter()).zip(messages_syn_ack.iter()) {
                log::info!("Sending long TTL {:?} to {}", *message, hole_punched_addr.natted);
                socket.send_to(*message, hole_punched_addr.natted).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?;
            }
        }

        // Finally, for nodes that operate on the same LAN, wait a little time b/c the initiator needs time
        // to finish its side of processing
        if !endpoints[0].ip().is_global() {
            log::info!("Delaying for initiator in a non-global network environment ...");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(hole_punched_addrs)
    }

    // Receives until a pattern is found in the payload
    async fn recv_until_initiator(pattern: &[u8], tag_len: usize, port_len: usize, socket: &mut UdpSocket, endpoint: &SocketAddr) -> Result<HolePunchedSocketAddr, FirewallError> {
        let buf = &mut [0u8; 4096];
        log::info!("Listening on {:?}", socket.local_addr().unwrap());

        while let Ok((len, nat_addr)) = socket.recv_from(buf).await {
            log::info!("RECV packet from {:?}", &nat_addr);
            if len == tag_len + port_len {
                let data = &buf[..len];
                let (tag, port) = data.split_at(tag_len);
                if tag == pattern {
                    let _private_remote_port = NetworkEndian::read_u16(port);
                    let initial_socket = endpoint;
                    let hole_punched_addr = HolePunchedSocketAddr::new(*initial_socket, nat_addr);
                    log::info!("RECV Dat: {}", &hole_punched_addr);
                    return Ok(hole_punched_addr);
                }
            }
        }

        Err(FirewallError::HolePunch("Socket recv error".to_string()))
    }

    // Receives until a pattern is found in the payload
    async fn recv_until_receiver(pattern: &[u8], tag_len: usize, port_len: usize, socket: &mut UdpSocket, endpoint: &SocketAddr) -> Result<HolePunchedSocketAddr, FirewallError> {
        log::info!("RECV_UNTIL listening on {:?}", socket.local_addr().unwrap());
        let buf = &mut [0u8; 4096];
        while let Ok((len, nat_addr)) = socket.recv_from(buf).await {
            log::info!("[local] RECV packet from {:?}", &nat_addr);
            if len == tag_len + port_len {
                let data = &buf[..len];
                let (tag, port) = data.split_at(tag_len);
                // With the endpoint IP, it needs to match since by this point since we already safely know where the packets are coming from
                if tag == pattern && nat_addr.ip() == endpoint.ip() {
                    let private_remote_port = NetworkEndian::read_u16(port);
                    // the private remote port should equal the original endpoint port supplied since all mappings are 1-1
                    let initial_socket = SocketAddr::new(endpoint.ip(), private_remote_port);
                    let hole_punched_addr = HolePunchedSocketAddr::new(initial_socket, nat_addr);
                    log::info!("{}", &hole_punched_addr);
                    return Ok(hole_punched_addr);
                }
            }
        }

        Err(FirewallError::HolePunch("Socket recv error".to_string()))
    }
}

#[async_trait]
impl LinearUdpHolePunchImpl for Method3 {
    async fn execute(&self, sockets: &mut Vec<UdpSocket>, endpoints: &Vec<SocketAddr>) -> Result<Vec<HolePunchedSocketAddr>, FirewallError> {
        match self.this_node_type {
            RelativeNodeType::Initiator => {
                self.execute_initiator(sockets, endpoints).await
            }

            RelativeNodeType::Receiver => {
                self.execute_receiver(sockets, endpoints).await
            }
        }
    }
}