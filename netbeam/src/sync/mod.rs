use serde::{Deserialize, Serialize};

pub mod operations;
pub mod primitives;

pub mod subscription;

pub mod network_application;
pub mod network_endpoint;
pub mod sync_start;

pub mod channel;

pub mod callback_channel;
pub mod tracked_callback_channel;

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Copy, Clone)]
/// Used to keep track between two symmetric actions across two nodes
pub struct SymmetricConvID(u64);

impl From<u64> for SymmetricConvID {
    fn from(item: u64) -> Self {
        Self(item)
    }
}

#[cfg(not(target_family = "wasm"))]
pub mod test_utils {
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::stream::{SplitSink, SplitStream};
    use futures::{SinkExt, StreamExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Mutex;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    use crate::reliable_conn::simulator::NetworkConnSimulator;
    use crate::reliable_conn::{ConnAddr, ReliableOrderedStreamToTarget};
    use crate::sync::network_application::NetworkApplication;
    use crate::sync::network_endpoint::NetworkEndpoint;
    use crate::sync::RelativeNodeType;
    use std::net::SocketAddr;

    pub struct TcpCodecFramed {
        sink: Mutex<SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>>,
        stream: Mutex<SplitStream<Framed<TcpStream, LengthDelimitedCodec>>>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    }

    #[async_trait]
    impl ReliableOrderedStreamToTarget for TcpCodecFramed {
        async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
            self.sink
                .lock()
                .await
                .send(Bytes::copy_from_slice(input))
                .await
        }

        async fn recv(&self) -> std::io::Result<Bytes> {
            Ok(self
                .stream
                .lock()
                .await
                .next()
                .await
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Stream died"))??
                .freeze())
        }
    }

    impl ConnAddr for TcpCodecFramed {
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.peer_addr)
        }
    }

    fn codec(stream: TcpStream) -> TcpCodecFramed {
        let local_addr = stream.local_addr().unwrap();
        let peer_addr = stream.peer_addr().unwrap();
        let (sink, stream) = LengthDelimitedCodec::builder().new_framed(stream).split();
        TcpCodecFramed {
            sink: Mutex::new(sink),
            stream: Mutex::new(stream),
            peer_addr,
            local_addr,
        }
    }

    fn create_listener<A: std::net::ToSocketAddrs>(addr: A) -> TcpListener {
        let std_listener = std::net::TcpListener::bind(addr).unwrap();
        std_listener.set_nonblocking(true).unwrap();
        TcpListener::from_std(std_listener).unwrap()
    }

    fn create_connect<A: std::net::ToSocketAddrs>(addr: A) -> TcpStream {
        let std_stream = std::net::TcpStream::connect(addr).unwrap();
        std_stream.set_nonblocking(true).unwrap();
        TcpStream::from_std(std_stream).unwrap()
    }

    pub async fn create_streams() -> (NetworkApplication, NetworkApplication) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = async move {
            let listener = create_listener("127.0.0.1:0");
            tx.send(listener.local_addr().unwrap()).unwrap();
            NetworkApplication::register(
                RelativeNodeType::Receiver,
                NetworkConnSimulator::new(0, codec(listener.accept().await.unwrap().0)),
            )
            .await
            .unwrap()
        };

        let client = async move {
            let addr = rx.await.unwrap();
            NetworkApplication::register(
                RelativeNodeType::Initiator,
                NetworkConnSimulator::new(0, codec(create_connect(addr))),
            )
            .await
            .unwrap()
        };

        tokio::join!(server, client)
    }

    pub async fn create_streams_with_addrs_and_lag(
        min: usize,
    ) -> (NetworkEndpoint, NetworkEndpoint) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = async move {
            let listener = create_listener("127.0.0.1:0");
            tx.send(listener.local_addr().unwrap()).unwrap();
            NetworkEndpoint::register(
                RelativeNodeType::Receiver,
                NetworkConnSimulator::new(min, codec(listener.accept().await.unwrap().0)),
            )
            .await
            .unwrap()
        };

        let client = async move {
            let addr = rx.await.unwrap();
            NetworkEndpoint::register(
                RelativeNodeType::Initiator,
                NetworkConnSimulator::new(min, codec(create_connect(addr))),
            )
            .await
            .unwrap()
        };

        tokio::join!(server, client)
    }

    pub async fn create_streams_with_addrs() -> (NetworkEndpoint, NetworkEndpoint) {
        create_streams_with_addrs_and_lag(0).await
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RelativeNodeType {
    Initiator,
    Receiver,
}

impl RelativeNodeType {
    pub fn into_byte(self) -> u8 {
        match self {
            RelativeNodeType::Initiator => 10,
            RelativeNodeType::Receiver => 20,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            10 => Some(RelativeNodeType::Initiator),
            20 => Some(RelativeNodeType::Receiver),
            _ => None,
        }
    }
}
