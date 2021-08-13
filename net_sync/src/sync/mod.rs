use serde::{Deserialize, Serialize};

pub mod network_endpoint;
pub mod net_try_join;
pub mod net_join;
pub mod net_select_ok;
pub mod net_select;
pub mod sync_start;

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Copy, Clone)]
/// Used to keep track between two symmetric actions across two nodes
pub struct SymmetricConvID(u64);

impl From<u64> for SymmetricConvID {
    fn from(item: u64) -> Self {
        Self(item)
    }
}

pub mod test_utils {
    use std::net::SocketAddr;

    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use futures::stream::{SplitSink, SplitStream};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Mutex;

    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    use crate::reliable_conn::ReliableOrderedConnectionToTarget;
    use crate::sync::network_endpoint::NetworkEndpoint;
    use crate::sync::RelativeNodeType;
    use crate::reliable_conn::simulator::NetworkConnSimulator;

    pub struct TcpCodecFramed {
        sink: Mutex<SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>>,
        stream: Mutex<SplitStream<Framed<TcpStream, LengthDelimitedCodec>>>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr
    }

    #[async_trait]
    impl ReliableOrderedConnectionToTarget for TcpCodecFramed {
        async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
            self.sink.lock().await.send(Bytes::copy_from_slice(input)).await
        }

        async fn recv(&self) -> std::io::Result<Bytes> {
            Ok(self.stream.lock().await.next().await.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Stream died"))??.freeze())
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.remote_addr)
        }
    }

    fn codec(stream: TcpStream) -> TcpCodecFramed {
        let local_addr = stream.local_addr().unwrap();
        let remote_addr = stream.peer_addr().unwrap();
        let (sink, stream) = LengthDelimitedCodec::builder().new_framed(stream).split();
        TcpCodecFramed { sink: Mutex::new(sink), stream: Mutex::new(stream), local_addr, remote_addr }
    }

    pub async fn create_streams() -> (NetworkEndpoint<NetworkConnSimulator<TcpCodecFramed>>, NetworkEndpoint<NetworkConnSimulator<TcpCodecFramed>>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            NetworkEndpoint::register(RelativeNodeType::Receiver, NetworkConnSimulator::from(codec(listener.accept().await.unwrap().0))).await.unwrap()
        };

        let client = async move {
            let addr = rx.await.unwrap();
            NetworkEndpoint::register(RelativeNodeType::Initiator, NetworkConnSimulator::from(codec(TcpStream::connect(addr).await.unwrap()))).await.unwrap()
        };

        tokio::join!(server, client)
    }

    pub fn deadlock_detector() {
        log::info!("Deadlock function called ...");
        use std::thread;
        use std::time::Duration;
        use parking_lot::deadlock;
        // Create a background thread which checks for deadlocks every 10s
        thread::spawn(move || {
            log::info!("Deadlock detector spawned ...");
            loop {
                thread::sleep(Duration::from_secs(8));
                let deadlocks = deadlock::check_deadlock();
                if deadlocks.is_empty() {
                    continue;
                }

                log::info!("{} deadlocks detected", deadlocks.len());
                for (i, threads) in deadlocks.iter().enumerate() {
                    log::info!("Deadlock #{}", i);
                    for t in threads {
                        //println!("Thread Id {:#?}", t.thread_id());
                        log::info!("{:#?}", t.backtrace());
                    }
                }
            }
        });
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RelativeNodeType {
    Initiator,
    Receiver
}

impl RelativeNodeType {
    pub fn into_byte(self) -> u8 {
        match self {
            RelativeNodeType::Initiator => 10,
            RelativeNodeType::Receiver => 20
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            10 => Some(RelativeNodeType::Initiator),
            20 => Some(RelativeNodeType::Receiver),
            _ => None
        }
    }
}
