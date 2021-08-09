use std::pin::Pin;
use futures::Future;
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use crate::udp_traversal::linear::RelativeNodeType;
use std::task::{Context, Poll};
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use crate::time_tracker::TimeTracker;
use std::time::Duration;

/// synchronizes the beginning of an operation between two nodes. Includes attaching an optional payload for transmission of information between two endpoints during the transmission-sync phase
pub struct NetSyncStart<'a, R> {
    future: Pin<Box<dyn Future<Output=Result<R, anyhow::Error>> + Send + 'a>>
}

impl<'a, R: 'a> NetSyncStart<'a, R> {
    pub fn new<Conn: ReliableOrderedConnectionToTarget + 'a, F: 'a, Fx: 'a, P: 'a + Serialize + DeserializeOwned + Send + Sync>(conn: Conn, relative_node_type: RelativeNodeType, future: Fx, payload: P) -> Self
        where
            F: Future<Output=R>,
            F: Send,
            Fx: FnOnce(P) -> F,
            Fx: Send {

        Self { future: Box::pin(synchronize(conn, relative_node_type, future, payload)) }
    }

    /// Unlike `new`, this function will simply return the payload to the adjacent node synchronisticly with the adjacent node (i.e., both nodes receive each other's payloads at about the same time)
    pub fn exchange_payload<Conn: ReliableOrderedConnectionToTarget + 'a>(conn: Conn, relative_node_type: RelativeNodeType, payload: R) -> Self
        where
            R: Serialize + DeserializeOwned + Send + Sync {

        let future = |payload: R| {
            futures::future::ready(payload)
        };

        Self { future: Box::pin(synchronize(conn, relative_node_type, future, payload)) }
    }

    /// This returned future will resolve once both sides terminate synchronisticly
    pub fn new_sync_only<Conn: ReliableOrderedConnectionToTarget + 'a>(conn: Conn, relative_node_type: RelativeNodeType) -> NetSyncStart<'a, ()> {
        NetSyncStart::exchange_payload(conn, relative_node_type, ())
    }
}

impl<R> Future for NetSyncStart<'_, R> {
    type Output = Result<R, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

#[derive(Serialize, Deserialize)]
enum SyncPacket<P: Send + Sync> {
    Syn(P),
    SynAck(P),
    Ack(i64)
}

impl<P: Send + Sync> SyncPacket<P> {
    fn payload(self) -> Result<P, anyhow::Error> {
        match self {
            Self::Syn(payload) | Self::SynAck(payload) => Ok(payload),
            _ => Err(anyhow::Error::msg("Payload not attached"))
        }
    }

    fn timestamp(self) -> Result<i64, anyhow::Error> {
        match self {
            Self::Ack(ts) => Ok(ts),
            _ => Err(anyhow::Error::msg("Payload not attched (sync time)"))
        }
    }
}

async fn synchronize<Conn: ReliableOrderedConnectionToTarget, F, Fx, P: Serialize + DeserializeOwned + Send + Sync, R>(ref conn: Conn, relative_node_type: RelativeNodeType, future: Fx, payload: P) -> Result<R, anyhow::Error>
    where
        F: Future<Output=R>,
        F: Send,
        Fx: FnOnce(P) -> F,
        Fx: Send {

    let tt = TimeTracker::new();

    match relative_node_type {
        RelativeNodeType::Receiver => {
            let now = tt.get_global_time_ns();
            send(conn, SyncPacket::Syn(payload)).await?;
            let payload_recv: P = recv(conn).await?.payload()?;
            let rtt = tt.get_global_time_ns() - now;
            let sync_time = tt.get_global_time_ns() + rtt;
            send::<_, P>(conn, SyncPacket::Ack(sync_time)).await?;
            log::info!("[Sync] Executing provided subroutine for receiver ...");

            tokio::time::sleep(Duration::from_nanos(rtt as _)).await;
            Ok((future)(payload_recv).await)
        }

        RelativeNodeType::Initiator => {
            let payload_recv: P = recv(conn).await?.payload()?;
            send(conn, SyncPacket::SynAck(payload)).await?;
            let sync_time = recv::<_, P>(conn).await?.timestamp()?;
            let delta = i64::abs(sync_time - tt.get_global_time_ns());

            tokio::time::sleep(Duration::from_nanos(delta as _)).await;
            log::info!("[Sync] Executing provided subroutine for initiator ...");

            Ok((future)(payload_recv).await)
        }
    }
}

async fn send<Conn: ReliableOrderedConnectionToTarget, P: Serialize + Send + Sync>(conn: &Conn, ref packet: SyncPacket<P>) -> Result<(), anyhow::Error> {
    Ok(conn.send_to_peer(&bincode2::serialize(packet).unwrap()).await?)
}

async fn recv<Conn: ReliableOrderedConnectionToTarget, P: DeserializeOwned + Send + Sync>(conn: &Conn) -> Result<SyncPacket<P>, anyhow::Error> {
    Ok(bincode2::deserialize(&conn.recv().await?)?)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, TcpStream};
    use std::str::FromStr;
    use crate::udp_traversal::linear::RelativeNodeType;
    use std::time::Duration;
    use crate::time_tracker::TimeTracker;
    use crate::sync::ReliableOrderedConnSyncExt;

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
    async fn run() {
        setup_log();

        let addr = SocketAddr::from_str("127.0.0.1:27890").unwrap();

        let server = async move {
            let listener = TcpListener::bind(addr).await.unwrap();
            let (ref stream, _addr) = listener.accept().await.unwrap();

            let res = stream.sync_execute(RelativeNodeType::Receiver, dummy_function, 100).await.unwrap();
            log::info!("Server res: {:?}", res);
            res
        };

        let client = async move {
            tokio::time::sleep(Duration::from_millis(10)).await; // give time for server to startup
            let stream = TcpStream::connect(addr).await.unwrap();

            let res = stream.sync_execute(RelativeNodeType::Initiator, dummy_function, 99).await.unwrap();
            log::info!("Client res: {:?}", res);
            res
        };

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);
        let (res0, res1) = tokio::join!(server, client);
        let res0 = res0.unwrap();
        let res1 = res1.unwrap();

        log::info!("res0: {}\nres1: {}\nDelta: {}", res0, res1, res1 - res0);
    }

    #[tokio::test]
    async fn run_getter() {
        setup_log();

        let addr = SocketAddr::from_str("127.0.0.1:27890").unwrap();

        let server = async move {
            let listener = TcpListener::bind(addr).await.unwrap();
            let (ref stream, _addr) = listener.accept().await.unwrap();

            let res = stream.sync_exchange_payload(RelativeNodeType::Receiver, 100).await.unwrap();
            log::info!("Server res: {:?}", res);
            res
        };

        let client = async move {
            tokio::time::sleep(Duration::from_millis(10)).await; // give time for server to startup
            let stream = TcpStream::connect(addr).await.unwrap();

            let res = stream.sync_exchange_payload(RelativeNodeType::Initiator, 99).await.unwrap();
            log::info!("Client res: {:?}", res);
            res
        };

        let server = tokio::spawn(server);
        let client = tokio::spawn(client);
        let (res0, res1) = tokio::join!(server, client);
        res0.unwrap();
        res1.unwrap();
    }

    async fn dummy_function(_payload: u64) -> i64 {
        TimeTracker::new().get_global_time_ns()
    }
}