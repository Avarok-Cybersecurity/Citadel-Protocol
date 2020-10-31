use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::str::FromStr;

use futures::{Future, Sink, TryFutureExt};
use futures::sync::mpsc::{channel, Receiver, Sender, unbounded, UnboundedReceiver, UnboundedSender};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::Stream;

use hyxe_netdata::connection::{ConnectionMetadata, EncodingConfig, IpVersion, NetStreamMetadata, ProtocolConfig};

use crate::connection::stream_wrappers::old::{OutboundItem, RawInboundItem};
use crate::packet::misc::ConnectError;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use futures2::compat::Future01CompatExt;
use std::marker::PhantomData;
use hyxe_user::prelude::{NetworkAccount, HyperNodeAccountInformation};
use hyxe_user::client_account::ClientNetworkAccount;
use std::pin::Pin;
use crate::connection::{STREAM_SHUTDOWN, STREAM_RESTART};
use crate::connection::registration::{REGISTRATION_PORT, P12_IDENTITY, P12_PASSWORD};
use crate::packet::definitions::{LOCAL_BIND_ADDR, DEFAULT_IP_VERSION, PORT_START, PORT_END, DEFAULT_AUXILIARY_PORTS, DEFAULT_NETWORK_STACK_PROTOCOL, DEFAULT_ENCODING_SCHEME, LOGIN_PORT};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::atomic::Ordering::SeqCst;
use native_tls::{Identity, TlsConnector};
use tokio_tls::{TlsAcceptor, TlsConnector, TlsStream};

use futures2::{TryStreamExt, FutureExt, StreamExt};

lazy_static! {
    /// For temporary use. The first key is the IpAddr, the second is the port number. Since each CID is unique to each connection,
    /// no overlap should exist unless two connections are tried (this, however, should not happen as logic gates upstream should account for this)
    pub static ref temp_rxs: Arc<RwLock<HashMap<IpAddr, HashMap<u16, (UnboundedReceiver<OutboundItem>, Receiver<u8>)>>>> = Arc::new(RwLock::new(HashMap::new()));
}

/// This is input into temp_rxs above for the first entry
const SERVER_IDX: u64 = 0;

/// This structure is used for each connection to an adjacent end point. It is used to:
/// Send messages, forward inbound messages, stop a connection, restart a connection.
///
/// A [ConnectionHandle] is granted upon the creation of this structure
///
/// NOTE: Since we select() all the connection futures, we only need 1 signal_tx and rx pair... because once one stops, the others stop too.
///
/// This does NOT have any RwLocking or mutexes. As such, there should be only 1 in existence, per [Session] and owned by the [Session] alone.
/// As such, all communication that occurs should go through the session layer.
pub struct ConnectionHandle<'cxn, 'bridge: 'cxn> {
    /// Metadata for the connection (for all possible ports)
    pub metadata: ConnectionMetadata<'cxn>,
    outbound_txs: Vec<UnboundedSender<OutboundItem>>,
    outbound_rxs: Vec<UnboundedReceiver<OutboundItem>>,
    inbound_txs: Vec<UnboundedSender<RawInboundItem>>,
    signal_txs: Vec<Sender<u8>>,
    signal_rxs: Vec<Receiver<u8>>,
    is_engaged: bool,
    is_listener: bool,
    /// This is really only used when needing to check the number of tubings injected. As such, this is just for client connection types
    tubes_injected: AtomicUsize,
    _phantom: PhantomData<&'bridge ()>
}

impl<'cxn, 'bridge: 'cxn> ConnectionHandle<'cxn, 'bridge> {

    /// Creates a new server connection
    pub fn new_server(local_bind_addr: IpAddr, ip_version: IpVersion, port_range: Range<u16>, auxiliary_ports: &[u16; 2], protocol: ProtocolConfig, encoding_scheme: EncodingConfig) -> Pin<Box<Self>> {
        let cid = SERVER_IDX;
        let mut write = temp_rxs.write();
        // Each CID in a network should be unique. If it is not, then this function returns None
        if !write.contains_key(&cid) {
            let _ = write.insert(cid, HashMap::new())?;
        }

        let port_count = port_range.len() + auxiliary_ports.len();

        Box::pin(Self {
            metadata: ConnectionMetadata::new(Some(local_bind_addr), ip_version, None, port_range, auxiliary_ports, protocol, encoding_scheme),
            outbound_txs: Vec::with_capacity(port_count),
            outbound_rxs: Vec::with_capacity(port_count),
            inbound_txs: Vec::with_capacity(port_count),
            signal_txs: Vec::with_capacity(port_count),
            signal_rxs: Vec::with_capacity(port_count),
            is_engaged: false,
            is_listener: true,
            tubes_injected: AtomicUsize::new(0),
            _phantom: Default::default()
        })
    }

    /// Creates a new client connection
    pub fn new_client(local_bind_addr: IpAddr, ip_version: IpVersion, peer_addr: IpAddr, port_range: Range<u16>, auxiliary_ports: &[u16; 2], protocol: ProtocolConfig, encoding_scheme: EncodingConfig) -> Pin<Box<Self>> {
        let mut write = temp_rxs.write();
        // Each CID in a network should be unique. If it is not, then this function returns None
        if !write.contains_key(&peer_addr) {
            let _ = write.insert(peer_addr, HashMap::new())?;
        }

        let port_count = port_range.len() + auxiliary_ports.len();

        Box::pin(Self {
            metadata: ConnectionMetadata::new(Some(local_bind_addr), ip_version, Some(peer_addr), port_range, auxiliary_ports, protocol, encoding_scheme),
            outbound_txs: Vec::with_capacity(port_count),
            outbound_rxs: Vec::with_capacity(port_count),
            inbound_txs: Vec::with_capacity(port_count),
            signal_txs: Vec::with_capacity(port_count),
            signal_rxs: Vec::with_capacity(port_count),
            is_engaged: false,
            is_listener: false,
            tubes_injected: AtomicUsize::new(0),
            _phantom: Default::default()
        })
    }

    /// A convenience method for creating a new server listener array
    pub fn default_server() -> Pin<Box<Self>> {
        Self::new_server(IpAddr::from_str(LOCAL_BIND_ADDR).unwrap(), DEFAULT_IP_VERSION,PORT_START..PORT_END, DEFAULT_AUXILIARY_PORTS, DEFAULT_NETWORK_STACK_PROTOCOL, DEFAULT_ENCODING_SCHEME)
    }

    /// A convenience method for creating a client connection to a unique IP with the default parameters
    pub fn default_client(peer_addr: IpAddr) -> Pin<Box<Self>> {
        Self::new_client(IpAddr::from_str(LOCAL_BIND_ADDR).unwrap(), DEFAULT_IP_VERSION, peer_addr, PORT_START..PORT_END, DEFAULT_AUXILIARY_PORTS, DEFAULT_NETWORK_STACK_PROTOCOL, DEFAULT_ENCODING_SCHEME)
    }

    /// This is the function which should be called by the [Server]. Each server has at least one server-based [ConnectionHandle],
    /// and as such, the 0th handle is the ConnectionHandle
    pub async fn start_server(mut self: Pin<&'cxn mut Self>, inbound_tx: &'bridge UnboundedSender<RawInboundItem>, new_tubing_sender: &'bridge UnboundedSender<(IpAddr, u16, UnboundedSender<OutboundItem>, Sender<u8>)>) -> Result<(), ConnectError> {
        if !&*self.is_listener {
            panic!("You are not allowed to start/setup a server in client mode")
        }

        let futures = self.setup_server(inbound_tx, new_tubing_sender);
        let tls_registration_port_future = self.initiate_tls_listener_at_port(REGISTRATION_PORT, inbound_tx, new_tubing_sender);

        use futures2::future::TryFutureExt;
        futures::future::lazy(move || {
            futures::future::select_all(futures).map(|_| ()).map_err(|err| err.0)
                .select(tls_registration_port_future).map(|_| ()).map_err(|err| err.0)
        }).compat().map_err(|err| ConnectError::Generic(err.to_string())).await
    }

    /// `inbound_tx` is the sender used to merge all packets into one global sink
    fn setup_server(mut self: Pin<&'cxn mut Self>, inbound_tx: &'bridge UnboundedSender<RawInboundItem>, new_tubing_sender: &'bridge UnboundedSender<(IpAddr, u16, UnboundedSender<OutboundItem>, Sender<u8>)>) -> Vec<impl Future<Item=(), Error=ConnectError> + 'cxn> {
        let range = self.metadata.port_range.clone();
        let aux_ports = self.metadata.auxiliary_ports;

        let mut futures = Vec::with_capacity(range.len() + 1);

        for port in range.start..range.end {
            let future = self.initiate_listener_at_port(port, inbound_tx, new_tubing_sender);
            futures.push(future);
        }

        futures.push(self.initiate_listener_at_port(aux_ports[0], inbound_tx, new_tubing_sender));
        //futures.push(self.initiate_listener_at_port(aux_ports[1], inbound_tx, new_tubing_sender));
        // Although we injected only 21 so-far, the caller of the function immediately adds another, giving us 22 total
        self.tubes_injected.store(range.len() + 2, SeqCst);
        
        futures
    }

    /// Starts the server at a given port. Panics if the static entry already has information within it
    /// `inbound_tx`: Forwards data to the globally-unified [StageDriver]
    fn initiate_listener_at_port(mut self: Pin<&'cxn mut Self>, port: u16, inbound_tx: &'bridge UnboundedSender<RawInboundItem>, new_tubing_sender: &'bridge UnboundedSender<(IpAddr, u16, UnboundedSender<OutboundItem>, Sender<u8>)>) -> impl Future<Item=(), Error=ConnectError> + 'cxn {
        let bind_addr = self.metadata.local_bind_addr.unwrap();

        //let (outbound_tx, outbound_rx) = unbounded::<OutboundItem>(); // removed because it makes no sense to send data outbound through a listener
        let (signal_tx, signal_rx) = channel::<u8>(3); // however, we will keep the signallers, because it will allow the server to exit upon signals
        // the ability for the server to exit will be achievable in this manner:
        // The higher-level [ServerBridgeHandler] draws-upon the zeroth-index [ConnectionHandle], and thereafter, call shutdown() which itself invokes the signal which forces this
        // listener to exit

        //self.outbound_txs.push(outbound_tx.clone());
        self.signal_txs.push(signal_tx);
        futures::lazy(move || {
            let local_addr = SocketAddr::new(*bind_addr, port);
            let server = TcpListener::bind(&local_addr).unwrap();

            println!("[Server Listener] {} started!", local_addr.to_string());
            server.incoming().map_err(|err| ConnectError::Generic(err.to_string())).for_each(move |stream| {
                let remote_addr = stream.peer_addr().unwrap();
                let addr = remote_addr.ip();
                println!("[Server] Connection with {} established! (Warning: using 1-1 port mapping)", addr);

                let metadata = NetStreamMetadata::new_client_stream_meta(&addr, remote_addr.port(), &bind_addr, port).unwrap();
                let (outbound_tx, outbound_rx) = unbounded();
                let (signal_tx, signal_rx) = channel(3);

                // in order to allow the server to have individual access to each stream of data, we must create the unique tubes (channels), and send the tubing to both
                // the stream wrapper below as well as to the higher-level [ServerBridgeHandler]. To have control over this stream, we need the ability to send
                // data directly to it, as well as have stop/restart access. As such, we only need two tubes sent via channel back to the [ServerBridgeHandler].
                // The higher-level [ServerBridgeHandler], in turn, will take note of the metadata (e.g., port, ip-addr) to derive the [NetworkAccount] which will
                // be placed within itself. Due to this minor break in architectural symmetry, the [ServerBridgeHandler] will have to create a new [Session] for
                // that new connection, which will in-turn make a new [BridgeHandler], and in turn a new [ConnectionHandle]**. It is necessary that the first packet***
                // obtained in the stream will have to be a DO_LOGIN packet, otherwise, the packet will be unconditionally tossed (to help reduce spam).
                //
                // In summary: The server needs a way to uniquely directly access each stream. We accomplish this with sendable tubing (channels).
                // **: The connection handle will have tubing equal to the tubes created within this closure. This new connection handle CANNOT create a new stream,
                // otherwise, we would have created two streams of information which causes a break in the underlying networking protocol. It is not needed! The server
                // will wait for this closure to send tubing to the higher-level [ServerBridgeHandler] wherein it will create a new [ConnectionHandle] which will await
                // to be filled with the appropriate data
                // ***: The first packet will be a DO_LOGIN on the first auxiliary port. Once the server determines that the login is a success, it will send a
                // DO_LOGIN_SUCCESS packet back to the client. At this point, the server will be expecting this closure, but on other ports, to send, in total, a total
                // of PORT_RANGE*2 tubes (two tubes for each port, where the first tube is for sending data outbound on the newly created stream, and the second tube
                // for stop/restart access to the stream).
                new_tubing_sender.unbounded_send((addr, port, outbound_tx, signal_tx));
                // Below, we send the two receivers created within this closure. We also send the globally-unified sender which forwards data to the [StageDriver]
                crate::connection::stream_wrappers::old::base64(stream, metadata, outbound_rx, inbound_tx.clone(), signal_rx)
            }).map_err(|err| {
                println!("ERR: {:#?}", &err);
                err
            }).map(|_| ()).select(signal_rx.map(|signal| {
                match signal {
                    STREAM_SHUTDOWN => {
                        println!("[AsyncStreamHandler] Shutting down stream");
                        Err(ConnectError::Shutdown)
                    },

                    STREAM_RESTART => {
                        println!("[AsyncStreamHandler] Restarting stream");
                        // TODO: Handle restart signal
                        Err(ConnectError::Restart)
                    },

                    _ => {
                        println!("[AsyncStreamHandler] unknown command!");
                        Ok(())
                    }
                }
            }))
        })
    }

    /// Starts the TLS server at a given port. Panics if the static entry already has information within it
    /// `inbound_tx`: Forwards data to the globally-unified [StageDriver]
    fn initiate_tls_listener_at_port(mut self: Pin<&'cxn mut Self>, port: u16, inbound_tx: &'bridge UnboundedSender<RawInboundItem>, new_tubing_sender: &'bridge UnboundedSender<(IpAddr, u16, UnboundedSender<OutboundItem>, Sender<u8>)>) -> impl Future<Item=(), Error=ConnectError> + 'cxn {
        let bind_addr = self.metadata.local_bind_addr.unwrap();

        //let (outbound_tx, outbound_rx) = unbounded::<OutboundItem>(); // removed because it makes no sense to send data outbound through a listener
        let (signal_tx, signal_rx) = channel::<u8>(3); // however, we will keep the signallers, because it will allow the server to exit upon signals
        // the ability for the server to exit will be achievable in this manner:
        // The higher-level [ServerBridgeHandler] draws-upon the zeroth-index [ConnectionHandle], and thereafter, call shutdown() which itself invokes the signal which forces this
        // listener to exit

        let tls_acceptor = self.get_tls_acceptor()?;

        //self.outbound_txs.push(outbound_tx.clone());
        self.signal_txs.push(signal_tx);
        futures::lazy(move || {
            let local_addr = SocketAddr::new(*bind_addr, port);
            let server = TcpListener::bind(&local_addr).unwrap();

            println!("[TLS Server Listener] {} started!", local_addr.to_string());
            server.incoming().map_err(|err| ConnectError::Generic(err.to_string())).for_each(move |stream| {
                let remote_addr = stream.peer_addr().unwrap();
                let addr = remote_addr.ip();
                tls_acceptor.accept(stream).and_then(move |tls_stream| {
                    println!("[TLS Server] Connection with {} established! (Warning: using 1-1 port mapping)", addr);

                    let metadata = NetStreamMetadata::new_client_stream_meta(&addr, remote_addr.port(), &bind_addr, port).unwrap();
                    let (outbound_tx, outbound_rx) = unbounded();
                    let (signal_tx, signal_rx) = channel(3);


                    new_tubing_sender.unbounded_send((addr, port, outbound_tx, signal_tx));
                    // Below, we send the two receivers created within this closure. We also send the globally-unified sender which forwards data to the [StageDriver]
                    crate::connection::stream_wrappers::old::base64(tls_stream, metadata, outbound_rx, inbound_tx.clone(), signal_rx)
                })
            }).map_err(|err| {
                println!("ERR: {:#?}", &err);
                err
            }).map(|_| ()).select(signal_rx.map(|signal| {
                match signal {
                    STREAM_SHUTDOWN => {
                        println!("[AsyncStreamHandler] Shutting down stream");
                        Err(ConnectError::Shutdown)
                    },

                    STREAM_RESTART => {
                        println!("[AsyncStreamHandler] Restarting stream");
                        // TODO: Handle restart signal
                        Err(ConnectError::Restart)
                    },

                    _ => {
                        println!("[AsyncStreamHandler] unknown command!");
                        Ok(())
                    }
                }
            }))
        })
    }

    /// This is the function which should be called by the [Server]. Each server has at least one server-based [ConnectionHandle],
    /// and as such, the 0th handle is the ConnectionHandle
    ///
    /// `inbound_tx`: The sender which forwards data to the [StageDriver]
    pub async fn start_client(mut self: Pin<&'cxn mut Self>, inbound_tx: &'bridge UnboundedSender<RawInboundItem>) -> Result<(), ConnectError> {
        if self.is_listener {
            panic!("You are not allowed to start/setup a client in server mode")
        }

        let futures = self.setup_client(inbound_tx);
        let tls_registration_port_future = self.initiate_tls_stream_at_port(REGISTRATION_PORT, REGISTRATION_PORT, inbound_tx);

        use futures2::future::TryFutureExt;
        let self_ptr = &mut *self as *mut Self; // This is safe in terms of the self being heap-pinned, however
        // this can possibly cause a data race with the field this pointer will try modifying. The use of this pointer must be
        // restricted to only a singular function, and that function should be gated at a higher-level to prevent any data races
        // herein the lower-levels

        futures::future::lazy(move || {
            futures::future::select_all(futures).map(|_| ()).map_err(|err| err.0)
                .select(tls_registration_port_future).map(|_| ()).map_err(|err| err.0)
        }).compat().map_err(|err| ConnectError::Generic(err.to_string())).await
    }

    /// `inbound_tx` is the sender used to merge all packets into one global sink
    fn setup_client(mut self: Pin<&'cxn mut Self>, inbound_tx: &'bridge UnboundedSender<RawInboundItem>) -> Vec<impl Future<Item=(), Error=ConnectError> + 'cxn> {
        let range = self.metadata.port_range.clone();
        let aux_ports = self.metadata.auxiliary_ports;

        println!("[Client WARNING] The current configuration assumes 1-1 port mapping (i.e., port_local == port_remote)");

        let mut futures = Vec::with_capacity(range.len() + 1);

        for port in range.start..range.end {
            let future = self.initiate_stream_at_port(port, port, inbound_tx);
            futures.push(future);
        }

        futures.push(self.initiate_stream_at_port(LOGIN_PORT, LOGIN_PORT, inbound_tx));
        //futures.push(self.initiate_listener_at_port(aux_ports[1], inbound_tx, new_tubing_sender));

        // Although we injected only 21 so-far, the caller of the function immediately adds another, giving us 22 total
        self.tubes_injected.store(range.len() + 2 , SeqCst);
        
        futures
    }

    /// Starts the client stream at a given port. Panics if the static entry already has information within it
    fn initiate_stream_at_port(mut self: Pin<&'cxn mut Self>, port_local: u16, port_remote: u16, inbound_tx: &'bridge UnboundedSender<RawInboundItem>) -> impl Future<Item=(), Error=ConnectError> + 'cxn {
        let bind_addr = self.metadata.local_bind_addr.unwrap();
        let remote_addr_ip = self.metadata.peer_addr.unwrap();

        let (outbound_tx, outbound_rx) = unbounded::<OutboundItem>();
        let (signal_tx, signal_rx) = channel::<u8>(3);

        assert!(temp_rxs.write().get_mut(&remote_addr_ip).unwrap().insert(port_local, (outbound_rx, signal_rx)).is_none()); // add outbound_rx to static table. This will cause a panic if there is a duplicate CID

        self.outbound_txs.push(outbound_tx);
        self.signal_txs.push(signal_tx);
        futures::lazy(move || {
            let local_addr = SocketAddr::new(*bind_addr, port_local);
            let remote_addr = SocketAddr::new(*remote_addr, port_local);
            let client = TcpStream::connect(&remote_addr);

            println!("[Client Stream] {} started!", local_addr.to_string());
            client.map_err(|err| ConnectError::Generic(err.to_string())).and_then(move |stream| {
                success!("[Client] Connection with {} established!", &remote_addr);

                let metadata = NetStreamMetadata::new_client_stream_meta(&remote_addr_ip, remote_addr.port(), &bind_addr, port_local).unwrap();
                let (outbound_rx, signal_rx) = temp_rxs.write().get_mut(&remote_addr_ip).unwrap().remove(&port_local).unwrap();

                crate::connection::stream_wrappers::old::base64(stream, metadata, outbound_rx, inbound_tx.clone(), signal_rx)
            }).map_err(|err| {
                println!("ERR: {:#?}", &err);
                err
            }).map(|_| ())
        })
    }

    /// Starts the TLS client stream at a given port. Panics if the static entry already has information within it
    fn initiate_tls_stream_at_port(mut self: Pin<&'cxn mut Self>, port_local: u16, port_remote: u16, inbound_tx: &'bridge UnboundedSender<RawInboundItem>) -> impl Future<Item=(), Error=ConnectError> + 'cxn {
        let bind_addr = self.metadata.local_bind_addr.unwrap();
        let remote_addr_ip = self.metadata.peer_addr.unwrap();

        let (outbound_tx, outbound_rx) = unbounded::<OutboundItem>();
        let (signal_tx, signal_rx) = channel::<u8>(3);


        assert!(temp_rxs.write().get_mut(&remote_addr_ip).unwrap().insert(port_local, (outbound_rx, signal_rx)).is_none()); // add outbound_rx to static table. This will cause a panic if there is a duplicate IpAddr

        self.outbound_txs.push(outbound_tx);
        self.signal_txs.push(signal_tx);
        futures::lazy(move || {
            let local_addr = SocketAddr::new(*bind_addr, port_local);
            let remote_addr = SocketAddr::new(*remote_addr, port_local);
            let client = TcpStream::connect(&remote_addr);

            let cx = native_tls::TlsConnector::builder().build().unwrap();
            let cx = tokio_tls::TlsConnector::from(cx);

            // We connect to the domain=IP with no port, but the socket should have the port
            let mut client = cx.connect(&remote_addr_ip.to_string(), remote_addr).await?;

            println!("[Client Stream] {} started!", local_addr.to_string());
            client.map_err(|err| ConnectError::Generic(err.to_string())).and_then(move |stream| {
                success!("[Client] Connection with {} established!", &remote_addr);

                let metadata = NetStreamMetadata::new_client_stream_meta(&remote_addr_ip, remote_addr.port(), &bind_addr, port_local).unwrap();
                let (outbound_rx, signal_rx) = temp_rxs.write().get_mut(&remote_addr_ip).unwrap().remove(&port_local).unwrap();

                crate::connection::stream_wrappers::old::base64(stream, metadata, outbound_rx, inbound_tx.clone(), signal_rx)
            }).map_err(|err| {
                println!("ERR: {:#?}", &err);
                err
            }).map(|_| ())
        })
    }

    /// This sends the data to the underlying stream. Make sure that the packet is completely built before this gate!
    /// This sends data into the codec layer.
    #[allow(unused)]
    pub fn send_outbound(&self, send_port: u16, remote_receive_port: u16, data: OutboundItem) -> Result<(), ConnectError> {
        if !self.is_engaged() {
            return Err(ConnectError::SystemNotEngaged);
        }

        match self.outbound_txs.get((send_port - self.metadata.port_range.start) as usize) {
            Some(tube) => {
                tube.unbounded_send(data).map_err(|err| ConnectError::Generic(err.to_string()))
            }
            _ => {
                Err(ConnectError::PortNotActive)
            }
        }
    }

    /// Stops the connection. This is unsafe, because it abruptly stops the connection due to the underlying futures-select() mechanism. Make sure to to implement a proper shutdown sequence
    /// in such a way that all connected clients (in server mode), or, the adjacent node is shutdown.
    /// 
    /// TODO: Implement safe shutdown alert system
    pub unsafe fn shutdown(&mut self) -> Result<(), ConnectError> {
        if !self.is_engaged() {
            return Err(ConnectError::SystemNotEngaged)
        }

        self.tubes_injected.store(0, Ordering::SeqCst);
        self.is_engaged = false;
        
        for signaller in &self.signal_txs {
            signaller.clone()
                .send(STREAM_SHUTDOWN)
                .map_err(|err| ConnectError::Generic(err.to_string()))
                .and_then(|_| Ok(()))?
        }

        self.outbound_txs.clear();
        self.outbound_rxs.clear();
        self.signal_txs.clear();
        self.signal_rxs.clear();
        
        Ok(())
    }

    /// Restarts the connection, setting up an .awaitable return
    /// `new_tubing_sender`: Use None if this is a pure client connection. Else, supply Some. This should be called by the higher-level [BridgeHandler] or [ServerBridgeHandler]
    ///
    /// panics if self is a server type of connection and None is supplied for `new_tubing_sender`
    pub async fn restart_connection(&'cxn mut self, inbound_tx: &'bridge UnboundedSender<RawInboundItem>, new_tubing_sender: Option<&'bridge UnboundedSender<(IpAddr, u16, UnboundedSender<OutboundItem>, Sender<u8>)>>) -> Result<(), ConnectError> {
        unsafe { self.shutdown() };
        
        if self.is_listener {
            self.start_server(inbound_tx, new_tubing_sender.unwrap()).await
        } else {
            self.start_client(inbound_tx).await
        }
        
    }

    /// Injects tubing into this structure in order to allow communication into a particular port. This returns true if all the tubes are loaded
    pub fn inject_tubing(&mut self, local_port: u16, stream_outbound_tx: UnboundedSender<OutboundItem>, stream_signal_tx: Sender<u8>) -> Result<bool, ConnectError> {
        let idx = (local_port - PORT_START) as usize;
        debug_assert!(idx <= self.outbound_txs.capacity());

        self.outbound_txs.insert(idx, stream_outbound_tx);
        self.signal_txs.insert(idx, stream_signal_tx);

        if self.tubes_injected.fetch_add(1, Ordering::SeqCst) + 1 == self.outbound_txs.capacity() {
            self.is_engaged = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Generates the TLS acceptor which can be used to handle TCP Streams
    fn get_tls_acceptor(&self) -> Result<TlsAcceptor, ConnectError> {
        let p12 = include_bytes!(P12_IDENTITY);
        let cert = Identity::from_pkcs12(p12, P12_PASSWORD)?;
        Ok(tokio_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build().map_err(|err| ConnectError::InvalidTlsConfiguration)?))
    }

    /// Automatically atomically increments the number of packets sent as well as the object ID, returning the next object ID
    /// This is what the [BridgeHandler] should always call
    #[allow(unused)]
    pub fn tally_and_get_eid_oid(&self, packet_count: usize) -> usize {
        self.get_and_increment_packets_sent_by(count);
        self.get_and_increment_objects_sent() // this starts at one, so getting and setting will return 1 at first. 0 is an internally reserved value
    }

    /// This should be called by the higher-level [BridgeHandler]
    pub fn get_and_increment_packets_sent(&self) -> usize {
        self.metadata.get_and_increment_packets_sent()
    }

    /// Adds `count` to the underlying atomic packet count. Returns the previous amount of packets
    pub fn get_and_increment_packets_sent_by(&self, count: usize) -> usize {
        self.metadata.get_and_increment_packets_sent_by(count)
    }

    /// This should be called by self. This should be called along with `get_and_increment_packets_sent_by` to ensure the proper packet count exists
    pub fn get_and_increment_objects_sent(&self) -> usize {
        self.metadata.get_and_increment_packets_sent()
    }

    /// Adds `count` to the underlying atomic packet count. Returns the previous amount of packets
    pub fn get_and_increment_objects_sent_by(&self, count: usize) -> usize {
        self.metadata.get_and_increment_packets_sent_by(count)
    }

    /// Returns true if the connection is a client-type
    pub fn is_client_connection(&self) -> bool {
        !self.is_listener
    }

    /// Returns true if the connection is a client-type
    pub fn is_listener(&self) -> bool {
        self.is_listener
    }

    /// Returns true if the listener or stream is engaged. All 22 ports must be active
    pub fn is_engaged(&self) -> bool {
        self.is_engaged && self.tubes_injected.load(SeqCst) == self.outbound_txs.capacity()
    }

}