#![feature(try_trait, decl_macro, result_flattening)]

#[cfg(test)]
pub mod tests {
    use std::error::Error;
    use hyxe_net::hdp::hdp_server::{HdpServerRequest, HdpServerRemote, Ticket, ConnectMode, UnderlyingProtocol};
    use crate::tests::kernel::{TestKernel, TestContainer, ActionType};
    use hyxe_net::kernel::kernel_executor::KernelExecutor;
    use hyxe_nat::hypernode_type::HyperNodeType;
    use hyxe_user::account_manager::AccountManager;
    use hyxe_net::hdp::hdp_packet_processor::includes::{SocketAddr, Duration};
    use std::str::FromStr;
    use hyxe_user::proposed_credentials::ProposedCredentials;
    use hyxe_crypt::drill::SecurityLevel;
    use std::sync::Arc;
    use parking_lot::{RwLock, Mutex, const_mutex};
    use hyxe_net::functional::{TriMap, PairMap};
    use hyxe_net::hdp::peer::peer_layer::{PeerSignal, PeerConnectionType};
    use hyxe_net::hdp::peer::channel::PeerChannel;
    use hyxe_crypt::sec_bytes::SecBuffer;
    use futures::{StreamExt, SinkExt, Future};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use crate::utils::{AssertSendSafeFuture, assert, assert_eq};
    use byteorder::ByteOrder;
    use hyxe_net::hdp::state_container::VirtualConnectionType;
    use hyxe_net::error::NetworkError;
    use hyxe_net::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
    use tokio::runtime::{Builder, Runtime};
    use hyxe_net::hdp::peer::message_group::MessageGroupKey;
    use hyxe_crypt::hyper_ratchet::constructor::{HyperRatchetConstructor, BobToAliceTransferType};
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_user::fcm::kem::FcmPostRegister;
    use hyxe_crypt::fcm::keys::FcmKeys;
    use hyxe_user::backend::BackendType;
    use hyxe_net::hdp::misc::net::TlsListener;
    use tokio::net::{TcpListener, TcpStream};
    use std::pin::Pin;
    use std::time::Instant;

    const COUNT: usize = 500;
    const TIMEOUT_CNT_MS: usize = 10000 + (COUNT * 50);

    #[allow(dead_code)]
    fn gen(cid: u64, vers: u32, sec: Option<SecurityLevel>) -> (HyperRatchet, HyperRatchet) {
        let mut alice_con = HyperRatchetConstructor::new_alice(None, cid, vers, sec);
        let bob_con = HyperRatchetConstructor::new_bob(0, cid, vers, alice_con.stage0_alice()).unwrap();
        alice_con.stage1_alice(&bob_con.stage0_bob().map(BobToAliceTransferType::Default).unwrap()).unwrap();
        (alice_con.finish().unwrap(), bob_con.finish().unwrap())
    }

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        //std::env::set_var("RUST_LOG", "error");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    fn flatten_err<T, E: ToString>(err: Result<Result<T, NetworkError>, E>) -> Result<T, NetworkError> {
        err.map_err(|err| NetworkError::Generic(err.to_string())).flatten()
    }

    fn function(f: Pin<Box<dyn Future<Output=Option<ActionType>> + Send + 'static>>) -> ActionType {
        ActionType::Function(f)
    }

    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub enum NodeType {
        Server,
        Client0,
        Client1,
        Client2,
    }

    fn backend_server() -> BackendType {
        if USE_FILESYSYEM {
            BackendType::Filesystem
        } else {
            BackendType::sql("mysql://nologik:mrmoney10@localhost/hyxewave")
        }
    }

    fn backend_client() -> BackendType {
        BackendType::Filesystem
    }

    static PROTO: Mutex<Option<UnderlyingProtocol>> = const_mutex(None);
    const USE_FILESYSYEM: bool = true;

    fn underlying_proto() -> UnderlyingProtocol {
        let lock = PROTO.lock();
        lock.as_ref().unwrap().clone()
    }

    #[tokio::test]
    async fn tls() {
        setup_log();
        const PKCS: &str = "/Users/nologik/satori.net/keys/devonly.pkcs";
        const CERT: &str = "/Users/nologik/satori.net/keys/devonly.crt";

        let identity = TlsListener::load_tls_pkcs(PKCS, "mrmoney10").unwrap();
        let cert = TlsListener::load_tls_cert(CERT).unwrap();
        let identity2 = identity.clone();

        // We need to use danger_accept_invalid_certs in the dev setting b/c self-signed certs are invalid. We can use letsencrypt follwed by an ACME challenge to generate the right certs

        let f1 = tokio::task::spawn(AssertSendSafeFuture::new_silent(async move {
            let listener = TcpListener::bind("127.0.0.1:27000").await.unwrap();
            let mut tls_listener = TlsListener::new(listener, identity).unwrap();
            while let Some(conn) = tls_listener.next().await {
                match conn {
                    Ok((_stream, addr)) => {
                        log::info!("Received conn from {:?}", addr);
                        tokio::time::sleep(Duration::from_millis(1000)).await;
                        return;
                    }

                    Err(err) => {
                        log::error!("Error accepting stream: {:?}", err);
                        return;
                    }
                }
            }
        }));

        let f2 = tokio::task::spawn(async move {
            let stream = TcpStream::connect("127.0.0.1:27000").await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let connector = tokio_native_tls::native_tls::TlsConnector::builder().use_sni(true).danger_accept_invalid_certs(true).build().map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err)).unwrap();
            let connector = tokio_native_tls::TlsConnector::from(connector);
            let stream = connector.connect("", stream).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err)).unwrap();
            log::info!("[Client] Success connecting to {:?}", stream.get_ref().get_ref().get_ref().peer_addr().unwrap());
        });

        let _ = tokio::join!(f1, f2).map(|r1, r2| r1.and(r2));

    }

    fn pinbox<F: Future<Output=Option<ActionType>> + 'static>(f: F) -> Pin<Box<dyn Future<Output=Option<ActionType>> + Send + 'static>> {
        Box::pin(AssertSendSafeFuture::new_silent(f))
    }

    #[test]
    fn main() -> Result<(), Box<dyn Error>> {
        super::utils::deadlock_detector();
        //*PROTO.lock() = Some(UnderlyingProtocol::Tls(TlsListener::load_tls_pkcs("/Users/nologik/satori.net/keys/devonly.pkcs", "mrmoney10").unwrap()));
        *PROTO.lock() = Some(UnderlyingProtocol::Tcp);
        let rt = Arc::new(Builder::new_multi_thread().enable_time().enable_io().build().unwrap());

        setup_log();
        let server_bind_addr = SocketAddr::from_str("127.0.0.1:33332").unwrap();
        let client0_bind_addr = SocketAddr::from_str("127.0.0.1:33333").unwrap();
        let client1_bind_addr = SocketAddr::from_str("127.0.0.1:33334").unwrap();
        let client2_bind_addr = SocketAddr::from_str("127.0.0.1:33335").unwrap();

        let security_level = SecurityLevel::LOW;
        let p2p_security_level = SecurityLevel::LOW;

        static CLIENT0_FULLNAME: &'static str = "Thomas P Braun (test)";
        static CLIENT0_USERNAME: &'static str = "nologik";
        static CLIENT0_PASSWORD: &'static str = "mrmoney10";

        static CLIENT1_FULLNAME: &'static str = "Thomas P Braun I (test)";
        static CLIENT1_USERNAME: &'static str = "nologik1";
        static CLIENT1_PASSWORD: &'static str = "mrmoney10";

        static CLIENT2_FULLNAME: &'static str = "Thomas P Braun II (test)";
        static CLIENT2_USERNAME: &'static str = "nologik2";
        static CLIENT2_PASSWORD: &'static str = "mrmoney10";





        let (proposed_credentials_0, proposed_credentials_1, proposed_credentials_2) = rt.block_on(async move {
            let p_0 = ProposedCredentials::new_register(CLIENT0_FULLNAME, CLIENT0_USERNAME, SecBuffer::from(CLIENT0_PASSWORD)).await.unwrap();
            let p_1 = ProposedCredentials::new_register(CLIENT1_FULLNAME, CLIENT1_USERNAME, SecBuffer::from(CLIENT1_PASSWORD)).await.unwrap();
            let p_2 = ProposedCredentials::new_register(CLIENT2_FULLNAME, CLIENT2_USERNAME, SecBuffer::from(CLIENT2_PASSWORD)).await.unwrap();
            (p_0, p_1, p_2)
        });

        let init = Instant::now();

        const ENABLE_FCM: bool = false;
        let keys0 = ENABLE_FCM.then(||FcmKeys::new("123", "456"));
        let keys1 = keys0.clone();
        let keys2 = keys0.clone();

        let test_container = Arc::new(RwLock::new(TestContainer::new()));
        let test_container0 = test_container.clone();
        let test_container1 = test_container.clone();
        let test_container2 = test_container.clone();
        let test_container3 = test_container.clone();
        let test_container4 = test_container.clone();
        let test_container5 = test_container.clone();
        let test_container6 = test_container.clone();


        let rt_main = rt.clone();

        rt_main.block_on(async move {
            log::info!("Setting up executors ...");
            let server_executor = create_executor(HyperNodeType::GloballyReachable, rt.clone(), server_bind_addr, Some(test_container.clone()), NodeType::Server, Vec::default(), backend_server()).await;
            log::info!("Done setting up server executor");
            let client0_executor = create_executor(HyperNodeType::BehindResidentialNAT, rt.clone(), client0_bind_addr, Some(test_container.clone()), NodeType::Client0, {
                vec![ActionType::Request(HdpServerRequest::RegisterToHypernode(server_bind_addr, proposed_credentials_0, None, keys0, security_level, underlying_proto())),
                     function(pinbox(client0_action1(test_container0, CLIENT0_PASSWORD, security_level))),
                     function(pinbox(client0_action2(test_container1, ENABLE_FCM))),
                     function(pinbox(client0_action3(test_container2, p2p_security_level)))
                ]
            }, backend_client()).await;

            let client1_executor = create_executor(HyperNodeType::BehindResidentialNAT, rt.clone(), client1_bind_addr, Some(test_container.clone()), NodeType::Client1, {
                vec![ActionType::Request(HdpServerRequest::RegisterToHypernode(server_bind_addr, proposed_credentials_1, None, keys1, security_level, underlying_proto())),
                     function(pinbox(client1_action1(test_container3, CLIENT1_PASSWORD, security_level)))
                ]
            }, backend_client()).await;

            let client2_executor = create_executor(HyperNodeType::BehindResidentialNAT, rt.clone(), client2_bind_addr, Some(test_container.clone()), NodeType::Client2, {
                vec![ActionType::Request(HdpServerRequest::RegisterToHypernode(server_bind_addr, proposed_credentials_2, None, keys2, security_level, underlying_proto())),
                     function(pinbox(client2_action1(test_container4, CLIENT2_PASSWORD, security_level))),
                     function(pinbox(client2_action2(test_container5, ENABLE_FCM))),
                     function(pinbox(client2_action3_start_group(test_container6)))
                ]
            }, backend_client()).await;

            log::info!("Done setting up executors");

            let server_future = async move { server_executor.execute().await };
            let client0_future = tokio::task::spawn(tokio::time::timeout(Duration::from_millis(TIMEOUT_CNT_MS as u64), AssertSendSafeFuture::new_silent(async move { client0_executor.execute().await })));
            let client1_future = tokio::task::spawn(tokio::time::timeout(Duration::from_millis(TIMEOUT_CNT_MS as u64), AssertSendSafeFuture::new_silent(async move { client1_executor.execute().await })));
            let client2_future = tokio::task::spawn(tokio::time::timeout(Duration::from_millis(TIMEOUT_CNT_MS as u64), AssertSendSafeFuture::new_silent(async move { client2_executor.execute().await })));

            let server = tokio::task::spawn(AssertSendSafeFuture::new_silent(server_future));
            tokio::time::sleep(Duration::from_millis(100)).await;

            //futures::future::try_join_all(vec![client0_future, client1_future]).await.map(|res|)
            tokio::try_join!(client0_future, client1_future, client2_future)?.map(|res0, res1, res2| flatten_err(res0).and(flatten_err(res1)).and(flatten_err(res2)))?;

            log::info!("Ending test (client(s) done) ...");

            let _ = tokio::time::timeout(Duration::from_millis(100), server).await;

            log::info!("Execution time: {}ms", init.elapsed().as_millis());
            Ok(())
        })
    }

    #[allow(unused_results)]
    async fn create_executor(hypernode_type: HyperNodeType, rt: Arc<Runtime>, bind_addr: SocketAddr, test_container: Option<Arc<RwLock<TestContainer>>>, node_type: NodeType, commands: Vec<ActionType>, backend_type: BackendType) -> KernelExecutor<TestKernel> {
        let account_manager = AccountManager::new(bind_addr, Some(format!("/Users/nologik/tmp/{}_{}", bind_addr.ip(), bind_addr.port())), backend_type).await.unwrap();
        account_manager.purge().await.unwrap();
        let kernel = TestKernel::new(node_type, commands, test_container);
        KernelExecutor::new(rt, hypernode_type, account_manager, kernel, bind_addr, underlying_proto()).await.unwrap()
    }

    pub mod kernel {
        use hyxe_net::kernel::kernel::NetKernel;
        use hyxe_net::hdp::hdp_server::{HdpServerRemote, HdpServerResult, HdpServerRequest, Ticket};
        use hyxe_net::error::NetworkError;
        use std::collections::{HashSet, VecDeque};
        use parking_lot::{Mutex, RwLock};
        use hyxe_net::hdp::hdp_packet_processor::includes::Duration;
        use async_trait::async_trait;
        use std::sync::Arc;
        use hyxe_user::client_account::ClientNetworkAccount;
        use crate::tests::{NodeType, handle_peer_channel, COUNT, CLIENT_SERVER_MESSAGE_STRESS_TEST, start_client_server_stress_test, GROUP_TICKET_TEST, client2_action4_fire_group};
        use hyxe_net::hdp::peer::peer_layer::{PeerSignal, PeerResponse};
        use byteorder::ByteOrder;
        use hyxe_net::hdp::hdp_packet_processor::peer::group_broadcast::{GroupBroadcast, MemberState};
        use crate::utils::{assert_eq, assert};
        use tokio::sync::broadcast;
        use futures::Future;
        use async_recursion::async_recursion;
        use std::pin::Pin;

        #[derive(Default)]
        pub struct TestContainer {
            pub cnac_client0: Option<ClientNetworkAccount>,
            pub cnac_client1: Option<ClientNetworkAccount>,
            pub cnac_client2: Option<ClientNetworkAccount>,
            pub remote_client0: Option<HdpServerRemote>,
            pub remote_client1: Option<HdpServerRemote>,
            pub remote_client2: Option<HdpServerRemote>,
            pub queued_requests_client0: Option<Arc<Mutex<HashSet<Ticket>>>>,
            pub queued_requests_client1: Option<Arc<Mutex<HashSet<Ticket>>>>,
            pub queued_requests_client2: Option<Arc<Mutex<HashSet<Ticket>>>>,
            pub can_begin_peer_post_register_recv: Option<VecDeque<broadcast::Receiver<()>>>,
            pub can_begin_peer_post_register_notifier_cl_1: Option<broadcast::Sender<()>>,
            pub client_server_as_server_recv_count: usize,
            pub client_server_as_client_recv_count: usize,
            pub group_members_entered_for_client2: usize,
            pub group_messages_received_client0: usize,
            pub group_messages_received_client1: usize,
            pub group_messages_verified_client2_host: usize,
            pub client_server_stress_test_done_as_client: bool,
            pub client_server_stress_test_done_as_server: bool,
        }

        impl TestContainer {
            pub fn new() -> Self {
                let (can_begin_peer_post_register_notifier_cl_1, can_begin_peer_post_register_recv_cl_0) = broadcast::channel(10);
                let can_begin_peer_post_register_recv_cl_2 = can_begin_peer_post_register_notifier_cl_1.subscribe();
                // client 0 and 2 must wait for client 1 to connect
                let mut can_begin_peer_post_register_recv = VecDeque::with_capacity(2);
                can_begin_peer_post_register_recv.push_back(can_begin_peer_post_register_recv_cl_0);
                can_begin_peer_post_register_recv.push_back(can_begin_peer_post_register_recv_cl_2);
                let can_begin_peer_post_register_recv = Some(can_begin_peer_post_register_recv);

                let can_begin_peer_post_register_notifier_cl_1 = Some(can_begin_peer_post_register_notifier_cl_1);

                Self { can_begin_peer_post_register_notifier_cl_1, can_begin_peer_post_register_recv, ..Default::default() }
            }
        }

        pub enum ActionType {
            Request(HdpServerRequest),
            Function(Pin<Box<dyn Future<Output=Option<ActionType>> + Send + 'static>>),
        }

        pub struct TestKernel {
            node_type: NodeType,
            commands: Mutex<Vec<ActionType>>,
            remote: Option<HdpServerRemote>,
            // a ticket gets added once a request is submitted. Once a VALID response occurs, the entry is removed. If an invalid response is received, then the ticket lingers, then the timer throws an error
            queued_requests: Arc<Mutex<HashSet<Ticket>>>,
            item_container: Option<Arc<RwLock<TestContainer>>>,
            ctx_cid: Mutex<Option<u64>>,
        }

        impl TestKernel {
            pub fn new(node_type: NodeType, commands: Vec<ActionType>, item_container: Option<Arc<RwLock<TestContainer>>>) -> Self {
                Self { node_type, commands: Mutex::new(commands), remote: None, queued_requests: Arc::new(Mutex::new(HashSet::new())), item_container, ctx_cid: Mutex::new(None) }
            }

            #[async_recursion]
            async fn execute_action(&self, request: ActionType, remote: &HdpServerRemote) {
                match request {
                    ActionType::Request(request) => {
                        let ticket = remote.unbounded_send(request).unwrap();
                        assert(self.queued_requests.lock().insert(ticket), "KLP");
                    }

                    ActionType::Function(fx) => {
                        // execute the created action, or, run the next enqueued action
                        if let Some(request) = fx.await {
                            self.execute_action(request, remote).await;
                        } else {
                            self.execute_next_action().await;
                        }
                    }
                }
            }

            #[async_recursion]
            async fn execute_next_action(&self) {
                if self.node_type != NodeType::Server {
                    let remote = self.remote.as_ref().unwrap();
                    let item = {
                        let mut lock = self.commands.lock();
                        if lock.len() != 0 {
                            log::info!("[TEST] Executing next action for {:?} ...", self.node_type);
                            let item = lock.remove(0);
                            std::mem::drop(lock);
                            item
                        } else {
                            return;
                        }
                    };

                    self.execute_action(item, remote).await;

                }
            }

            fn on_valid_ticket_received(&self, ticket: Ticket) {
                if self.node_type != NodeType::Server {
                    assert(self.queued_requests.lock().remove(&ticket), "EXCV");
                    log::info!("{:?} checked-in ticket {}", self.node_type, ticket);
                }
            }

            #[allow(dead_code)]
            fn shutdown_in(&self, time: Option<Duration>) {
                let remote = self.remote.clone().unwrap();
                if let Some(time) = time {
                    tokio::task::spawn(async move {
                        tokio::time::sleep(time).await;
                        remote.shutdown().unwrap();
                    });
                } else {
                    remote.shutdown().unwrap();
                }
            }
        }

        #[async_trait]
        impl NetKernel for TestKernel {
            async fn on_start(&mut self, server_remote: HdpServerRemote) -> Result<(), NetworkError> {
                log::info!("Running node {:?} onStart", self.node_type);
                if self.node_type != NodeType::Server {
                    let item = {
                        self.commands.lock().remove(0)
                    };

                    self.execute_action(item, &server_remote).await;
                    let container = self.item_container.as_ref().unwrap();
                    let mut write = container.write();
                    if self.node_type == NodeType::Client0 {
                        write.remote_client0 = Some(server_remote.clone());
                        write.queued_requests_client0 = Some(self.queued_requests.clone());
                    } else if self.node_type == NodeType::Client1 {
                        write.remote_client1 = Some(server_remote.clone());
                        write.queued_requests_client1 = Some(self.queued_requests.clone());
                    } else if self.node_type == NodeType::Client2 {
                        write.remote_client2 = Some(server_remote.clone());
                        write.queued_requests_client2 = Some(self.queued_requests.clone());
                    } else {
                        log::error!("Unaccounted node type {:?}", self.node_type);
                        assert(false, "TTT");
                    }
                }

                self.remote = Some(server_remote);
                Ok(())
            }

            async fn on_server_message_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
                log::info!("[{:?}] Message received: {:?}", self.node_type, &message);
                if self.node_type != NodeType::Server || message.is_message() {
                    match message {
                        HdpServerResult::ConnectFail(..) | HdpServerResult::RegisterFailure(..) => {
                            assert(false, "Register/Connect failed");
                        }

                        HdpServerResult::GroupEvent(implicated_cid, ticket, group) => {
                            match group {
                                GroupBroadcast::Invitation(key) => {
                                    log::info!("{:?} Received an invitation to group {}", self.node_type, key);
                                    // accept it
                                    if self.node_type == NodeType::Client0 || self.node_type == NodeType::Client1 {
                                        let accept = GroupBroadcast::AcceptMembership(key);
                                        let remote = self.remote.clone().unwrap();
                                        remote.send_with_custom_ticket(ticket, HdpServerRequest::GroupBroadcastCommand(implicated_cid, accept)).unwrap();
                                    } else {
                                        return Err(NetworkError::InternalError("Invalid group invitation recipient"));
                                    }
                                }

                                GroupBroadcast::CreateResponse(Some(key)) => {
                                    log::info!("[Group] Successfully created group {} for {:?}", key, self.node_type);
                                    assert(self.node_type == NodeType::Client2, "FTQ");
                                    // Even as the host, we do nothing here. We wait until both members joined the room
                                    //self.on_valid_ticket_received(GROUP_TICKET_TEST);
                                    /*
                                    let remote = self.remote.clone().unwrap();

                                    tokio::task::spawn(async move {
                                        tokio::time::sleep(Duration::from_millis(500)).await;
                                        remote.shutdown().unwrap();
                                    });*/
                                }

                                GroupBroadcast::AcceptMembershipResponse(success) => {
                                    // client 1 & 0 will get this
                                    assert(self.node_type == NodeType::Client0 || self.node_type == NodeType::Client1, "EQW");
                                    assert(success, "YTR");
                                    log::info!("[Group] Successfully entered* group for {:?}? {}", self.node_type, success);
                                    /*
                                    let remote = self.remote.clone().unwrap();
                                    self.on_valid_ticket_received(GROUP_TICKET_TEST);
                                    // We don't have to do anything here; we just wait for group messages to start
                                    // pouring-in

                                    tokio::task::spawn(async move {
                                        tokio::time::sleep(Duration::from_millis(500)).await;
                                        remote.shutdown().unwrap();
                                    });*/
                                }

                                GroupBroadcast::MemberStateChanged(key, state) => {
                                    if self.node_type == NodeType::Client2 {
                                        log::info!("[Group] Member state changed: {:?}", &state);
                                        match state {
                                            MemberState::EnteredGroup(peers) => {
                                                let mut lock = self.item_container.as_ref().unwrap().write();
                                                lock.group_members_entered_for_client2 += peers.len();

                                                if lock.group_members_entered_for_client2 == 2 {
                                                    log::info!("[Group] Client2/Host will now begin group stress test ...");
                                                    let test_container = self.item_container.clone().unwrap();
                                                    std::mem::drop(lock);
                                                    /*
                                                    let remote = self.remote.clone().unwrap();
                                                    self.on_valid_ticket_received(GROUP_TICKET_TEST);

                                                    tokio::task::spawn(async move {
                                                        tokio::time::sleep(Duration::from_millis(500)).await;
                                                        remote.shutdown().unwrap();
                                                    });*/
                                                    client2_action4_fire_group(test_container, key, ticket);
                                                }
                                            }

                                            _ => {}
                                        }
                                    }
                                }

                                GroupBroadcast::Message(_, _, msg) => {
                                    let val = byteorder::BigEndian::read_u64(msg.as_ref());
                                    assert(val <= COUNT as u64, "DFT");
                                    assert(self.node_type == NodeType::Client0 || self.node_type == NodeType::Client1, "LKJ");
                                    let mut lock = self.item_container.as_ref().unwrap().write();
                                    let count = if self.node_type == NodeType::Client0 {
                                        lock.group_messages_received_client0 += 1;
                                        lock.group_messages_received_client0
                                    } else {
                                        lock.group_messages_received_client1 += 1;
                                        lock.group_messages_received_client1
                                    };

                                    log::info!("[Group] {:?} received {} messages", self.node_type, lock.group_messages_received_client0);

                                    if count >= COUNT {
                                        log::info!("[Group] {:?} is done receiving messages", self.node_type);
                                        self.on_valid_ticket_received(GROUP_TICKET_TEST);
                                        let remote = self.remote.clone().unwrap();
                                        tokio::task::spawn(async move {
                                            tokio::time::sleep(Duration::from_millis(500)).await;
                                            remote.shutdown().unwrap();
                                        });
                                    }
                                }

                                GroupBroadcast::MessageResponse(_, success) => {
                                    assert(success, "UQE");
                                    assert(self.node_type == NodeType::Client2, "KZMT");
                                    let mut lock = self.item_container.as_ref().unwrap().write();
                                    lock.group_messages_verified_client2_host += 1;

                                    if lock.group_messages_verified_client2_host >= COUNT {
                                        log::info!("[Group] {:?}/Host has successfully sent all messages", self.node_type);
                                        self.on_valid_ticket_received(GROUP_TICKET_TEST);
                                        let remote = self.remote.clone().unwrap();
                                        tokio::task::spawn(async move {
                                            tokio::time::sleep(Duration::from_millis(500)).await;
                                            remote.shutdown().unwrap();
                                        });
                                    }
                                }

                                _ => {}
                            }
                        }

                        HdpServerResult::MessageDelivery(_, _, msg) => {
                            log::info!("{:?} Message delivery **", self.node_type);
                            let container = self.item_container.as_ref().unwrap();
                            let mut lock = container.write();

                            match self.node_type {
                                NodeType::Client0 => {
                                    // client0 already had its sender started. We only need to increment the inner count
                                    let val = byteorder::BigEndian::read_u64(msg.as_ref());
                                    assert(val <= COUNT as u64, "MRAP");
                                    lock.client_server_as_client_recv_count += 1;
                                    log::info!("[Client/Server Stress Test] RECV {} for {:?}", lock.client_server_as_client_recv_count, self.node_type);
                                    if lock.client_server_as_client_recv_count >= COUNT {
                                        log::info!("Client has finished receiving {} messages", COUNT);
                                        lock.client_server_stress_test_done_as_client = true;
                                        let _remote = self.remote.as_ref().unwrap().clone();
                                        std::mem::drop(lock);
                                        let mut lock = self.queued_requests.lock();
                                        assert(lock.remove(&CLIENT_SERVER_MESSAGE_STRESS_TEST), "VIDZ");
                                        // we insert the group ticket. We wait for client2 to send the group invite
                                        assert(lock.insert(GROUP_TICKET_TEST), "VIDX");
                                        std::mem::drop(lock);

                                        /*
                                        tokio::task::spawn(async move {
                                            tokio::time::sleep(Duration::from_millis(1000)).await;
                                            remote.shutdown().unwrap();
                                        });*/
                                    }
                                }

                                NodeType::Server => {
                                    //log::info!("RBX");
                                    let val = byteorder::BigEndian::read_u64(msg.as_ref());
                                    assert(val <= COUNT as u64, "NRAP");
                                    //log::info!("RBXX {}", val);
                                    // assert_eq(val, lock.client_server_as_server_recv_count as u64, "LVV"); Note: delivery order is not necessary since of tokio::spawn in the kernel event loop.
                                    //log::info!("RBX0");
                                    lock.client_server_as_server_recv_count += 1;
                                    log::info!("[Client/Server Stress Test] RECV {} for {:?}", lock.client_server_as_server_recv_count, self.node_type);
                                    if lock.client_server_as_server_recv_count == 1 {
                                        // we start firing packets from this side
                                        // lock.client_server_stress_test_done_as_server = true;
                                        // we must fire-up this side's subroutine for sending packets
                                        let client0_cid = lock.cnac_client0.as_ref().unwrap().get_cid();
                                        let queued_requests = self.queued_requests.clone();
                                        let remote = self.remote.clone().unwrap();
                                        let node_type = self.node_type;
                                        std::mem::drop(lock);
                                        tokio::task::spawn(async move {
                                            start_client_server_stress_test(queued_requests, remote, client0_cid, node_type).await;
                                        });
                                        return Ok(());
                                    }

                                    if lock.client_server_as_server_recv_count >= COUNT {
                                        log::info!("SERVER has finished receiving {} messages", COUNT);
                                        let _remote = self.remote.clone().unwrap();
                                        lock.client_server_stress_test_done_as_server = true;
                                        std::mem::drop(lock);
                                        let mut lock = self.queued_requests.lock();
                                        assert(lock.remove(&CLIENT_SERVER_MESSAGE_STRESS_TEST), "JKZ");
                                        // we insert the group ticket. We wait for client2 to send the group invite
                                        assert(lock.insert(GROUP_TICKET_TEST), "JKOT");

                                        /*
                                        tokio::task::spawn(async move {
                                            tokio::time::sleep(Duration::from_millis(1000)).await;
                                            remote.shutdown().unwrap();
                                        });*/
                                    }
                                }

                                _ => {
                                    log::error!("Invalid message delivery recipient {:?}", self.node_type);
                                    assert(false, "Invalid message delivery recipient");
                                }
                            }
                        }

                        HdpServerResult::InternalServerError(_, err) => {
                            panic!("Internal server error: {}", err);
                        }

                        HdpServerResult::RegisterOkay(ticket, cnac, _) => {
                            log::info!("SUCCESS registering ticket {} for {:?}", ticket, self.node_type);
                            // register the CID to be used in further checks
                            *self.ctx_cid.lock() = Some(cnac.get_cid());

                            if self.node_type == NodeType::Client0 {
                                self.item_container.as_ref().unwrap().write().cnac_client0 = Some(cnac);
                            } else if self.node_type == NodeType::Client1 {
                                self.item_container.as_ref().unwrap().write().cnac_client1 = Some(cnac);
                            } else if self.node_type == NodeType::Client2 {
                                self.item_container.as_ref().unwrap().write().cnac_client2 = Some(cnac);
                            } else {
                                //panic!("Unaccounted node type: {:?}", self.node_type)
                                assert(false, "Unaccounted node type");
                            }

                            self.on_valid_ticket_received(ticket);
                        }

                        HdpServerResult::ConnectSuccess(ticket, ..) => {
                            log::info!("SUCCESS connecting ticket {} for {:?}", ticket, self.node_type);
                            self.on_valid_ticket_received(ticket);

                            if self.node_type == NodeType::Client1 {
                                assert_eq(self.item_container.as_ref().unwrap().write().can_begin_peer_post_register_notifier_cl_1.as_ref().unwrap().send(()).unwrap(), 2, "Expected broadcast count not present");
                            }

                            if self.node_type == NodeType::Client0 || self.node_type == NodeType::Client2 {
                                // wait to ensure Client1 connects
                                let mut recv = self.item_container.as_ref().unwrap().write().can_begin_peer_post_register_recv.as_mut().unwrap().pop_back().unwrap();
                                log::info!("[Broadcast await] waiting for client 1 ...");
                                recv.recv().await.unwrap();
                                log::info!("[Broadcast await] Done awaiting ...");
                            }
                        }

                        HdpServerResult::PeerChannelCreated(ticket, channel) => {
                            self.on_valid_ticket_received(ticket);
                            handle_peer_channel(channel, self.remote.clone().unwrap(), self.item_container.clone().unwrap(), self.queued_requests.clone(), self.node_type);
                            //self.shutdown_in(Some(Duration::from_millis(1000)));
                        }

                        HdpServerResult::PeerEvent(signal, ticket) => {
                            match signal {
                                PeerSignal::PostRegister(vconn, _peer_username, _, resp_opt, fcm) => {
                                    if let Some(resp) = resp_opt {
                                        match resp {
                                            PeerResponse::Accept(_) => {
                                                log::info!("RECV PeerResponse::Accept for {:?}", self.node_type);
                                                self.on_valid_ticket_received(ticket);

                                                if self.node_type == NodeType::Client2 {
                                                    //self.remote.as_ref().unwrap().shutdown().unwrap();
                                                    // add the group ticket. Client2 will next send the group request ONCE the stress test is DONE between cl0 and server
                                                    assert(self.queued_requests.lock().insert(GROUP_TICKET_TEST), "MJW");
                                                }
                                            }

                                            _ => {
                                                log::error!("Invalid peer response for post-register")
                                            }
                                        }
                                    } else {
                                        log::info!("RECV PeerResponse::PostRegister for {:?} from {:?}", self.node_type, vconn);
                                        // the receiver of peer register requests is client 1 (c0 -> c1, c2 -> c1)
                                        assert_eq(self.node_type, NodeType::Client1, "LV0");
                                        let item_container = self.item_container.as_ref().unwrap();
                                        let read = item_container.read();
                                        let this_cnac = read.cnac_client1.as_ref().unwrap();

                                        let this_cid = this_cnac.get_cid();
                                        let this_username = this_cnac.get_username();
                                        let accept_post_register = HdpServerRequest::PeerCommand(this_cid, PeerSignal::PostRegister(vconn.reverse(), this_username, Some(ticket), Some(PeerResponse::Accept(None)), fcm));
                                        self.remote.as_ref().unwrap().send_with_custom_ticket(ticket, accept_post_register).unwrap();
                                        //self.shutdown_in(Some(Duration::from_millis(500)));
                                    }
                                }

                                PeerSignal::PostConnect(vconn, _, resp_opt, p2p_sec_lvl) => {
                                    if let Some(_resp) = resp_opt {
                                        // TODO
                                    } else {
                                        // the receiver is client 1
                                        assert_eq(self.node_type, NodeType::Client1, "PQZ");
                                        // receiver peer. ALlow the connection
                                        let item_container = self.item_container.as_ref().unwrap();
                                        let read = item_container.read();
                                        let this_cnac = read.cnac_client1.as_ref().unwrap();

                                        let this_cid = this_cnac.get_cid();
                                        let accept_post_connect = HdpServerRequest::PeerCommand(this_cid, PeerSignal::PostConnect(vconn.reverse(), Some(ticket), Some(PeerResponse::Accept(None)), p2p_sec_lvl));
                                        // we will expect a PeerChannel
                                        self.queued_requests.lock().insert(ticket);
                                        self.remote.as_ref().unwrap().send_with_custom_ticket(ticket, accept_post_connect).unwrap();
                                        //self.shutdown_in(Some(Duration::from_millis(1500)));
                                    }
                                }

                                PeerSignal::SignalReceived(_) => {}

                                PeerSignal::Disconnect(vconn, _) => {
                                    log::warn!("Peer vconn {} disconnected", vconn)
                                }

                                _ => {
                                    panic!("Unexpected signal: {:?}", signal);
                                }
                            }
                        }

                        _ => {
                            // prevent unaccounted signals from triggering next actions
                            return Ok(());
                        }
                    }

                    self.execute_next_action().await;
                }

                Ok(())
            }

            fn can_run(&self) -> bool {
                true
            }

            async fn on_stop(&self) -> Result<(), NetworkError> {
                if self.queued_requests.lock().len() != 0 || self.commands.lock().len() != 0 {
                    log::error!("ITEMS REMAIN (node type: {:?})", self.node_type);
                    Err(NetworkError::Generic(format!("Test error: items still in queue, or commands still pending for {:?}", self.node_type)))
                } else {
                    log::info!("NO ITEMS REMAIN (node type: {:?})", self.node_type);
                    Ok(())
                }
            }
        }
    }

    const CLIENT_SERVER_MESSAGE_STRESS_TEST: Ticket = Ticket(0xfffffffe);
    const P2P_MESSAGE_STRESS_TEST: Ticket = Ticket(0xffffffff);
    const GROUP_TICKET_TEST: Ticket = Ticket(0xfffffffd);

    #[allow(unused_results)]
    pub fn handle_peer_channel(channel: PeerChannel, remote: HdpServerRemote, test_container: Arc<RwLock<TestContainer>>, requests: Arc<Mutex<HashSet<Ticket>>>, node_type: NodeType) {
        assert(requests.lock().insert(P2P_MESSAGE_STRESS_TEST), "YUW");
        assert(node_type != NodeType::Server, "This function is not for servers");
        log::info!("[Peer channel] received on {:?}", node_type);
        tokio::task::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let (sink, mut stream) = channel.split();
            let sender = async move {
                for x in 0..COUNT {
                    if x % 10 == 9 {
                        tokio::time::sleep(Duration::from_millis(1)).await
                    }
                    //tokio::time::sleep(Duration::from_millis(10)).await;
                    sink.send_unbounded(SecBuffer::from(&(x as u64).to_be_bytes() as &[u8])).unwrap();
                }

                log::info!("DONE sending {} messages for {:?}", COUNT, node_type);
                true
            };

            let receiver = async move {
                let messages_recv = Arc::new(AtomicUsize::new(0));

                while let Some(val) = stream.next().await {
                    match node_type {
                        NodeType::Client0 | NodeType::Client1 => {
                            let count_now = messages_recv.clone().fetch_add(1, Ordering::SeqCst) + 1;
                            log::info!("{:?} RECV MESSAGE {:?}. CUR COUNT: {}", val.as_ref(), node_type, count_now);
                            let value = byteorder::BigEndian::read_u64(val.as_ref()) as usize;
                            assert_eq(count_now - 1, value, "EGQ");
                            if count_now >= COUNT {
                                break;
                            }
                        }

                        n => {
                            panic!("Unaccounted node type in p2p message handler: {:?}", n);
                        }
                    }
                }

                let count = messages_recv.load(Ordering::SeqCst);
                if count >= COUNT {
                    log::info!("DONE receiving {} messages for {:?}", COUNT, node_type);
                    true
                } else {
                    log::error!("Unable to receive all messages {:?}: {}/{}", node_type, count, COUNT);
                    false
                }
            };

            if tokio::join!(sender, receiver) == (true, true) {
                assert(requests.lock().remove(&P2P_MESSAGE_STRESS_TEST), "KPA");
                if node_type == NodeType::Client0 {
                    let implicated_cid = {
                        let read = test_container.read();
                        read.cnac_client0.as_ref().unwrap().get_cid()
                    };

                    // begin the sender
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    start_client_server_stress_test(requests.clone(), remote.clone(), implicated_cid, node_type).await;
                } else {
                    // at this point, client 1 will idle until the client/server stress test is done
                    log::info!("Client1 awaiting for group command ...");
                    assert(requests.lock().insert(GROUP_TICKET_TEST), "KPK");
                    /*tokio::time::sleep(Duration::from_millis(1000)).await;
                    remote.shutdown().unwrap();*/
                }
            } else {
                log::error!("One or more tx/rx failed for {:?}", node_type);
                assert(false, "One or more tx/rx failed");
            }
        });
    }

    const CLIENT_SERVER_STRESS_TEST_SEC: SecurityLevel = SecurityLevel::LOW;

    async fn start_client_server_stress_test(requests: Arc<Mutex<HashSet<Ticket>>>, mut remote: HdpServerRemote, implicated_cid: u64, node_type: NodeType) {
        assert(requests.lock().insert(CLIENT_SERVER_MESSAGE_STRESS_TEST), "MV0");
        log::info!("[Server/Client Stress Test] Starting send of {} messages on {:?} [target: {}]", COUNT, node_type, implicated_cid);

        for x in 0..COUNT {
            let next_ticket = remote.get_next_ticket();
            remote.send((next_ticket, HdpServerRequest::SendMessage(SecBuffer::from(&(x as u64).to_be_bytes() as &[u8]), implicated_cid, VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid), CLIENT_SERVER_STRESS_TEST_SEC))).await.unwrap();
        }

        log::info!("[Server/Client Stress Test] Done sending {} messages as {:?}", COUNT, node_type)
    }

    #[allow(dead_code)]
    fn default_error(msg: &'static str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, msg)
    }

    async fn client0_action1(item_container: Arc<RwLock<TestContainer>>, password: &'static str, security_level: SecurityLevel) -> Option<ActionType> {
        let read_c = item_container.read();
        let cnac = read_c.cnac_client0.clone().unwrap();
        let read = cnac.read();
        let ip = read.adjacent_nac.as_ref().unwrap().get_addr(true).unwrap();
        let cid = read.cid;
        std::mem::drop(read);
        std::mem::drop(read_c);

        log::info!("About to hash ...");
        let proposed_credentials = cnac.hash_password_as_client(SecBuffer::from(password)).await.unwrap();
        log::info!("Hashing done ...");

        Some(ActionType::Request(HdpServerRequest::ConnectToHypernode(ip, cid, proposed_credentials, security_level, ConnectMode::Standard, None, None, Some(true), None, underlying_proto())))
    }

    async fn client1_action1(item_container: Arc<RwLock<TestContainer>>, password: &'static str, security_level: SecurityLevel) -> Option<ActionType> {
        let read_c = item_container.read();
        let cnac = read_c.cnac_client1.clone().unwrap();
        let read = cnac.read();
        let ip = read.adjacent_nac.as_ref().unwrap().get_addr(true).unwrap();
        let cid = read.cid;
        std::mem::drop(read);
        std::mem::drop(read_c);

        log::info!("About to hash ...");
        let proposed_credentials = cnac.hash_password_as_client(SecBuffer::from(password)).await.unwrap();
        log::info!("Hashing done ...");

        Some(ActionType::Request(HdpServerRequest::ConnectToHypernode(ip, cid, proposed_credentials, security_level, ConnectMode::Standard, None, None, Some(true), None, underlying_proto())))
    }

    async fn client2_action1(item_container: Arc<RwLock<TestContainer>>, password: &'static str, security_level: SecurityLevel) -> Option<ActionType> {
        let read_c = item_container.read();
        let cnac = read_c.cnac_client2.clone().unwrap();
        let read = cnac.read();
        let ip = read.adjacent_nac.as_ref().unwrap().get_addr(true).unwrap();
        let cid = read.cid;
        std::mem::drop(read);
        std::mem::drop(read_c);

        log::info!("About to hash ...");
        let proposed_credentials = cnac.hash_password_as_client(SecBuffer::from(password)).await.unwrap();
        log::info!("Hashing done ...");

        Some(ActionType::Request(HdpServerRequest::ConnectToHypernode(ip, cid, proposed_credentials, security_level, ConnectMode::Standard, None, None, Some(true), None, underlying_proto())))
    }

    // client 2 will initiate the p2p *registration* to client1
    async fn client2_action2(item_container: Arc<RwLock<TestContainer>>, enable_fcm: bool) -> Option<ActionType> {
        tokio::task::spawn(async move {
            log::info!("Executing Client2_action2");
            let write = item_container.write();
            let cnac = write.cnac_client1.clone().unwrap();
            let client2_cnac = write.cnac_client2.as_ref().unwrap();
            let client2_id = client2_cnac.get_cid();
            let target_cid = cnac.get_cid();
            let client2_username = client2_cnac.get_username();
            let requests = write.queued_requests_client2.as_ref().unwrap();
            let fcm = enable_fcm.then(|| FcmPostRegister::Enable).unwrap_or(FcmPostRegister::Disable);
            let post_register_request = HdpServerRequest::PeerCommand(client2_id, PeerSignal::PostRegister(PeerConnectionType::HyperLANPeerToHyperLANPeer(client2_id, target_cid), client2_username, None, None, fcm));
            let ticket = write.remote_client2.as_ref().unwrap().unbounded_send(post_register_request).unwrap();
            assert(requests.lock().insert(ticket), "RDXY");
        });

        None
    }

    /* We DO NOT connect to client1 w/ client2 because we only want to test p2p conns
    // client 2 will initiate the p2p *connection* to client1
    fn client2_action3(item_container: Arc<RwLock<TestContainer>>, p2p_security_level: SecurityLevel) -> Option<ActionType> {
        tokio::task::spawn(async move {
            let read = item_container.read();
            let cnac = read.cnac_client1.clone().unwrap();
            let client2_cnac = read.cnac_client2.as_ref().unwrap();
            let client2_id = client2_cnac.get_cid();
            let target_cid = cnac.get_cid();
            let requests = read.queued_requests_client2.as_ref().unwrap();
            let post_connect_request = HdpServerRequest::PeerCommand(client2_id, PeerSignal::PostConnect(PeerConnectionType::HyperLANPeerToHyperLANPeer(client2_id, target_cid), None, None, p2p_security_level));
            let ticket = read.remote_client2.as_ref().unwrap().unbounded_send(post_connect_request).unwrap();
            assert(requests.lock().insert(ticket), "Z12-3");
        });

        None
    }*/

    /// Client 2 will patiently wait to send a group invite
    async fn client2_action3_start_group(item_container: Arc<RwLock<TestContainer>>) -> Option<ActionType> {
        tokio::task::spawn(async move {
            loop {
                {
                    let read = item_container.read();
                    if read.client_server_stress_test_done_as_server && read.client_server_stress_test_done_as_client {
                        log::info!("[GROUP Stress test] Starting group stress test w/ client2 host [members: client0 & client1]");
                        let client0_cnac = read.cnac_client0.as_ref().unwrap();
                        let client1_cnac = read.cnac_client1.as_ref().unwrap();
                        let this_cid = read.cnac_client2.as_ref().unwrap().get_cid();

                        let request = HdpServerRequest::GroupBroadcastCommand(this_cid, GroupBroadcast::Create(vec![client0_cnac.get_cid(), client1_cnac.get_cid()]));
                        let remote = read.remote_client2.clone().unwrap();
                        let _ticket = remote.unbounded_send(request).unwrap();
                        //assert(read.queued_requests_client2.as_ref().unwrap().lock().insert(ticket), "MDY");
                        return;
                    }
                }

                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        None
    }

    fn client2_action4_fire_group(item_container: Arc<RwLock<TestContainer>>, group_key: MessageGroupKey, ticket: Ticket) {
        tokio::task::spawn(async move {
            let (this_cnac, mut remote) = {
                let read = item_container.read();
                log::info!("[GROUP Stress test] Client2/Host firing messages @ [members: client0 & client1]");
                let this_cnac = read.cnac_client2.clone().unwrap();
                let remote = read.remote_client2.clone().unwrap();
                (this_cnac, remote)
            };

            let this_cid = this_cnac.get_cid();
            let this_username = this_cnac.get_username();

            let mut stream = tokio_stream::iter((0..COUNT).into_iter().map(|idx| Ok((ticket, HdpServerRequest::GroupBroadcastCommand(this_cid, GroupBroadcast::Message(this_username.clone(), group_key, SecBuffer::from(&idx.to_be_bytes() as &[u8])))))));
            remote.send_all(&mut stream).await.unwrap();
            log::info!("[GROUP Stress test] Client2/Host done firing messages");
            // We don't get to remove the GROUP_TICKET_TEST quite yet. We need to receive COUNT of GroupBroadcast::MessageResponse(key, true) first
        });
    }

    // client 0 will initiate the p2p *registration* to client1
    async fn client0_action2(item_container: Arc<RwLock<TestContainer>>, enable_fcm: bool) -> Option<ActionType> {
        tokio::task::spawn(async move {
            let write = item_container.write();
            let cnac = write.cnac_client1.clone().unwrap();
            let client0_cnac = write.cnac_client0.as_ref().unwrap();
            let client0_id = client0_cnac.get_cid();
            let target_cid = cnac.get_cid();
            let client0_username = client0_cnac.get_username();
            let requests = write.queued_requests_client0.as_ref().unwrap();
            let fcm = enable_fcm.then(|| FcmPostRegister::Enable).unwrap_or(FcmPostRegister::Disable);
            let post_register_request = HdpServerRequest::PeerCommand(client0_id, PeerSignal::PostRegister(PeerConnectionType::HyperLANPeerToHyperLANPeer(client0_id, target_cid), client0_username, None, None, fcm));
            let ticket = write.remote_client0.as_ref().unwrap().unbounded_send(post_register_request).unwrap();
            assert(requests.lock().insert(ticket), "ABK");
        });

        None
    }

    // client 0 will initiate the p2p *connection* to client1
    async fn client0_action3(item_container: Arc<RwLock<TestContainer>>, p2p_security_level: SecurityLevel) -> Option<ActionType> {
        tokio::task::spawn(async move {
            let read = item_container.read();
            let cnac = read.cnac_client1.clone().unwrap();
            let client0_cnac = read.cnac_client0.as_ref().unwrap();
            let client0_id = client0_cnac.get_cid();
            let target_cid = cnac.get_cid();
            let requests = read.queued_requests_client0.as_ref().unwrap();
            let post_connect_request = HdpServerRequest::PeerCommand(client0_id, PeerSignal::PostConnect(PeerConnectionType::HyperLANPeerToHyperLANPeer(client0_id, target_cid), None, None, p2p_security_level));
            let ticket = read.remote_client0.as_ref().unwrap().unbounded_send(post_connect_request).unwrap();
            assert(requests.lock().insert(ticket), "Z12");
        });

        None
    }
}

pub mod utils {
    use futures::Future;
    use std::pin::Pin;
    use futures::task::{Context, Poll};

    /// For denoting to the compiler that running the future is thread-safe
    /// It is up to the caller to ensure the supplied future is not going to be called
    /// from multiple threads concurrently. IF there is a single instance of the task, then
    /// use this. If there will be multiple, use the safer version in misc::ThreadSafeFuture
    pub struct AssertSendSafeFuture<'a, Out: 'a>(Pin<Box<dyn Future<Output=Out> + 'a>>);

    unsafe impl<'a, Out: 'a> Send for AssertSendSafeFuture<'a, Out> {}

    impl<'a, Out: 'a> AssertSendSafeFuture<'a, Out> {
        /// Wraps a future, asserting it is safe to use in a multithreaded context at the possible cost of race conditions, locks, etc
        pub unsafe fn new(fx: impl Future<Output=Out> + 'a) -> Self {
            Self(Box::pin(fx))
        }
        pub fn new_silent(fx: impl Future<Output=Out> + 'a) -> Self {
            Self(Box::pin(fx))
        }
    }

    impl<'a, Out: 'a> Future for AssertSendSafeFuture<'a, Out> {
        type Output = Out;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.0.as_mut().poll(cx)
        }
    }

    pub fn assert(cond: bool, tag: &str) {
        assert_eq(cond, true, tag)
    }

    pub fn assert_eq<T: PartialEq<R> + std::fmt::Debug, R: PartialEq<T> + std::fmt::Debug>(t: T, r: R, tag: &str) {
        if t != r {
            log::error!("Failed assert for {}: Expected: {:?} == {:?}", tag, t, r);
            std::process::exit(-1);
        }
    }

    #[allow(dead_code)]
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