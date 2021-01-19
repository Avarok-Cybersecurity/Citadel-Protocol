#![feature(try_trait, decl_macro)]

#[cfg(test)]
pub mod tests {
    use std::error::Error;
    use hyxe_net::hdp::hdp_server::HdpServerRequest;
    use crate::tests::kernel::{TestKernel, TestContainer, ActionType};
    use hyxe_net::kernel::kernel_executor::KernelExecutor;
    use hyxe_nat::hypernode_type::HyperNodeType;
    use hyxe_user::account_manager::AccountManager;
    use hyxe_net::hdp::hdp_packet_processor::includes::{SocketAddr, Duration};
    use std::str::FromStr;
    use hyxe_net::proposed_credentials::ProposedCredentials;
    use secstr::SecVec;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_net::hdp::AssertSendSafeFuture;
    use std::sync::Arc;
    use parking_lot::RwLock;
    use hyxe_net::functional::PairMap;
    use hyxe_net::hdp::peer::peer_layer::{PeerSignal, PeerConnectionType};

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    fn function(f: impl FnOnce(Arc<RwLock<TestContainer>>) -> Option<ActionType> + Send + 'static) -> ActionType {
        ActionType::Function(Box::new(f))
    }

    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub enum NodeType {
        Server,
        Client0,
        Client1
    }

    #[tokio::test]
    async fn main() -> Result<(), Box<dyn Error>> {
        setup_log();
        let server_bind_addr = SocketAddr::from_str("127.0.0.1:33332").unwrap();
        let client0_bind_addr = SocketAddr::from_str("127.0.0.1:33333").unwrap();
        let client1_bind_addr = SocketAddr::from_str("127.0.0.1:33334").unwrap();

        let security_level = SecurityLevel::LOW;
        static CLIENT0_FULLNAME: &'static str = "Thomas P Braun (test)";
        static CLIENT0_USERNAME: &'static str = "nologik";
        static CLIENT0_PASSWORD: &'static str = "mrmoney10";

        static CLIENT1_FULLNAME: &'static str = "Thomas P Braun I (test)";
        static CLIENT1_USERNAME: &'static str = "nologik1";
        static CLIENT1_PASSWORD: &'static str = "mrmoney10";

        let test_container = Arc::new(RwLock::new(TestContainer::default()));

        log::info!("Setting up executors ...");
        let server_executor = create_executor(server_bind_addr, None,NodeType::Server, Vec::default()).await;
        log::info!("Done setting up server executor");
        let client0_executor = create_executor(client0_bind_addr, Some(test_container.clone()), NodeType::Client0, {
            vec![ActionType::Request(HdpServerRequest::RegisterToHypernode(server_bind_addr, ProposedCredentials::new_unchecked(CLIENT0_FULLNAME, CLIENT0_USERNAME, SecVec::new(Vec::from(CLIENT0_PASSWORD)), None), None, security_level)),
                 function(move |test_container| client0_action1(test_container, CLIENT0_USERNAME, CLIENT0_PASSWORD, security_level)),
                 function(move |test_container| client0_action2(test_container))
            ]
        }).await;

        let client1_executor = create_executor(client1_bind_addr, Some(test_container.clone()), NodeType::Client1, {
            vec![ActionType::Request(HdpServerRequest::RegisterToHypernode(server_bind_addr, ProposedCredentials::new_unchecked(CLIENT1_FULLNAME, CLIENT1_USERNAME, SecVec::new(Vec::from(CLIENT1_PASSWORD)), None), None, security_level)),
                 function(move |test_container| client1_action1(test_container, CLIENT1_USERNAME, CLIENT1_PASSWORD, security_level))
            ]
        }).await;

        log::info!("Done setting up executors");

        let server_future = async move { server_executor.execute().await };
        let client0_future = tokio::time::timeout(Duration::from_millis(10000), async move { client0_executor.execute().await });
        let client1_future = tokio::time::timeout(Duration::from_millis(10000), async move { client1_executor.execute().await });

        let server = tokio::task::spawn(AssertSendSafeFuture::new_silent(server_future));
        tokio::time::delay_for(Duration::from_millis(100)).await;

        let joined_clients_future = tokio::try_join!(client0_future, client1_future)?.map(|res0, res1| res0.and(res1))?;

        //tokio::task::spawn(unsafe { AssertSendSafeFuture::new(client0_future) }).await???;
        log::info!("Ending test (client(s) done) ...");

        tokio::time::timeout(Duration::from_millis(100), server).await;

        Ok(())
    }

    async fn create_executor(bind_addr: SocketAddr, test_container: Option<Arc<RwLock<TestContainer>>>, node_type: NodeType, commands: Vec<ActionType>) -> KernelExecutor<TestKernel> {
        let account_manager = AccountManager::new(bind_addr, Some(format!("/Users/nologik/tmp/{}_{}", bind_addr.ip(), bind_addr.port()))).await.unwrap();
        account_manager.purge();
        let kernel = TestKernel::new(node_type, commands, test_container);
        KernelExecutor::new(HyperNodeType::BehindResidentialNAT, account_manager, kernel, bind_addr).await.unwrap()
    }

    pub mod kernel {
        use hyxe_net::kernel::kernel::NetKernel;
        use hyxe_net::hdp::hdp_server::{HdpServerRemote, HdpServerResult, HdpServerRequest, Ticket};
        use hyxe_net::error::NetworkError;
        use std::collections::HashSet;
        use parking_lot::{Mutex, RwLock};
        use hyxe_net::hdp::hdp_packet_processor::includes::Duration;
        use async_trait::async_trait;
        use std::sync::Arc;
        use hyxe_user::client_account::ClientNetworkAccount;
        use crate::tests::NodeType;
        use hyxe_net::hdp::peer::peer_layer::{PeerSignal, PeerResponse};

        #[derive(Default)]
        pub struct TestContainer {
            pub cnac_client0: Option<ClientNetworkAccount>,
            pub cnac_client1: Option<ClientNetworkAccount>,
            pub remote_client0: Option<HdpServerRemote>,
            pub remote_client1: Option<HdpServerRemote>,
            pub queued_requests_client0: Option<Arc<Mutex<HashSet<Ticket>>>>,
            pub queued_requests_client1: Option<Arc<Mutex<HashSet<Ticket>>>>
        }

        pub enum ActionType {
            Request(HdpServerRequest),
            Function(Box<dyn FnOnce(Arc<RwLock<TestContainer>>) -> Option<ActionType> + Send + 'static>)
        }

        pub struct TestKernel {
            node_type: NodeType,
            commands: Mutex<Vec<ActionType>>,
            remote: Option<HdpServerRemote>,
            // a ticket gets added once a request is submitted. Once a VALID response occurs, the entry is removed. If an invalid response is received, then the ticket lingers, then the timer throws an error
            queued_requests: Arc<Mutex<HashSet<Ticket>>>,
            item_container: Option<Arc<RwLock<TestContainer>>>,
            ctx_cid: Mutex<Option<u64>>
        }

        impl TestKernel {
            pub fn new(node_type: NodeType, commands: Vec<ActionType>, item_container: Option<Arc<RwLock<TestContainer>>>) -> Self {
                Self { node_type, commands: Mutex::new(commands), remote: None, queued_requests: Arc::new(Mutex::new(HashSet::new())), item_container, ctx_cid: Mutex::new(None) }
            }

            fn execute_action(&self, request: ActionType, remote: &HdpServerRemote) {
                match request {
                    ActionType::Request(request) => {
                        let ticket = remote.unbounded_send(request).unwrap();
                        assert!(self.queued_requests.lock().insert(ticket));
                    }

                    ActionType::Function(fx) => {
                        // execute the created action, or, run the next enqueued action
                        if let Some(request) = (fx)(self.item_container.clone().unwrap()) {
                            self.execute_action(request, remote);
                        } else {
                            self.execute_next_action();
                        }
                    }
                }

            }

            fn execute_next_action(&self) {
                let remote = self.remote.as_ref().unwrap();
                let mut lock = self.commands.lock();
                if lock.len() != 0 {
                    log::info!("[TEST] Executing next action ...");
                    let item = lock.remove(0);
                    std::mem::drop(lock);
                    self.execute_action(item, remote);
                }
            }

            fn on_valid_ticket_received(&self, ticket: Ticket) {
                if self.node_type != NodeType::Server {
                    assert!(self.queued_requests.lock().remove(&ticket))
                }
            }

            fn shutdown_in(&self, time: Option<Duration>) {
                let remote = self.remote.clone().unwrap();
                if let Some(time) = time {
                    tokio::task::spawn(async move {
                        tokio::time::delay_for(time).await;
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
                    self.execute_action(self.commands.lock().remove(0), &server_remote);
                    let container = self.item_container.as_ref().unwrap();
                    let mut write = container.write();
                    if self.node_type == NodeType::Client0 {
                        write.remote_client0 = Some(server_remote.clone());
                        write.queued_requests_client0 = Some(self.queued_requests.clone());
                    } else if self.node_type == NodeType::Client1 {
                        write.remote_client1 = Some(server_remote.clone());
                        write.queued_requests_client1 = Some(self.queued_requests.clone());
                    } else {
                        panic!("Unaccounted node type {:?}", self.node_type);
                    }
                }

                self.remote = Some(server_remote);
                Ok(())
            }

            async fn on_server_message_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
                log::info!("Message received: {:?}", &message);
                if self.node_type != NodeType::Server {
                    match message {
                        HdpServerResult::ConnectFail(..) | HdpServerResult::RegisterFailure(..) => {
                            panic!("Register/Connect failed");
                        }

                        HdpServerResult::InternalServerError(_, err) => {
                            panic!("Internal server error: {}", err);
                        }

                        HdpServerResult::RegisterOkay(ticket, cnac, _) => {
                            log::info!("SUCCESS registering ticket {}", ticket);
                            // register the CID to be used in further checks
                            *self.ctx_cid.lock() = Some(cnac.get_cid());

                            if self.node_type == NodeType::Client0 {
                                self.item_container.as_ref().unwrap().write().cnac_client0 = Some(cnac);
                            } else if self.node_type == NodeType::Client1 {
                                self.item_container.as_ref().unwrap().write().cnac_client1 = Some(cnac);
                            } else {
                                panic!("Unaccounted node type: {:?}", self.node_type)
                            }

                            self.on_valid_ticket_received(ticket);
                        }

                        HdpServerResult::ConnectSuccess(ticket, ..) => {
                            log::info!("SUCCESS connecting ticket {}", ticket);
                            self.on_valid_ticket_received(ticket);
                        }

                        HdpServerResult::PeerEvent(signal, ticket) => {
                            match signal {
                                PeerSignal::PostRegister(vconn, peer_username, _, resp_opt) => {
                                    if let Some(resp) = resp_opt {
                                        match resp {
                                            PeerResponse::Accept(_) => {
                                                self.on_valid_ticket_received(ticket);
                                                self.shutdown_in(None);
                                            }

                                            _ => {
                                                log::error!("Invalid peer response for post-register")
                                            }
                                        }
                                    } else {
                                        let item_container = self.item_container.as_ref().unwrap();
                                        let read = item_container.read();
                                        // the receiver is client 1
                                        assert_eq!(self.node_type, NodeType::Client1);
                                        let this_cnac = read.cnac_client1.as_ref().unwrap();
                                        // we are receiving the post-register request. Accept it
                                        //let this_cid = self.ctx_cid.lock().clone().unwrap();
                                        let this_cid = this_cnac.get_cid();
                                        let this_username = this_cnac.get_username();
                                        let accept_post_register = HdpServerRequest::PeerCommand(this_cid, PeerSignal::PostRegister(vconn.reverse(), this_username, Some(ticket), Some(PeerResponse::Accept(None))));
                                        self.remote.as_ref().unwrap().send_with_custom_ticket(ticket, accept_post_register).unwrap();
                                        self.shutdown_in(Some(Duration::from_millis(500)));
                                    }
                                }

                                PeerSignal::SignalReceived(_) => {}

                                _ => {
                                    panic!("Unexpected signal: {:?}", signal);
                                }
                            }
                        }

                        _ => {}
                    }

                    self.execute_next_action();
                }

                Ok(())
            }

            fn can_run(&self) -> bool {
                true
            }

            async fn on_stop(&self) -> Result<(), NetworkError> {
                if self.queued_requests.lock().len() != 0 || self.commands.lock().len() != 0 {
                    log::error!("ITEMS REMAIN (node type: {:?})", self.node_type);
                    Err(NetworkError::InternalError("Test error: items still in queue, or commands still pending"))
                } else {
                    log::info!("NO ITEMS REMAIN (node type: {:?})", self.node_type);
                    Ok(())
                }
            }
        }
    }

    #[allow(dead_code)]
    fn default_error(msg: &'static str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, msg)
    }

    fn client0_action1(item_container: Arc<RwLock<TestContainer>>, username: &str, password: &str, security_level: SecurityLevel) -> Option<ActionType> {
        let read = item_container.read();
        let cnac = read.cnac_client0.as_ref().unwrap();
        let read = cnac.read();
        let full_name = ""; // irrelevant for testing
        let ip = read.adjacent_nac.as_ref().unwrap().get_addr(true).unwrap();
        let cid = read.cid;
        let nonce = read.password_hash.as_slice();
        let proposed_credentials = ProposedCredentials::new_unchecked(full_name, username, SecVec::from(Vec::from(password)), Some(nonce));

        Some(ActionType::Request(HdpServerRequest::ConnectToHypernode(ip, cid, proposed_credentials, security_level, None, None, Some(true))))
    }

    fn client1_action1(item_container: Arc<RwLock<TestContainer>>, username: &str, password: &str, security_level: SecurityLevel) -> Option<ActionType> {
        let read = item_container.read();
        let cnac = read.cnac_client1.as_ref().unwrap();
        let read = cnac.read();
        let full_name = ""; // irrelevant for testing
        let ip = read.adjacent_nac.as_ref().unwrap().get_addr(true).unwrap();
        let cid = read.cid;
        let nonce = read.password_hash.as_slice();
        let proposed_credentials = ProposedCredentials::new_unchecked(full_name, username, SecVec::from(Vec::from(password)), Some(nonce));

        Some(ActionType::Request(HdpServerRequest::ConnectToHypernode(ip, cid, proposed_credentials, security_level, None, None, Some(true))))
    }

    // client 0 will initiate the p2p connection to client1
    fn client0_action2(item_container: Arc<RwLock<TestContainer>>) -> Option<ActionType> {
        tokio::task::spawn(async move {
            loop {
                {
                    let mut write = item_container.write();
                    if let Some(cnac) = write.cnac_client1.as_ref() {
                        let client0_cnac = write.cnac_client0.as_ref().unwrap();
                        let client0_id = client0_cnac.get_cid();
                        let target_cid = cnac.get_cid();
                        let client0_username = client0_cnac.get_username();
                        let requests = write.queued_requests_client0.as_ref().unwrap();
                        let post_register_request = HdpServerRequest::PeerCommand(client0_id, PeerSignal::PostRegister(PeerConnectionType::HyperLANPeerToHyperLANPeer(client0_id, target_cid), client0_username, None, None));
                        let ticket = write.remote_client0.as_ref().unwrap().unbounded_send(post_register_request).unwrap();
                        assert!(requests.lock().insert(ticket));
                        return;
                    }
                }

                tokio::time::delay_for(Duration::from_millis(100)).await;
            }
        });

        None
    }
}