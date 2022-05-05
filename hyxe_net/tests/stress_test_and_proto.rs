#[cfg(test)]
pub mod tests {
    use std::collections::{HashSet, HashMap};
    use std::error::Error;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Instant;

    use futures::{Future, StreamExt};
    use parking_lot::{const_mutex, Mutex, RwLock};
    use tokio::runtime::{Builder, Handle};

    use ez_pqcrypto::algorithm_dictionary::{EncryptionAlgorithm, KemAlgorithm};
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_crypt::fcm::keys::FcmKeys;
    use hyxe_crypt::prelude::SecBuffer;
    use hyxe_wire::hypernode_type::NodeType;
    use std::time::Duration;
    use std::net::SocketAddr;
    use hyxe_net::prelude::*;
    use hyxe_user::account_manager::AccountManager;
    use hyxe_user::backend::BackendType;
    use hyxe_user::external_services::fcm::kem::FcmPostRegister;
    use hyxe_user::auth::proposed_credentials::ProposedCredentials;

    use crate::tests::kernel::{ActionType, MessageTransfer, TestContainer, TestKernel};
    use crate::utils::{assert, assert_eq, AssertSendSafeFuture, deadlock_detector};
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    use hyxe_net::test_common::HdpServer;
    use hyxe_net::auth::AuthenticationRequest;
    use dirs2::home_dir;
    use clap::ArgMatches;

    use rstest::*;
    use futures::stream::FuturesUnordered;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use rand::{SeedableRng, Rng};
    use hyxe_wire::exports::tokio_rustls::rustls::ClientConfig;
    use hyxe_wire::socket_helpers::is_ipv6_enabled;

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
        err.map_err(|err| NetworkError::Generic(err.to_string()))?
    }

    fn function(f: Pin<Box<dyn Future<Output=Option<ActionType>> + Send + 'static>>) -> ActionType {
        ActionType::Function(f)
    }

    #[fixture]
    fn protocols() -> Vec<UnderlyingProtocol> {
        vec![
            UnderlyingProtocol::Tcp,
            UnderlyingProtocol::new_tls_self_signed().unwrap(),
            UnderlyingProtocol::new_quic_self_signed(),
            UnderlyingProtocol::load_tls("../keys/testing.p12", "password", "thomaspbraun.com").unwrap(),
            UnderlyingProtocol::load_quic("../keys/testing.p12", "password", "thomaspbraun.com").unwrap()
        ]
    }

    #[fixture]
    #[once]
    fn client_config() -> Arc<ClientConfig> {
        let certs = hyxe_wire::tls::load_native_certs().unwrap();
        Arc::new(hyxe_wire::tls::cert_vec_to_secure_client_config(&certs).unwrap())
    }

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[tokio::test]
    async fn test_tcp_or_tls(#[case] addr: SocketAddr,
                             protocols: Vec<UnderlyingProtocol>,
                             client_config: &Arc<ClientConfig>) -> std::io::Result<()> {
        setup_log();
        deadlock_detector();

        if !is_ipv6_enabled() && addr.is_ipv6() {
            log::info!("Skipping ipv6 test since ipv6 is not enabled locally");
            return Ok(())
        }

        for proto in protocols {
            log::info!("Testing proto {:?}", &proto);

            let (mut listener, addr) = HdpServer::server_create_primary_listen_socket(proto,addr).unwrap();
            log::info!("Bind/connect addr: {:?}", addr);

            let server = async move {
                let next = listener.next().await;
                log::info!("[Server] Next conn: {:?}", next);
                let (mut stream, peer_addr) = next.unwrap().unwrap();
                log::info!("[Server] Received stream from {}", peer_addr);
                let buf = &mut [0u8;64];
                let res = stream.read(buf).await;
                log::info!("Server-res: {:?}", res);
                assert_eq(buf[0], 0xfb, "Invalid read");
                let _ = stream.write(&[0xfa]).await.unwrap();
                stream.shutdown().await.unwrap();
            };

            let client = async move {
                let (mut stream, _) = HdpServer::c2s_connect_defaults(None, addr, client_config).await.unwrap();
                log::info!("Client connected");
                let res = stream.write(&[0xfb]).await;
                log::info!("Client connected - A02 {:?}", res);
                let buf = &mut [0u8;64];
                let res = stream.read(buf).await;
                log::info!("Client connected - AO3 {:?}", res);
                assert_eq(buf[0], 0xfa, "Invalid read - client");
            };

            let _ = tokio::join!(server, client);
            log::info!("Ended");
        }

        Ok(())
    }

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[tokio::test]
    async fn test_many_proto_conns(#[case] addr: SocketAddr,
                                   protocols: Vec<UnderlyingProtocol>,
                                   client_config: &Arc<ClientConfig>) -> std::io::Result<()> {
        setup_log();
        deadlock_detector();

        let port = portpicker::pick_unused_port().unwrap();
        let addr = SocketAddr::new(addr.ip(), port);

        if !is_ipv6_enabled() && addr.is_ipv6() {
            log::info!("Skipping ipv6 test since ipv6 is not enabled locally");
            return Ok(())
        }

        let count = 32; // keep this value low to ensure that runners don't get exhausted and run out of FD's
        for proto in protocols {
            // give sleep to give time for conns to drop
            tokio::time::sleep(Duration::from_millis(100)).await;
            log::info!("Testing proto {:?}", &proto);
            let cnt = &AtomicUsize::new(0);

            let (mut listener, addr) = HdpServer::server_create_primary_listen_socket(proto,addr).unwrap();
            log::info!("Bind/connect addr: {:?}", addr);

            let server = async move {
                loop {
                    let next = listener.next().await;
                    log::info!("[Server] Next conn: {:?}", next);
                    let (mut stream, peer_addr) = next.unwrap().unwrap();
                    tokio::spawn(async move {
                        log::info!("[Server] Received stream from {}", peer_addr);
                        let buf = &mut [0u8;64];
                        let res = stream.read(buf).await;
                        log::info!("Server-res: {:?}", res);
                        assert_eq(buf[0], 0xfb, "Invalid read");
                        let _ = stream.write(&[0xfa]).await.unwrap();
                        stream.shutdown().await.unwrap();
                    });
                }
            };

            let client = FuturesUnordered::new();

            for _ in 0..count {
                client.push(async move {
                    let mut rng = rand::rngs::StdRng::from_entropy();
                    tokio::time::sleep(Duration::from_millis(rng.gen_range(10, 50))).await;
                    let (mut stream, _) = HdpServer::c2s_connect_defaults(None, addr, client_config).await.unwrap();
                    log::info!("Client connected");
                    let res = stream.write(&[0xfb]).await;
                    log::info!("Client connected - A02 {:?}", res);
                    let buf = &mut [0u8;64];
                    let res = stream.read(buf).await;
                    log::info!("Client connected - AO3 {:?}", res);
                    assert_eq(buf[0], 0xfa, "Invalid read - client");
                    let _ = cnt.fetch_add(1, Ordering::SeqCst);
                });
            }

            let client = client.collect::<Vec<()>>();
            // if server ends, bad. If client ends, maybe good
            let res = tokio::select! {
                res0 = server => {
                    res0
                },
                res1 = client => {
                    res1
                }
            };

            log::info!("Res: {:?}", res);

            assert_eq!(cnt.load(Ordering::SeqCst), count);

            log::info!("Ended proto test for singular proto successfully");
        }

        Ok(())
    }


    fn pinbox<F: Future<Output=Option<ActionType>> + 'static>(f: F) -> Pin<Box<dyn Future<Output=Option<ActionType>> + Send + 'static>> {
        Box::pin(AssertSendSafeFuture::new_silent(f))
    }

    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub enum TestNodeType {
        Server,
        Client0,
        Client1,
        Client2,
    }

    fn backend_server() -> BackendType {
        if USE_FILESYSYEM {
            BackendType::Filesystem
        } else {
            #[cfg(feature = "enterprise")] {
                match std::env::var("TESTING_SQL_SERVER_ADDR") {
                    Ok(addr) => {
                        log::info!("Testing SQL ADDR: {}", addr);
                        BackendType::sql(addr)
                    }

                    _ => {
                        log::error!("Make sure TESTING_SQL_SERVER_ADDR is set in the environment");
                        std::process::exit(1)
                    }
                }
            }

            #[cfg(not(feature = "enterprise"))] {
                BackendType::Filesystem
            }
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

    enum InputExtractionSource<'a> {
        UnitTest(HashMap<&'static str, &'a str>),
        Console(ArgMatches<'a>)
    }

    impl<'a> InputExtractionSource<'a> {
        fn value_of(&self, key: &str) -> Option<&'_ str> {
            match self {
                Self::UnitTest(map) => map.get(key).copied(),
                Self::Console(matches) => matches.value_of(key)
            }
        }

        fn is_present(&self, key: &str) -> bool {
            self.value_of(key).is_some()
        }
    }

    #[allow(dead_code)]
    fn setup_clap() {
        let kems = KemAlgorithm::names();
        let kems = kems.iter().map(|r| r.as_str()).collect::<Vec<&str>>();

        let app = clap::App::new("stress-testing harness").arg(clap::Arg::with_name("count").long("count").takes_value(true).required(false))
            .arg(clap::Arg::with_name("tls").long("tls").required(false).takes_value(false).conflicts_with_all(&["tcp", "quic"]))
            .arg(clap::Arg::with_name("security_level").long("sec").required(false).takes_value(true))
            .arg(clap::Arg::with_name("timeout").long("timeout").required(false).takes_value(true))
            .arg(clap::Arg::with_name("message_length").long("len").required(false).takes_value(true))
            .arg(clap::Arg::with_name("secrecy_mode").long("secrecy").required(false).takes_value(true).possible_values(&["pfs", "bem"]))
            .arg(clap::Arg::with_name("encryption_algorithm").long("enx").required(false).takes_value(true).possible_values(&["aes", "chacha"]))
            .arg(clap::Arg::with_name("key_exchange_mechanism").long("kem").required(false).takes_value(true).possible_values(kems.as_slice()))
            .arg(clap::Arg::with_name("udp").long("udp").required(false).takes_value(false))
            .arg(clap::Arg::with_name("proto").long("proto").default_value("tcp").required(false).takes_value(true).possible_values(&["tcp", "tls", "quic"]));

        let matches = app.get_matches_from(std::env::args().skip_while(|v| v != "--clap").collect::<Vec<String>>());
        extract_args_to_statics(InputExtractionSource::Console(matches))
    }

    fn extract_args_to_statics(matches: InputExtractionSource) {
        if let Some(matches) = matches.value_of("count") {
            COUNT.lock().replace(usize::from_str(matches).unwrap());
        } else {
            COUNT.lock().replace(DEFAULT_COUNT);
        }

        if matches.is_present("udp") {
            UDP_MODE.lock().replace(UdpMode::Enabled);
        } else {
            UDP_MODE.lock().replace(DEFAULT_UDP_MODE);
        }

        if let Some(matches) = matches.value_of("secrecy_mode") {
            SECRECY_MODE.lock().replace(matches.if_eq("pfs", SecrecyMode::Perfect).if_false(SecrecyMode::BestEffort));
        } else {
            SECRECY_MODE.lock().replace(DEFAULT_SECRECY_MODE);
        }

        if let Some(matches) = matches.value_of("encryption_algorithm") {
            ENCRYPTION_ALGORITHM.lock().replace(matches.if_eq("aes", EncryptionAlgorithm::AES_GCM_256_SIV).if_false(EncryptionAlgorithm::Xchacha20Poly_1305));
        } else {
            ENCRYPTION_ALGORITHM.lock().replace(DEFAULT_ENCRYPTION_ALGORITHM);
        }

        if let Some(matches) = matches.value_of("key_exchange_mechanism") {
            KEM_ALGORITHM.lock().replace(KemAlgorithm::try_from_str(matches).unwrap());
        } else {
            KEM_ALGORITHM.lock().replace(DEFAULT_KEM_ALGORITHM);
        }

        if let Some(matches) = matches.value_of("security_level") {
            let level = SecurityLevel::from(u8::from_str(matches).unwrap());
            SESSION_SECURITY_LEVEL.lock().replace(level);
            P2P_SECURITY_LEVEL.lock().replace(level);
        } else {
            SESSION_SECURITY_LEVEL.lock().replace(DEFAULT_SESSION_SECURITY_LEVEL);
            P2P_SECURITY_LEVEL.lock().replace(DEFAULT_P2P_SECURITY_LEVEL);
        }

        if let Some(matches) = matches.value_of("timeout") {
            let timeout = usize::from_str(matches).unwrap();
            TIMEOUT_CNT_MS.lock().replace(timeout);
        } else {
            TIMEOUT_CNT_MS.lock().replace(DEFAULT_TIMEOUT_CNT_MS);
        }

        if let Some(matches) = matches.value_of("message_length") {
            let len = usize::from_str(matches).unwrap();
            RAND_MESSAGE_LEN.lock().replace(len);
        } else {
            RAND_MESSAGE_LEN.lock().replace(DEFAULT_RAND_MESSAGE_LEN);
        }

        let proto = matches.value_of("proto").unwrap();
        match proto {
            "tls" => PROTO.lock().replace(UnderlyingProtocol::new_tls_self_signed().unwrap()),
            "quic" => PROTO.lock().replace(UnderlyingProtocol::new_quic_self_signed()),
            "tcp" => PROTO.lock().replace(UnderlyingProtocol::Tcp),
            invalid_proto => panic!("invalid proto specified: {}", invalid_proto)
        };
    }

    fn count() -> usize {
        (*COUNT.lock()).unwrap()
    }
    fn secrecy_mode() -> SecrecyMode { (*SECRECY_MODE.lock()).unwrap() }
    fn session_security_level() -> SecurityLevel { (*SESSION_SECURITY_LEVEL.lock()).unwrap() }
    fn p2p_security_level() -> SecurityLevel { (*P2P_SECURITY_LEVEL.lock()).unwrap() }
    fn timeout_cnt_ms() -> usize { (*TIMEOUT_CNT_MS.lock()).unwrap() }
    fn rand_message_len() -> usize { (*RAND_MESSAGE_LEN.lock()).unwrap() }
    fn encryption_algorithm() -> EncryptionAlgorithm { (*ENCRYPTION_ALGORITHM.lock()).unwrap() }
    fn kem_algorithm() -> KemAlgorithm { (*KEM_ALGORITHM.lock()).unwrap() }
    fn udp_mode() -> UdpMode { (*UDP_MODE.lock()).unwrap() }

    pub static SECRECY_MODE: parking_lot::Mutex<Option<SecrecyMode>> = const_mutex(None);
    pub static SESSION_SECURITY_LEVEL: parking_lot::Mutex<Option<SecurityLevel>> = const_mutex(None);
    pub static P2P_SECURITY_LEVEL: parking_lot::Mutex<Option<SecurityLevel>> = const_mutex(None);
    pub static COUNT: parking_lot::Mutex<Option<usize>> = const_mutex(None);
    pub static RAND_MESSAGE_LEN: parking_lot::Mutex<Option<usize>> = const_mutex(None);
    pub static TIMEOUT_CNT_MS: parking_lot::Mutex<Option<usize>> = const_mutex(None);
    pub static ENCRYPTION_ALGORITHM: parking_lot::Mutex<Option<EncryptionAlgorithm>> = const_mutex(None);
    pub static KEM_ALGORITHM: parking_lot::Mutex<Option<KemAlgorithm>> = const_mutex(None);
    pub static UDP_MODE: parking_lot::Mutex<Option<UdpMode>> = const_mutex(None);

    pub const DEFAULT_SESSION_SECURITY_LEVEL: SecurityLevel = SecurityLevel::LOW;
    pub const DEFAULT_P2P_SECURITY_LEVEL: SecurityLevel = SecurityLevel::LOW;
    pub const DEFAULT_SECRECY_MODE: SecrecyMode = SecrecyMode::BestEffort;
    pub const DEFAULT_UNDERLYING_PROTOCOL: UnderlyingProtocol = UnderlyingProtocol::Tcp;
    pub const DEFAULT_COUNT: usize = 4000;
    pub const DEFAULT_TIMEOUT_CNT_MS: usize = 60000 * 4;
    pub const DEFAULT_RAND_MESSAGE_LEN: usize = 2000;
    pub const DEFAULT_ENCRYPTION_ALGORITHM: EncryptionAlgorithm = EncryptionAlgorithm::AES_GCM_256_SIV;
    pub const DEFAULT_KEM_ALGORITHM: KemAlgorithm = KemAlgorithm::Firesaber;
    pub const DEFAULT_UDP_MODE: UdpMode = UdpMode::Disabled;

    // misc statics
    pub static P2P_SENDING_START_TIME: Mutex<Option<Instant>> = const_mutex(None);
    pub static P2P_SENDING_END_TIME: Mutex<Option<Instant>> = const_mutex(None);

    #[fixture]
    fn bind_addrs() -> (SocketAddr, SocketAddr, SocketAddr, SocketAddr) {
        let mut addrs = vec![];
        for _ in 0..4 {
            let port = portpicker::pick_unused_port().unwrap();
            addrs.push(SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap())
        }

        (addrs.pop().unwrap(), addrs.pop().unwrap(), addrs.pop().unwrap(), addrs.pop().unwrap())
    }

    #[rstest]
    fn stress_test_messaging(
        #[values("tcp", "tls", "quic")]
        underlying_proto_arg: &str,
        #[values("aes", "chacha")]
        enx_algorithm: &str,
        #[values("4000")]
        message_count_per_activity: &str,
        bind_addrs: (SocketAddr, SocketAddr, SocketAddr, SocketAddr),
        client_config: &Arc<ClientConfig>
    ) -> Result<(), Box<dyn Error>> {
        setup_log();
        super::utils::deadlock_detector();

        let map = std::collections::HashMap::from([
            ("proto", underlying_proto_arg),
            ("encryption_algorithm", enx_algorithm),
            ("count", message_count_per_activity)
        ]);

        extract_args_to_statics(InputExtractionSource::UnitTest(map));

        let total_p2p_messages = 2 * count();
        let total_messages = total_p2p_messages + (2 * count()) + (3 * count()); // p2p sending to each other simultaneously, c2s sending to each other simultaneously, then one group member using central server to broadcast to two others (3 encryptions)

        println!("Using Underlying Protocol: {:?}", PROTO.lock());
        println!("Encryption algorithm: {:?}", encryption_algorithm());
        println!("Post-quantum key exchange algorithm: {:?}", kem_algorithm());
        println!("Message count per node per activity: {} (total: {})", count(), total_messages);
        println!("Message length: {} bytes", rand_message_len());
        println!("Using secrecy mode: {:?}", secrecy_mode());
        println!("UDP mode: {:?}", udp_mode());
        println!("Session/P2P security level: {:?}/{:?}", session_security_level(), p2p_security_level());
        println!("Timeout: {}ms", timeout_cnt_ms());

        let rt = Builder::new_multi_thread().enable_time().enable_io().build().unwrap();

        let (server_bind_addr, client0_bind_addr, client1_bind_addr, client2_bind_addr) = bind_addrs;

        let params = kem_algorithm() + encryption_algorithm();

        let default_security_settings = SessionSecuritySettingsBuilder::default().with_secrecy_mode(secrecy_mode()).with_security_level(session_security_level()).with_crypto_params(params).build();

        static CLIENT0_FULLNAME: &str = "Thomas P Braun (test)";
        static CLIENT0_USERNAME: &str = "nologik";
        static CLIENT0_PASSWORD: &str = "password0";

        static CLIENT1_FULLNAME: &str = "Thomas P Braun I (test)";
        static CLIENT1_USERNAME: &str = "nologik1";
        static CLIENT1_PASSWORD: &str = "password1";

        static CLIENT2_FULLNAME: &str = "Thomas P Braun II (test)";
        static CLIENT2_USERNAME: &str = "nologik2";
        static CLIENT2_PASSWORD: &str = "password2";

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

        let handle = rt.handle().clone();

        rt.block_on(async move {
            log::info!("Setting up executors ...");
            let server_executor = create_executor(NodeType::Server(server_bind_addr), handle.clone(), server_bind_addr, Some(test_container.clone()), TestNodeType::Server, Vec::default(), backend_server(), underlying_proto(), client_config.clone()).await;

            log::info!("Done setting up server executor");

            let client0_executor = create_executor(NodeType::Peer, handle.clone(), client0_bind_addr, Some(test_container.clone()), TestNodeType::Client0, {
                vec![ActionType::Request(HdpServerRequest::RegisterToHypernode(server_bind_addr, proposed_credentials_0, keys0, default_security_settings)),
                     function(pinbox(client0_action1(test_container0, CLIENT0_PASSWORD, default_security_settings))),
                     function(pinbox(client0_action2(test_container1, ENABLE_FCM))),
                     function(pinbox(client0_action3(test_container2, p2p_security_level())))
                ]
            }, backend_client(), underlying_proto(), client_config.clone()).await;

            let client1_executor = create_executor(NodeType::Peer, handle.clone(), client1_bind_addr, Some(test_container.clone()), TestNodeType::Client1, {
                vec![ActionType::Request(HdpServerRequest::RegisterToHypernode(server_bind_addr, proposed_credentials_1, keys1, default_security_settings)),
                     function(pinbox(client1_action1(test_container3, CLIENT1_PASSWORD, default_security_settings)))
                ]
            }, backend_client(), underlying_proto(), client_config.clone()).await;

            let client2_executor = create_executor(NodeType::Peer, handle.clone(), client2_bind_addr, Some(test_container.clone()), TestNodeType::Client2, {
                vec![ActionType::Request(HdpServerRequest::RegisterToHypernode(server_bind_addr, proposed_credentials_2, keys2, default_security_settings)),
                     function(pinbox(client2_action1(test_container4, CLIENT2_PASSWORD, default_security_settings))),
                     function(pinbox(client2_action2(test_container5, ENABLE_FCM))),
                     function(pinbox(client2_action3_start_group(test_container6)))
                ]
            }, backend_client(), underlying_proto(), client_config.clone()).await;

            log::info!("Done setting up executors");

            let server_future = ExplicitPanicFuture::new(handle.spawn(AssertSendSafeFuture::new_silent(server_executor.execute())));
            let client0_future = ExplicitPanicFuture::new(handle.spawn(tokio::time::timeout(Duration::from_millis(timeout_cnt_ms() as u64), AssertSendSafeFuture::new_silent(client0_executor.execute()))));
            let client1_future = ExplicitPanicFuture::new(handle.spawn(tokio::time::timeout(Duration::from_millis(timeout_cnt_ms() as u64), AssertSendSafeFuture::new_silent(client1_executor.execute()))));
            let client2_future = ExplicitPanicFuture::new(handle.spawn(tokio::time::timeout(Duration::from_millis(timeout_cnt_ms() as u64), AssertSendSafeFuture::new_silent(client2_executor.execute()))));

            tokio::time::sleep(Duration::from_millis(100)).await;

            //futures::future::try_join_all(vec![client0_future, client1_future]).await.map(|res|)
            tokio::try_join!(client0_future, client1_future, client2_future)?.map(|res0, res1, res2| flatten_err(res0).and(flatten_err(res1)).and(flatten_err(res2)))?;

            log::info!("Ending test (client(s) done) ...");

            // Give time for the server to stop now that the clients are done
            let _ = tokio::time::timeout(Duration::from_millis(100), server_future).await;
            let elapsed = init.elapsed();
            let p2p_elapsed = P2P_SENDING_END_TIME.lock().as_ref().unwrap().duration_since(*P2P_SENDING_START_TIME.lock().as_ref().unwrap());
            let messages_per_sec = total_p2p_messages as f32 / p2p_elapsed.as_secs_f32();
            let total_p2p_bytes = 2 * count() * rand_message_len();
            let bytes_per_second = (total_p2p_bytes as f64) / p2p_elapsed.as_secs_f64();
            let mbps = bytes_per_second/(1_000_000f64);
            println!("Execution time: {}ms (p2p elapsed: {}ms. Approx min p2p rate: {} messages/sec = {} MB/s)", elapsed.as_millis(), p2p_elapsed.as_millis() , messages_per_sec, mbps);

            Ok(()) as Result<(), Box<dyn Error>>
        })?;

        std::mem::drop(rt);
        log::info!("Ending execution");
        Ok(())
    }

    #[allow(unused_results)]
    async fn create_executor(hypernode_type: NodeType, rt: Handle, bind_addr: SocketAddr, test_container: Option<Arc<RwLock<TestContainer>>>, node_type: TestNodeType, commands: Vec<ActionType>, backend_type: BackendType, underlying_proto: UnderlyingProtocol, client_config: Arc<ClientConfig>) -> KernelExecutor<TestKernel> {
        let home_dir = format!("{}/tmp/{}_{}", home_dir().unwrap().to_str().unwrap(), bind_addr.ip(), bind_addr.port());
        log::info!("Home dir: {}", &home_dir);
        let account_manager = AccountManager::new(bind_addr, Some(home_dir), backend_type, None, None, None).await.unwrap();
        account_manager.purge().await.unwrap();
        let kernel = TestKernel::new(node_type, commands, test_container);
        KernelExecutor::new(rt, hypernode_type, account_manager, kernel, underlying_proto, Some(client_config)).await.unwrap()
    }

    pub mod kernel {
        use std::collections::{HashSet, VecDeque};
        use std::pin::Pin;
        use std::sync::Arc;

        use async_recursion::async_recursion;
        use async_trait::async_trait;
        use futures::Future;
        use parking_lot::{Mutex, RwLock};
        use rand::Rng;
        use rand::rngs::ThreadRng;
        use serde::{Deserialize, Serialize};
        use tokio::sync::broadcast;

        use hyxe_crypt::prelude::SecBuffer;
        use hyxe_fs::io::SyncIO;
        use std::time::Duration;
        use hyxe_user::client_account::ClientNetworkAccount;

        use crate::tests::{GROUP_TICKET_TEST, handle_c2s_peer_channel, handle_peer_channel, rand_message_len, TestNodeType, handle_group_channel};
        use crate::utils::{assert, assert_eq};
        use hyxe_net::prelude::*;

        #[derive(Serialize, Deserialize)]
        pub struct MessageTransfer {
            pub idx: u64,
            pub rand: Vec<u8>
        }

        impl MessageTransfer {
            pub fn create(idx: u64) -> SecureProtocolPacket {
                let mut rng = ThreadRng::default();
                let mut rand = vec![0u8; rand_message_len()];
                rng.fill(rand.as_mut_slice());

                SecureProtocolPacket::from(Self { idx, rand }.serialize_to_vector().unwrap())
            }

            pub fn receive(input: SecBuffer) -> Self {
                Self::deserialize_from_vector(input.as_ref()).unwrap()
            }
        }


        #[derive(Default)]
        pub struct TestContainer {
            pub cnac_client0: Option<ClientNetworkAccount>,
            pub cnac_client1: Option<ClientNetworkAccount>,
            pub cnac_client2: Option<ClientNetworkAccount>,
            pub remote_client0: Option<NodeRemote>,
            pub remote_client1: Option<NodeRemote>,
            pub remote_client2: Option<NodeRemote>,
            pub queued_requests_client0: Option<Arc<Mutex<HashSet<Ticket>>>>,
            pub queued_requests_client1: Option<Arc<Mutex<HashSet<Ticket>>>>,
            pub queued_requests_client2: Option<Arc<Mutex<HashSet<Ticket>>>>,
            pub can_begin_peer_post_register_recv: Option<VecDeque<broadcast::Receiver<()>>>,
            pub can_begin_peer_post_register_notifier_cl_1: Option<broadcast::Sender<()>>,
            pub p2p_pre_sending_tx: Option<broadcast::Sender<()>>,
            pub p2p_pre_sending_rx: Option<VecDeque<broadcast::Receiver<()>>>,
            pub p2p_sending_complete_tx: Option<broadcast::Sender<()>>,
            pub p2p_sending_complete_rx: Option<VecDeque<broadcast::Receiver<()>>>,
            pub group_end_tx: Option<broadcast::Sender<()>>,
            pub group_end_rxs: Option<VecDeque<broadcast::Receiver<()>>>,
            pub client0_c2s_channel: Option<PeerChannel>,
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
                let (p2p_sending_complete_tx, p2p_sending_complete_rx) = broadcast::channel(10);
                let p2p_sending_complete_rx_1 = p2p_sending_complete_tx.subscribe();
                let p2p_sending_complete_tx = Some(p2p_sending_complete_tx);
                let can_begin_peer_post_register_notifier_cl_1 = Some(can_begin_peer_post_register_notifier_cl_1);

                let mut p2p_sending_complete_rxs = VecDeque::new();
                p2p_sending_complete_rxs.push_back(p2p_sending_complete_rx);
                p2p_sending_complete_rxs.push_back(p2p_sending_complete_rx_1);
                let p2p_sending_complete_rx = Some(p2p_sending_complete_rxs);

                // client 0 and 2 must wait for client 1 to connect
                let mut can_begin_peer_post_register_recv = VecDeque::with_capacity(2);
                can_begin_peer_post_register_recv.push_back(can_begin_peer_post_register_recv_cl_0);
                can_begin_peer_post_register_recv.push_back(can_begin_peer_post_register_recv_cl_2);
                let can_begin_peer_post_register_recv = Some(can_begin_peer_post_register_recv);

                let (group_end_tx, group_end_rx0) = broadcast::channel(10);
                let mut group_end_rxs = VecDeque::with_capacity(3);
                group_end_rxs.push_back(group_end_rx0);
                group_end_rxs.push_back(group_end_tx.subscribe());
                group_end_rxs.push_back(group_end_tx.subscribe());
                let group_end_tx = Some(group_end_tx);
                let group_end_rxs = Some(group_end_rxs);

                let (p2p_pre_sending_tx, p2p_pre_sending_rx) = broadcast::channel(10);
                let mut p2p_pre_sending_rxs = VecDeque::with_capacity(2);
                p2p_pre_sending_rxs.push_back(p2p_pre_sending_rx);
                p2p_pre_sending_rxs.push_back(p2p_pre_sending_tx.subscribe());
                let p2p_pre_sending_tx = Some(p2p_pre_sending_tx);
                let p2p_pre_sending_rx = Some(p2p_pre_sending_rxs);

                Self { p2p_pre_sending_rx, p2p_pre_sending_tx, group_end_tx, group_end_rxs, p2p_sending_complete_rx, p2p_sending_complete_tx, can_begin_peer_post_register_notifier_cl_1, can_begin_peer_post_register_recv, ..Default::default() }
            }
        }

        pub enum ActionType {
            Request(HdpServerRequest),
            Function(Pin<Box<dyn Future<Output=Option<ActionType>> + Send + 'static>>),
        }

        pub struct TestKernel {
            node_type: TestNodeType,
            commands: Mutex<Vec<ActionType>>,
            remote: Option<NodeRemote>,
            // a ticket gets added once a request is submitted. Once a VALID response occurs, the entry is removed. If an invalid response is received, then the ticket lingers, then the timer throws an error
            queued_requests: Arc<Mutex<HashSet<Ticket>>>,
            item_container: Option<Arc<RwLock<TestContainer>>>,
            ctx_cid: Mutex<Option<u64>>,
        }

        impl TestKernel {
            pub fn new(node_type: TestNodeType, commands: Vec<ActionType>, item_container: Option<Arc<RwLock<TestContainer>>>) -> Self {
                Self { node_type, commands: Mutex::new(commands), remote: None, queued_requests: Arc::new(Mutex::new(HashSet::new())), item_container, ctx_cid: Mutex::new(None) }
            }

            #[async_recursion]
            async fn execute_action(&self, request: ActionType, remote: &mut NodeRemote) {
                match request {
                    ActionType::Request(request) => {
                        let ticket = remote.send(request).await.unwrap();
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
                if self.node_type != TestNodeType::Server {
                    let mut remote = self.remote.clone().unwrap();
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

                    self.execute_action(item, &mut remote).await;

                }
            }

            fn on_valid_ticket_received(&self, ticket: Ticket) {
                if self.node_type != TestNodeType::Server {
                    assert(self.queued_requests.lock().remove(&ticket), "EXCV");
                    log::info!("{:?} checked-in ticket {}", self.node_type, ticket);
                }
            }

            #[allow(dead_code)]
            fn shutdown_in(&self, time: Option<Duration>) {
                let mut remote = self.remote.clone().unwrap();
                tokio::task::spawn(async move {
                    if let Some(time) = time {
                        tokio::time::sleep(time).await;
                        remote.shutdown().await.unwrap();
                    } else {
                        remote.shutdown().await.unwrap();
                    }
                });
            }
        }

        #[async_trait]
        impl NetKernel for TestKernel {
            fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
                self.remote = Some(server_remote);
                Ok(())
            }

            async fn on_start(&self) -> Result<(), NetworkError> {
                log::info!("Running node {:?} onStart", self.node_type);
                let mut server_remote = self.remote.clone().unwrap();
                if self.node_type != TestNodeType::Server {
                    let item = {
                        self.commands.lock().remove(0)
                    };

                    self.execute_action(item, &mut server_remote).await;
                    let container = self.item_container.as_ref().unwrap();
                    let mut write = container.write();
                    if self.node_type == TestNodeType::Client0 {
                        write.remote_client0 = Some(server_remote.clone());
                        write.queued_requests_client0 = Some(self.queued_requests.clone());
                    } else if self.node_type == TestNodeType::Client1 {
                        write.remote_client1 = Some(server_remote.clone());
                        write.queued_requests_client1 = Some(self.queued_requests.clone());
                    } else if self.node_type == TestNodeType::Client2 {
                        write.remote_client2 = Some(server_remote.clone());
                        write.queued_requests_client2 = Some(self.queued_requests.clone());
                    } else {
                        log::error!("Unaccounted node type {:?}", self.node_type);
                        assert(false, "TTT");
                    }
                }

                Ok(())
            }

            async fn on_node_event_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
                log::info!("[{:?}] Message received: {:?}", self.node_type, &message);
                if self.node_type != TestNodeType::Server || message.is_connect_success_type() {
                    match message {
                        HdpServerResult::ConnectFail(..) | HdpServerResult::RegisterFailure(..) => {
                            assert(false, "Register/Connect failed");
                        }

                        HdpServerResult::GroupEvent(implicated_cid, ticket, group) => {
                            match group {
                                GroupBroadcast::Invitation(key) => {
                                    log::info!("{:?} Received an invitation to group {}", self.node_type, key);
                                    // accept it
                                    if self.node_type == TestNodeType::Client0 || self.node_type == TestNodeType::Client1 {
                                        let accept = GroupBroadcast::AcceptMembership(key);
                                        let mut remote = self.remote.clone().unwrap();
                                        remote.send_with_custom_ticket(ticket, HdpServerRequest::GroupBroadcastCommand(implicated_cid, accept)).await.unwrap();
                                    } else {
                                        return Err(NetworkError::InternalError("Invalid group invitation recipient"));
                                    }
                                }

                                GroupBroadcast::CreateResponse(Some(key)) => {
                                    log::info!("[Group] Successfully created group {} for {:?}", key, self.node_type);
                                    assert(self.node_type == TestNodeType::Client2, "FTQ");
                                }

                                GroupBroadcast::AcceptMembershipResponse(_key, success) => {
                                    // client 1 & 0 will get this
                                    assert(self.node_type == TestNodeType::Client0 || self.node_type == TestNodeType::Client1, "EQW");
                                    assert(success, "YTR");
                                    log::info!("[Group] Successfully entered* group for {:?}? {}", self.node_type, success);
                                }

                                _ => {}
                            }
                        }

                        HdpServerResult::GroupChannelCreated(_ticket, channel) => {
                            handle_group_channel(self.remote.clone().unwrap(), self.node_type, self.item_container.clone().unwrap(), self.queued_requests.clone(), channel)
                        }

                        HdpServerResult::InternalServerError(_, err) => {
                            log::error!("Internal server error: {}", err);
                            std::process::exit(-1);
                        }

                        HdpServerResult::RegisterOkay(ticket, cnac, _) => {
                            log::info!("SUCCESS registering ticket {} for {:?}", ticket, self.node_type);
                            // register the CID to be used in further checks
                            *self.ctx_cid.lock() = Some(cnac.get_cid());

                            if self.node_type == TestNodeType::Client0 {
                                self.item_container.as_ref().unwrap().write().cnac_client0 = Some(cnac);
                            } else if self.node_type == TestNodeType::Client1 {
                                self.item_container.as_ref().unwrap().write().cnac_client1 = Some(cnac);
                            } else if self.node_type == TestNodeType::Client2 {
                                self.item_container.as_ref().unwrap().write().cnac_client2 = Some(cnac);
                            } else {
                                //panic!("Unaccounted node type: {:?}", self.node_type)
                                assert(false, "Unaccounted node type");
                            }

                            self.on_valid_ticket_received(ticket);
                        }

                        HdpServerResult::ConnectSuccess(ticket, _, _, _, _, _, _, _, channel, _udp) => {
                            log::info!("SUCCESS connecting ticket {} for {:?}", ticket, self.node_type);
                            self.on_valid_ticket_received(ticket);

                            // The server is reactive. It won't begin firing packets at client0 until client0 starts firing at it
                            if self.node_type == TestNodeType::Server || self.node_type == TestNodeType::Client0 {
                                if self.node_type == TestNodeType::Client0 {
                                    let container = self.item_container.as_ref().unwrap();
                                    container.write().client0_c2s_channel = Some(channel);
                                } else {
                                    handle_c2s_peer_channel(self.node_type, self.item_container.as_ref().unwrap().clone(), self.queued_requests.clone(), channel);
                                }
                            }


                            if self.node_type == TestNodeType::Client1 {
                                assert_eq(self.item_container.as_ref().unwrap().write().can_begin_peer_post_register_notifier_cl_1.as_ref().unwrap().send(()).unwrap(), 2, "Expected broadcast count not present");
                            }

                            if self.node_type == TestNodeType::Client0 || self.node_type == TestNodeType::Client2 {
                                // wait to ensure Client1 connects
                                let mut recv = self.item_container.as_ref().unwrap().write().can_begin_peer_post_register_recv.as_mut().unwrap().pop_back().unwrap();
                                log::info!("[Broadcast await] waiting for client 1 ...");
                                recv.recv().await.unwrap();
                                log::info!("[Broadcast await] Done awaiting ...");
                            }
                        }

                        HdpServerResult::PeerChannelCreated(ticket, channel, _udp) => {
                            self.on_valid_ticket_received(ticket);
                            assert(self.node_type == TestNodeType::Server || self.node_type == TestNodeType::Client0 || self.node_type == TestNodeType::Client1, "ZSQ");
                            // pull out the c2s channel loaded earlier
                            let c2s_channel = if self.node_type == TestNodeType::Client0 {
                                let container = self.item_container.as_ref().unwrap();
                                let item = container.write().client0_c2s_channel.take().unwrap();
                                Some(item)
                            } else {
                                None
                            };

                            handle_peer_channel(channel, self.remote.clone().unwrap(), self.item_container.clone().unwrap(), self.queued_requests.clone(), self.node_type, c2s_channel);
                            //self.shutdown_in(Some(Duration::from_millis(1000)));
                        }

                        HdpServerResult::PeerEvent(signal, ticket) => {
                            match signal {
                                PeerSignal::PostRegister(vconn, _peer_username, _,_, resp_opt, fcm) => {
                                    if let Some(resp) = resp_opt {
                                        match resp {
                                            PeerResponse::Accept(_) => {
                                                log::info!("RECV PeerResponse::Accept for {:?}", self.node_type);
                                                self.on_valid_ticket_received(ticket);

                                                if self.node_type == TestNodeType::Client2 {
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
                                        assert_eq(self.node_type, TestNodeType::Client1, "LV0");
                                        let item_container = self.item_container.as_ref().unwrap();
                                        let accept_post_register = {
                                            let read = item_container.read();
                                            let this_cnac = read.cnac_client1.as_ref().unwrap();

                                            let this_cid = this_cnac.get_cid();
                                            let this_username = this_cnac.get_username();
                                            HdpServerRequest::PeerCommand(this_cid, PeerSignal::PostRegister(vconn.reverse(), this_username, None,Some(ticket), Some(PeerResponse::Accept(None)), fcm))
                                        };

                                        self.remote.clone().unwrap().send_with_custom_ticket(ticket, accept_post_register).await.unwrap();
                                        //self.shutdown_in(Some(Duration::from_millis(500)));
                                    }
                                }

                                PeerSignal::PostConnect(vconn, _, resp_opt, p2p_sec_lvl, udp_mode) => {
                                    if let Some(_resp) = resp_opt {
                                        // no need to handle since we only react to peer channel created
                                    } else {
                                        let accept_post_connect = {
                                            // the receiver is client 1
                                            assert_eq(self.node_type, TestNodeType::Client1, "PQZ");
                                            // receiver peer. ALlow the connection
                                            let item_container = self.item_container.as_ref().unwrap();
                                            let read = item_container.read();
                                            let this_cnac = read.cnac_client1.as_ref().unwrap();

                                            let this_cid = this_cnac.get_cid();
                                            let accept_post_connect = HdpServerRequest::PeerCommand(this_cid, PeerSignal::PostConnect(vconn.reverse(), Some(ticket), Some(PeerResponse::Accept(None)), p2p_sec_lvl, udp_mode));
                                            // we will expect a PeerChannel
                                            self.queued_requests.lock().insert(ticket);
                                            accept_post_connect
                                        };

                                        self.remote.clone().unwrap().send_with_custom_ticket(ticket, accept_post_connect).await.unwrap();
                                        //self.shutdown_in(Some(Duration::from_millis(1500)));
                                    }
                                }

                                PeerSignal::SignalReceived(_) => {}

                                PeerSignal::Disconnect(vconn, _) => {
                                    log::warn!("Peer vconn {} disconnected", vconn)
                                }

                                _ => {
                                    log::error!("[QUITTING] Unexpected signal: {:?}", signal);
                                    std::process::exit(-1);
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

            async fn on_stop(self) -> Result<(), NetworkError> {
                if self.queued_requests.lock().len() != 0 || self.commands.lock().len() != 0 {
                    log::error!("ITEMS REMAIN (node type: {:?})", self.node_type);
                    Err(NetworkError::Generic(format!("Test error: items still in queue, or commands still pending for {:?}", self.node_type)))
                } else {
                    log::info!("NO ITEMS REMAIN (node type: {:?})", self.node_type);
                    Ok(())
                }
            }

            fn can_run(&self) -> bool {
                true
            }
        }
    }

    const CLIENT_SERVER_MESSAGE_STRESS_TEST: Ticket = Ticket(0xfffffffe);
    const P2P_MESSAGE_STRESS_TEST: Ticket = Ticket(0xffffffff);
    const GROUP_TICKET_TEST: Ticket = Ticket(0xfffffffd);

    pub fn handle_c2s_peer_channel(node_type: TestNodeType, container: Arc<RwLock<TestContainer>>, queued_requests: Arc<Mutex<HashSet<Ticket>>>, channel: PeerChannel) {
        assert(node_type == TestNodeType::Server || node_type == TestNodeType::Client0, "POZX");
        let (sink, mut stream) = channel.split();

        if node_type == TestNodeType::Client0 {
            tokio::task::spawn(start_client_server_stress_test(queued_requests.clone(), sink.clone(),  node_type));
        }

        let task = async move {
            while let Some(msg) = stream.next().await {
                log::info!("{:?} Message delivery **", node_type);
                let mut lock = container.write();
                let data = MessageTransfer::receive(msg);
                match node_type {
                    TestNodeType::Client0 => {
                        // client0 already had its sender started. We only need to increment the inner count
                        //let val = byteorder::BigEndian::read_u64(msg.as_ref());
                        assert_eq(data.idx as usize, lock.client_server_as_client_recv_count, "MRAP");
                        assert_eq(data.rand.len(), rand_message_len(), "LZX");
                        log::info!("[Client/Server Stress Test] RECV {} for {:?}", lock.client_server_as_client_recv_count, node_type);
                        lock.client_server_as_client_recv_count += 1;

                        if lock.client_server_as_client_recv_count >= count() {
                            log::info!("Client has finished receiving {} messages", count());
                            lock.client_server_stress_test_done_as_client = true;
                            std::mem::drop(lock);
                            let mut lock = queued_requests.lock();
                            assert(lock.remove(&CLIENT_SERVER_MESSAGE_STRESS_TEST), "VIDZ");
                            // we insert the group ticket. We wait for client2 to send the group invite
                            assert(lock.insert(GROUP_TICKET_TEST), "VIDX");
                            std::mem::drop(lock);
                        }
                    }

                    TestNodeType::Server => {
                        //log::info!("RBX");
                        //let val = byteorder::BigEndian::read_u64(msg.as_ref());
                        assert_eq(data.idx as usize, lock.client_server_as_server_recv_count, "NRAP");
                        assert_eq(data.rand.len(), rand_message_len(), "QAAM");
                        log::info!("[Client/Server Stress Test] RECV {} for {:?}", lock.client_server_as_server_recv_count, node_type);
                        lock.client_server_as_server_recv_count += 1;

                        if lock.client_server_as_server_recv_count == 1 {
                            // we start firing packets from this side
                            // lock.client_server_stress_test_done_as_server = true;
                            // we must fire-up this side's subroutine for sending packets
                            //let client0_cid = lock.cnac_client0.as_ref().unwrap().get_cid();
                            let queued_requests = queued_requests.clone();
                            std::mem::drop(lock);
                            tokio::task::spawn(start_client_server_stress_test(queued_requests, sink.clone(),  node_type));
                            continue;
                            // The signal supposedly gets sent to the primary_outbound_stream, but, they aren't all received there by the sink ... TCP, this does not occur, but with TLS, the error occurs
                        }

                        if lock.client_server_as_server_recv_count >= count() {
                            log::info!("SERVER has finished receiving {} messages", count());
                            lock.client_server_stress_test_done_as_server = true;
                            std::mem::drop(lock);
                            let mut lock = queued_requests.lock();
                            assert(lock.remove(&CLIENT_SERVER_MESSAGE_STRESS_TEST), "JKZ");
                            // we insert the group ticket. We wait for client2 to send the group invite
                            assert(lock.insert(GROUP_TICKET_TEST), "JKOT");
                        }
                    }

                    _ => {
                        log::error!("Invalid message delivery recipient {:?}", node_type);
                        assert(false, "Invalid message delivery recipient");
                    }
                }
            }
        };

        tokio::task::spawn(task);
    }

    #[allow(unused_results)]
    pub fn handle_group_channel(remote: NodeRemote, node_type: TestNodeType, test_container: Arc<RwLock<TestContainer>>, requests: Arc<Mutex<HashSet<Ticket>>>, channel: GroupChannel) {
        tokio::task::spawn(async move {
            let (sink, mut stream) = channel.split();
            let sink = &mut Some(sink);

            while let Some(evt) = stream.next().await {
                match evt {
                    GroupBroadcastPayload::Message { payload, .. } => {
                        use byteorder::ByteOrder;
                        let val = byteorder::BigEndian::read_u64(payload.as_ref());
                        assert(val <= count() as u64, "DFT");
                        assert(node_type == TestNodeType::Client0 || node_type == TestNodeType::Client1, "LKJ");
                        let mut lock = test_container.write();
                        let cnt = if node_type == TestNodeType::Client0 {
                            lock.group_messages_received_client0 += 1;
                            lock.group_messages_received_client0
                        } else {
                            lock.group_messages_received_client1 += 1;
                            lock.group_messages_received_client1
                        };

                        log::info!("[Group] {:?} received {} messages", node_type, cnt);

                        if cnt >= count() {
                            log::info!("[Group] {:?} is done receiving messages", node_type);
                            requests.lock().remove(&GROUP_TICKET_TEST);
                            let mut remote = remote.clone();

                            let tx = lock.group_end_tx.clone().unwrap();
                            let mut rx = lock.group_end_rxs.as_mut().map(|r| r.pop_front().unwrap()).unwrap();
                            tx.send(()).unwrap();
                            std::mem::drop(lock);

                            // now, await 3 times
                            tokio::task::spawn(async move {
                                rx.recv().await.unwrap();
                                rx.recv().await.unwrap();
                                rx.recv().await.unwrap();
                                remote.shutdown().await.unwrap();
                            });
                        }
                    }

                    GroupBroadcastPayload::Event { payload } => {
                        match payload {
                            GroupBroadcast::MessageResponse(_, success) => {
                                assert(success, "UQE");
                                assert(node_type == TestNodeType::Client2, "KZMT");
                                let mut lock = test_container.write();
                                lock.group_messages_verified_client2_host += 1;

                                if lock.group_messages_verified_client2_host >= count() {
                                    log::info!("[Group] {:?}/Host has successfully sent all messages", node_type);
                                    requests.lock().remove(&GROUP_TICKET_TEST);
                                    let mut remote = remote.clone();

                                    let tx = lock.group_end_tx.clone().unwrap();
                                    let mut rx = lock.group_end_rxs.as_mut().map(|r| r.pop_front().unwrap()).unwrap();
                                    tx.send(()).unwrap();
                                    std::mem::drop(lock);

                                    // now, await 3 times
                                    tokio::task::spawn(async move {
                                        rx.recv().await.unwrap();
                                        rx.recv().await.unwrap();
                                        rx.recv().await.unwrap();
                                        remote.shutdown().await.unwrap();
                                    });
                                }
                            },

                            GroupBroadcast::MemberStateChanged(_key, state) => {
                                if node_type == TestNodeType::Client2 {
                                    log::info!("[Group] Member state changed: {:?}", &state);
                                    match state {
                                        MemberState::EnteredGroup(peers) => {
                                            let mut lock = test_container.write();
                                            lock.group_members_entered_for_client2 += peers.len();

                                            if lock.group_members_entered_for_client2 == 2 {
                                                log::info!("[Group] Client2/Host will now begin group stress test ...");
                                                std::mem::drop(lock);

                                                client2_action4_fire_group(sink.take().unwrap());
                                            }
                                        }

                                        _ => {}
                                    }
                                }
                            }

                            _ => {}
                        }
                    }
                }
            }
        });
    }

    #[allow(unused_results)]
    pub fn handle_peer_channel(channel: PeerChannel, _remote: NodeRemote, test_container: Arc<RwLock<TestContainer>>, requests: Arc<Mutex<HashSet<Ticket>>>, node_type: TestNodeType, c2s_channel: Option<PeerChannel>) {
        assert(requests.lock().insert(P2P_MESSAGE_STRESS_TEST), "YUW");
        assert(node_type != TestNodeType::Server, "This function is not for servers");
        log::info!("[Peer channel] received on {:?}", node_type);
        tokio::task::spawn(async move {
            let (broadcast_tx, mut broadcast_rx, p2p_broadcast_tx, mut p2p_broadcast_rx) = {
                let mut write = test_container.write();
                let p2p_broadcast_tx = write.p2p_pre_sending_tx.clone().unwrap();
                let p2p_broadcast_rx = write.p2p_pre_sending_rx.as_mut().unwrap().pop_front().unwrap();

                let broadcast_tx = write.p2p_sending_complete_tx.clone().unwrap();
                let broadcast_rx = write.p2p_sending_complete_rx.as_mut().unwrap().pop_front().unwrap();
                (broadcast_tx, broadcast_rx, p2p_broadcast_tx, p2p_broadcast_rx)
            };

            //tokio::time::sleep(Duration::from_millis(300)).await;
            p2p_broadcast_tx.send(()).unwrap();
            p2p_broadcast_rx.recv().await.unwrap();
            p2p_broadcast_rx.recv().await.unwrap();
            //tokio::time::sleep(Duration::from_millis(300)).await;
            *P2P_SENDING_START_TIME.lock() = Some(Instant::now());
            let (mut sink, mut stream) = channel.split();
            let sender = async move {

                    for x in 0..count() {
                        if x % 10 == 9 {
                            //tokio::time::sleep(Duration::from_millis(1)).await
                        }
                        //tokio::time::sleep(Duration::from_millis(10)).await;
                        //sink.send_unbounded(MessageTransfer::create(x as u64)).unwrap();
                        sink.send_message(MessageTransfer::create(x as _)).await.unwrap();
                    }
                //let mut stream = tokio_stream::iter((0..COUNT).map(|x| Ok(MessageTransfer::create(x as u64))).collect::<Vec<Result<SecBuffer, _>>>());
                //sink.send_all(&mut stream).await.unwrap();

                    log::info!("DONE sending {} messages for {:?}", count(), node_type);

                true
            };



            let receiver = async move {
                let mut messages_recv = 0;

                while let Some(val) = stream.next().await {
                    let val = MessageTransfer::receive(val);
                    match node_type {
                        TestNodeType::Client0 | TestNodeType::Client1 => {
                            log::info!("RECV MESSAGE {:?}. CUR COUNT: {}", node_type, messages_recv);
                            //let value = byteorder::BigEndian::read_u64(val.as_ref()) as usize;
                            assert_eq(messages_recv, val.idx as usize, "EGQ");
                            messages_recv += 1;
                            if messages_recv >= count() {
                                break;
                            }
                        }

                        n => {
                            panic!("Unaccounted node type in p2p message handler: {:?}", n);
                        }
                    }
                }

                let res = if messages_recv >= count() {
                    log::info!("DONE receiving {} messages for {:?}", count(), node_type);
                    true
                } else {
                    log::error!("Unable to receive all messages {:?}: {}/{}", node_type, messages_recv, count());
                    false
                };

                // before dropping the channel, we want to wait for the other side to send its signal, as well as count this one's.
                broadcast_tx.send(()).unwrap();
                broadcast_rx.recv().await.unwrap();
                broadcast_rx.recv().await.unwrap();
                *P2P_SENDING_END_TIME.lock() = Some(Instant::now());
                // hacky fix: don't drop the recieve half since this will kill the session
                std::mem::forget(stream);
                res
            };

            if tokio::join!(sender, receiver) == (true, true) {
                assert(requests.lock().remove(&P2P_MESSAGE_STRESS_TEST), "KPA");
                if node_type == TestNodeType::Client0 {
                    handle_c2s_peer_channel(node_type,test_container.clone(), requests.clone(), c2s_channel.unwrap());
                } else {
                    // at this point, client 1 will idle until the client/server stress test is done
                    log::info!("Client1 awaiting for group command ...");
                    assert(requests.lock().insert(GROUP_TICKET_TEST), "KPK");
                }
            } else {
                log::error!("One or more tx/rx failed for {:?}", node_type);
                assert(false, "One or more tx/rx failed");
            }
        });
    }

    async fn start_client_server_stress_test(requests: Arc<Mutex<HashSet<Ticket>>>, mut sink: PeerChannelSendHalf, node_type: TestNodeType) {
        assert(requests.lock().insert(CLIENT_SERVER_MESSAGE_STRESS_TEST), "MV0");
        log::info!("[Server/Client Stress Test] Starting send of {} messages [local type: {:?}]", count(), node_type);

        //let mut stream = tokio_stream::iter((0..COUNT).map(|x| Ok(MessageTransfer::create(x as u64))).collect::<Vec<Result<SecBuffer, _>>>());
        //sink.send_all(&mut stream).await.unwrap();

        for x in 0..count() {
            //sink.send(MessageTransfer::create(x as u64)).await.unwrap();
            sink.send_message(MessageTransfer::create(x as u64)).await.unwrap();
            //sink.send_unbounded(MessageTransfer::create(x as _)).unwrap();
            //tokio::time::sleep(Duration::from_micros(1000)).await; // For some reason, when THIS line is added, we don't get the error of it randomly stopping ... weird
        }

        log::info!("[Server/Client Stress Test] Done sending {} messages as {:?}", count(), node_type)
    }

    #[allow(dead_code)]
    fn default_error(msg: &'static str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, msg)
    }

    async fn client0_action1(item_container: Arc<RwLock<TestContainer>>, password: &'static str, security_settings: SessionSecuritySettings) -> Option<ActionType> {
        let read_c = item_container.read();
        let cnac = read_c.cnac_client0.clone().unwrap();
        let cid = cnac.get_cid();

        Some(ActionType::Request(HdpServerRequest::ConnectToHypernode(AuthenticationRequest::credentialed(cid, password), ConnectMode::Standard {force_login: false},  None, udp_mode(), None, security_settings)))
    }

    async fn client1_action1(item_container: Arc<RwLock<TestContainer>>, password: &'static str, security_settings: SessionSecuritySettings) -> Option<ActionType> {
        let read_c = item_container.read();
        let cnac = read_c.cnac_client1.clone().unwrap();
        let cid = cnac.get_cid();

        Some(ActionType::Request(HdpServerRequest::ConnectToHypernode(AuthenticationRequest::credentialed(cid, password), ConnectMode::Standard {force_login: false},  None, udp_mode(), None, security_settings)))
    }

    async fn client2_action1(item_container: Arc<RwLock<TestContainer>>, password: &'static str, security_settings: SessionSecuritySettings) -> Option<ActionType> {
        let read_c = item_container.read();
        let cnac = read_c.cnac_client2.clone().unwrap();
        let cid = cnac.get_cid();

        Some(ActionType::Request(HdpServerRequest::ConnectToHypernode(AuthenticationRequest::credentialed(cid, password), ConnectMode::Standard { force_login: false },  None, udp_mode(), None, security_settings)))
    }

    // client 2 will initiate the p2p *registration* to client1
    async fn client2_action2(item_container: Arc<RwLock<TestContainer>>, enable_fcm: bool) -> Option<ActionType> {
        AssertSendSafeFuture::spawn(async move {
            log::info!("Executing Client2_action2");
            let write = item_container.write();
            let cnac = write.cnac_client1.clone().unwrap();
            let client2_cnac = write.cnac_client2.as_ref().unwrap();
            let client2_id = client2_cnac.get_cid();
            let target_cid = cnac.get_cid();
            let client2_username = client2_cnac.get_username();
            let requests = write.queued_requests_client2.clone().unwrap();
            let fcm = enable_fcm.then(|| FcmPostRegister::Enable).unwrap_or(FcmPostRegister::Disable);
            let post_register_request = HdpServerRequest::PeerCommand(client2_id, PeerSignal::PostRegister(PeerConnectionType::HyperLANPeerToHyperLANPeer(client2_id, target_cid), client2_username, None, None, None, fcm));

            let mut remote_client2 = write.remote_client2.clone().unwrap();
            std::mem::drop(write);
            let ticket = remote_client2.send(post_register_request).await.unwrap();
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
        AssertSendSafeFuture::spawn(async move {
            loop {
                {
                    let read = item_container.read();
                    if read.client_server_stress_test_done_as_server && read.client_server_stress_test_done_as_client {
                        let this_cid = read.cnac_client2.as_ref().unwrap().get_cid();
                        log::info!("[GROUP Stress test] Starting group stress test w/ client2 host [members: client0 & client1] (self: {})", this_cid);
                        let client0_cnac = read.cnac_client0.as_ref().unwrap();
                        let client1_cnac = read.cnac_client1.as_ref().unwrap();

                        let request = HdpServerRequest::GroupBroadcastCommand(this_cid, GroupBroadcast::Create(vec![client0_cnac.get_cid(), client1_cnac.get_cid()]));
                        let mut remote = read.remote_client2.clone().unwrap();

                        std::mem::drop(read);
                        let _ticket = remote.send(request).await.unwrap();
                        //assert(read.queued_requests_client2.as_ref().unwrap().lock().insert(ticket), "MDY");
                        return;
                    }
                }

                // TODO: Replace with broadcast
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        None
    }

    fn client2_action4_fire_group(sink: GroupChannelSendHalf) {
        tokio::task::spawn(async move {
            log::info!("[GROUP Stress test] Client2/Host firing messages @ [members: client0 && client1]");
            let stream = (0..count()).into_iter().map(|idx| SecBuffer::from(&idx.to_be_bytes() as &[u8]));
            for packet in stream {
                sink.send_message(packet).await.unwrap();
            }

            log::info!("[GROUP Stress test] Client2/Host done firing messages");
            // We don't get to remove the GROUP_TICKET_TEST quite yet. We need to receive COUNT of GroupBroadcast::MessageResponse(key, true) first
        });
    }

    // client 0 will initiate the p2p *registration* to client1
    async fn client0_action2(item_container: Arc<RwLock<TestContainer>>, enable_fcm: bool) -> Option<ActionType> {
        AssertSendSafeFuture::spawn(async move {
            let write = item_container.write();
            let cnac = write.cnac_client1.clone().unwrap();
            let client0_cnac = write.cnac_client0.as_ref().unwrap();
            let client0_id = client0_cnac.get_cid();
            let target_cid = cnac.get_cid();
            let client0_username = client0_cnac.get_username();
            let requests = write.queued_requests_client0.clone().unwrap();
            let fcm = enable_fcm.then(|| FcmPostRegister::Enable).unwrap_or(FcmPostRegister::Disable);
            let post_register_request = HdpServerRequest::PeerCommand(client0_id, PeerSignal::PostRegister(PeerConnectionType::HyperLANPeerToHyperLANPeer(client0_id, target_cid), client0_username, None,None, None, fcm));

            let mut remote_client0 = write.remote_client0.clone().unwrap();
            std::mem::drop(write);
            let ticket = remote_client0.send(post_register_request).await.unwrap();
            assert(requests.lock().insert(ticket), "ABK");
        });

        None
    }

    // client 0 will initiate the p2p *connection* to client1
    async fn client0_action3(item_container: Arc<RwLock<TestContainer>>, p2p_security_level: SecurityLevel) -> Option<ActionType> {
        AssertSendSafeFuture::spawn(async move {
            let read = item_container.read();
            let cnac = read.cnac_client1.clone().unwrap();
            let client0_cnac = read.cnac_client0.as_ref().unwrap();
            let client0_id = client0_cnac.get_cid();
            let target_cid = cnac.get_cid();
            let requests = read.queued_requests_client0.clone().unwrap();
            let settings = SessionSecuritySettingsBuilder::default().with_security_level(p2p_security_level).with_secrecy_mode(secrecy_mode()).build();
            let post_connect_request = HdpServerRequest::PeerCommand(client0_id, PeerSignal::PostConnect(PeerConnectionType::HyperLANPeerToHyperLANPeer(client0_id, target_cid), None, None, settings, UdpMode::Enabled));

            let mut remote_client0 = read.remote_client0.clone().unwrap();
            std::mem::drop(read);
            let ticket = remote_client0.send(post_connect_request).await.unwrap();
            assert(requests.lock().insert(ticket), "Z12");
        });

        None
    }
}

pub mod utils {
    use std::pin::Pin;

    use futures::Future;
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

        pub fn spawn(fx: impl Future<Output=Out> + 'static) where Out: Send + 'static {
            let task = AssertSendSafeFuture::new_silent(fx);
            tokio::task::spawn(task);
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