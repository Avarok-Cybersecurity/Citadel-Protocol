#[cfg(test)]
mod tests {
    use lusna_sdk::prelude::*;
    use std::net::{SocketAddr, IpAddr};
    use std::str::FromStr;
    use hyxe_net::test_common::base_kernel::generate_endpoint_test_kernels;
    use hyxe_net::test_common::TestingCoKernel;
    use tokio::sync::mpsc::UnboundedSender;
    use crate::deadlock_detection::deadlock_detector;
    use std::sync::atomic::{AtomicBool, Ordering};

    const BACKEND_TYPE: BackendType = BackendType::Filesystem;
    const UNDERLYING_PROTO: UnderlyingProtocol = UnderlyingProtocol::Tcp;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        //std::env::set_var("RUST_LOG", "error");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    async fn generate_endpoints<K: NetKernel, K2: NetKernel>(k0: K, k1: K2) -> (KernelExecutor<K>, KernelExecutor<K2>) {
        let handle = tokio::runtime::Handle::current();
        let (server_bind_addr, server_account_manager) = generate_endpoint_context().await;
        let (_client_bind_addr, client_account_manager) = generate_endpoint_context().await;

        let server_kernel = KernelExecutor::new(handle.clone(), NodeType::Server(server_bind_addr), server_account_manager, k0, UNDERLYING_PROTO).await.unwrap();
        let client_kernel = KernelExecutor::new(handle, NodeType::Peer, client_account_manager, k1, UNDERLYING_PROTO).await.unwrap();
        (server_kernel, client_kernel)
    }

    async fn generate_endpoint_context() -> (SocketAddr, AccountManager) {
        let addr = SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), portpicker::pick_unused_port().unwrap());
        let mut dir = dirs2::home_dir().unwrap();
        dir.push("./tmp");
        dir.push(format!("{}_{}", addr.ip(), addr.port()));
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let acc_mgr = AccountManager::new(addr, Some(dir.into_os_string().into_string().unwrap()), BACKEND_TYPE, None, None, None).await.unwrap();
        (addr, acc_mgr)
    }

    struct ClientRegisterCoKernel;
    struct ServerRegisterCoKernel(Option<NodeRemote>);

    static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);


    #[async_trait]
    impl TestingCoKernel for ClientRegisterCoKernel {
        async fn on_start(&self, mut server_remote: NodeRemote, server_address: Option<SocketAddr>, stop_server_tx: Option<UnboundedSender<()>>) -> Result<(), NetworkError> {
            let server_addr = server_address.unwrap();

            let _register = server_remote.register_with_defaults(server_addr, "Thomas P Braun", "nologik", "mrmoney10").await?;
            CLIENT_SUCCESS.store(true, Ordering::SeqCst);

            stop_server_tx.unwrap().send(()).unwrap();
            server_remote.shutdown().await
        }

        async fn on_server_message_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
            log::info!("Receiving message on client: {:?}", message);
            Ok(())
        }

        async fn on_stop(self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    #[async_trait]
    impl TestingCoKernel for ServerRegisterCoKernel {
        async fn on_start(&self, _server_remote: NodeRemote, _server_address: Option<SocketAddr>, _stop_server_tx: Option<UnboundedSender<()>>) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn on_server_message_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
            log::info!("Server received message: {:?}", &message);
            Ok(())
        }

        async fn on_stop(self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn main() {
        setup_log();
        deadlock_detector();

        let (server_kernel, client_kernel) = generate_endpoint_test_kernels(ServerRegisterCoKernel(None), ClientRegisterCoKernel {});
        let (server, client) = generate_endpoints(server_kernel, client_kernel).await;
        let (ac0, ac1) = (server.account_manager().clone(), client.account_manager().clone());

        let (_, _) = tokio::try_join!(server.execute(), client.execute()).unwrap();
        ac0.purge_home_directory().await.unwrap();
        ac1.purge_home_directory().await.unwrap();

        assert!(CLIENT_SUCCESS.load(Ordering::SeqCst));
    }
}

mod deadlock_detection {
    pub fn deadlock_detector() {
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