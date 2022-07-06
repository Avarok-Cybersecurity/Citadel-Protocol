#[cfg(test)]
mod tests {

    use hyxe_user::account_manager::AccountManager;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use std::str::FromStr;
    use hyxe_user::client_account::ClientNetworkAccount;
    use hyxe_crypt::stacked_ratchet::constructor::{BobToAliceTransferType, StackedRatchetConstructor};
    use hyxe_user::backend::{BackendType, PersistenceHandler};
    use hyxe_crypt::prelude::{SecBuffer, ConstructorOpts};
    use ez_pqcrypto::algorithm_dictionary::KemAlgorithm;
    use tokio::sync::Mutex;
    use hyxe_user::auth::proposed_credentials::ProposedCredentials;
    use futures::Future;
    
    use hyxe_user::misc::{AccountError, CNACMetadata};
    use hyxe_user::prelude::{MutualPeer, ConnectionInfo};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use ez_pqcrypto::prelude::algorithm_dictionary::EncryptionAlgorithm;

    static TEST_MUTEX: Mutex<()> = Mutex::const_new(());

    #[derive(Clone)]
    struct TestContainer {
        server_acc_mgr: AccountManager,
        client_acc_mgr: AccountManager
    }

    impl TestContainer {
        pub async fn new(server_backend: BackendType, client_backend: BackendType) -> Self {
            let server_acc_mgr = acc_mgr(server_backend).await;
            let client_acc_mgr = acc_mgr(client_backend).await;

            Self {
                server_acc_mgr,
                client_acc_mgr
            }
        }

        pub async fn create_cnac(&self, username: &str, password: &str, full_name: &str) -> (ClientNetworkAccount, ClientNetworkAccount) {
            let conn_info = ConnectionInfo { addr: SocketAddr::from_str("127.0.0.1:12345").unwrap() };
            let cid = self.server_acc_mgr.get_persistence_handler().get_cid_by_username(username);
            let (client_hr, server_hr) = gen(cid, 0, None);
            let server_vers = self.server_acc_mgr.register_impersonal_hyperlan_client_network_account(conn_info.clone(), ProposedCredentials::new_register(full_name, username, SecBuffer::from(password)).await.unwrap(), server_hr).await.unwrap();
            let client_vers = self.client_acc_mgr.register_personal_hyperlan_server(client_hr, ProposedCredentials::new_register(full_name, username, SecBuffer::from(password)).await.unwrap(), conn_info).await.unwrap();

            (client_vers, server_vers)
        }

        pub async fn create_peer_cnac(&self, username: &str, password: &str, full_name: &str, peer_backend: BackendType) -> (ClientNetworkAccount, TestContainer) {
            // we assume same server node
            let conn_info = ConnectionInfo { addr: SocketAddr::from_str("127.0.0.1:54321").unwrap() };
            let server_acc_mgr = self.server_acc_mgr.clone();
            let client_acc_mgr = acc_mgr(peer_backend).await;

            let cid = self.server_acc_mgr.get_persistence_handler().get_cid_by_username(username);
            let (client_hr, server_hr) = gen(cid, 0, None);

            let _server_vers = self.server_acc_mgr.register_impersonal_hyperlan_client_network_account(conn_info.clone(), ProposedCredentials::new_register(full_name, username, SecBuffer::from(password)).await.unwrap(), server_hr).await.unwrap();
            let client_vers = client_acc_mgr.register_personal_hyperlan_server(client_hr, ProposedCredentials::new_register(full_name, username, SecBuffer::from(password)).await.unwrap(), conn_info).await.unwrap();
            let client_test_container = TestContainer {
                server_acc_mgr,
                client_acc_mgr
            };

            (client_vers, client_test_container)
        }

        async fn purge(&self) {
            self.server_acc_mgr.purge().await.unwrap();
            self.client_acc_mgr.purge().await.unwrap();
        }
    }

    fn generate_random_filesystem_dir() -> BackendType {
        let mut home = dirs2::home_dir().unwrap();
        let rand = uuid::Uuid::new_v4().to_string();
        home.push(format!("tmp/{}/", rand));

        if home.exists() {
            return generate_random_filesystem_dir()
        }

        BackendType::new(format!("file:{}", home.display())).unwrap()
    }

    #[cfg(any(feature = "sql", feature = "redis", feature = "filesystem"))]
    fn get_possible_backends(env: &str, ty: &str) -> Vec<BackendType> {
        let mut backends = vec![BackendType::InMemory, generate_random_filesystem_dir()];

        match std::env::var(&env) {
            Ok(addr) => {
                for addr in  addr.split(',') {
                    log::trace!(target: "lusna", "Adding testing addr: {}", addr);
                    let backend = BackendType::new(addr).unwrap();
                    backends.push(backend);
                }
            }
            _ => {
                if std::env::var("SKIP_EXT_BACKENDS").is_err() {
                    log::error!(target: "lusna", "Make sure {} is set in the environment", env);
                    std::process::exit(1)
                }
            }
        }

        log::info!(target: "lusna", "Backends generated for {}: {:?}", ty, backends);

        backends
    }

    #[cfg(not(any(feature = "sql", feature = "redis", feature = "filesystem")))]
    fn get_possible_backends(_env: &str, _ty: &str) -> Vec<BackendType> {
        vec![BackendType::InMemory]
    }

    fn client_backends() -> Vec<BackendType> {
        get_possible_backends("TESTING_SQL_SERVER_ADDR_CLIENT", "Client")
    }

    fn server_backends() -> Vec<BackendType> {
        get_possible_backends("TESTING_SQL_SERVER_ADDR_SERVER", "Server")
    }

    async fn test_harness<T, F>(mut t: T) -> Result<(), AccountError>
        where T: Send + 'static + FnMut(TestContainer, PersistenceHandler, PersistenceHandler) -> F,
        F: Future<Output=Result<(), AccountError>> + Send + 'static {
        lusna_logging::setup_log();
        let _lock = TEST_MUTEX.lock().await;

        let client_backends = client_backends();
        let server_backends = server_backends();


        async fn harness_inner<T, F>(client_backend: &BackendType, server_backend: &BackendType, t: &mut T) -> Result<(), AccountError>
            where T: Send + 'static + FnMut(TestContainer, PersistenceHandler, PersistenceHandler) -> F,
                  F: Future<Output=Result<(), AccountError>> + Send + 'static {
            log::info!(target: "lusna", "Trying combination: client={:?} w/ server={:?}", client_backend, server_backend);
            let container = TestContainer::new(server_backend.clone(), client_backend.clone()).await;
            let (pers_cl, pers_se) = (container.client_acc_mgr.get_persistence_handler().clone(), container.server_acc_mgr.get_persistence_handler().clone());
            log::trace!(target: "lusna", "About to execute test on thread ...");
            let res = tokio::task::spawn((t)(container.clone(), pers_cl, pers_se)).await.map_err(|err| AccountError::Generic(err.to_string()));
            log::info!(target: "lusna", "About to clear test container ...");
            if res.is_err() {
                log::error!(target: "lusna", "Task failed! {:?}", res);
            }

            container.purge().await;
            res?
        }

        for client_backend in &client_backends {
            harness_inner(client_backend, &BackendType::InMemory, &mut t).await?
        }

        for server_backend in &server_backends {
            harness_inner(&BackendType::InMemory, server_backend, &mut t).await?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_setup_account_managers() -> Result<(), AccountError> {
        test_harness(|_, _, _| async move { Ok(()) }).await
    }

    const USERNAME: &str = "nologik";
    const PASSWORD: &str = "password";
    const FULL_NAME: &str = "Sir John Doe";

    lazy_static::lazy_static! {
        pub static ref PEERS: Vec<(String, String, String)> = {
            ["alpha", "beta", "charlie", "echo", "delta", "epsilon", "foxtrot"]
            .iter().map(|base| (format!("{}.username", base), format!("{}.password", base), format!("{}.full_name", base)))
            .collect()
        };
    }

    #[tokio::test]
    // test to make sure persistence works between Account manager loads
    async fn test_interload_persistence() -> Result<(), AccountError> {
        lazy_static::lazy_static! {
            static ref CL_BACKENDS: parking_lot::Mutex<Vec<BackendType>> = parking_lot::Mutex::new(vec![]);
            static ref SE_BACKENDS: parking_lot::Mutex<Vec<BackendType>> = parking_lot::Mutex::new(vec![]);
        }

        let client_backends = &client_backends();
        let server_backends = &server_backends();

        let mut containers = vec![];

        for server_backend in server_backends {
            // in memory does not persist, so skip them in this specific test
            if !matches!(server_backend, BackendType::InMemory) {
                let cont0 = TestContainer::new(server_backend.clone(), BackendType::InMemory).await;
                for (username, password, full_name) in PEERS.iter() {
                    let _ = cont0.create_cnac(username, password, full_name).await;
                }

                assert_eq!(cont0.client_acc_mgr.get_persistence_handler().get_clients_metadata(None).await.unwrap().len(), PEERS.len());
                assert_eq!(cont0.server_acc_mgr.get_persistence_handler().get_clients_metadata(None).await.unwrap().len(), PEERS.len());

                let cont_reloaded = TestContainer::new(server_backend.clone(), BackendType::InMemory).await;
                assert_eq!(cont_reloaded.client_acc_mgr.get_persistence_handler().get_clients_metadata(None).await.unwrap().len(), 0); // since in-memory does not persist
                assert_eq!(cont_reloaded.server_acc_mgr.get_persistence_handler().get_clients_metadata(None).await.unwrap().len(), PEERS.len());
                containers.push(cont0);
            }
        }

        for container in &containers {
            container.purge().await;
        }

        containers.clear();

        for client_backend in client_backends {
            // in memory does not persist, so skip them in this specific test
            if !matches!(client_backend, BackendType::InMemory) {
                let cont0 = TestContainer::new(BackendType::InMemory, client_backend.clone()).await;
                for (username, password, full_name) in PEERS.iter() {
                    let _ = cont0.create_cnac(username, password, full_name).await;
                }

                assert_eq!(cont0.client_acc_mgr.get_persistence_handler().get_clients_metadata(None).await.unwrap().len(), PEERS.len());
                assert_eq!(cont0.server_acc_mgr.get_persistence_handler().get_clients_metadata(None).await.unwrap().len(), PEERS.len());

                let cont_reloaded = TestContainer::new(BackendType::InMemory, client_backend.clone()).await;
                assert_eq!(cont_reloaded.client_acc_mgr.get_persistence_handler().get_clients_metadata(None).await.unwrap().len(), PEERS.len());
                assert_eq!(cont_reloaded.server_acc_mgr.get_persistence_handler().get_clients_metadata(None).await.unwrap().len(), 0); // since in-memory does not persist
                containers.push(cont0);
            }
        }

        for container in &containers {
            container.purge().await;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_cnac_creation() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            assert!(pers_cl.cid_is_registered(client.get_cid()).await.unwrap());
            assert!(pers_se.cid_is_registered(client.get_cid()).await.unwrap());

            assert_eq!(pers_cl.get_client_metadata(client.get_cid()).await.unwrap().unwrap(), CNACMetadata {
                cid: client.get_cid(),
                username: USERNAME.to_string(),
                full_name: FULL_NAME.to_string(),
                is_personal: true, // true from the perspective of client pers
                creation_date: "".to_string()
            });

            assert_eq!(pers_se.get_client_metadata(client.get_cid()).await.unwrap().unwrap(), CNACMetadata {
                cid: client.get_cid(),
                username: USERNAME.to_string(),
                full_name: FULL_NAME.to_string(),
                is_personal: false, // false from the perspective of server pers
                creation_date: "".to_string()
            });

            assert_eq!(pers_cl.get_clients_metadata(None).await.unwrap(), vec![CNACMetadata {
                cid: client.get_cid(),
                username: USERNAME.to_string(),
                full_name: FULL_NAME.to_string(),
                is_personal: true, // true from the perspective of client pers
                creation_date: "".to_string()
            }]);

            assert_eq!(pers_se.get_clients_metadata(None).await.unwrap(), vec![CNACMetadata {
                cid: client.get_cid(),
                username: USERNAME.to_string(),
                full_name: FULL_NAME.to_string(),
                is_personal: false, // false from the perspective of server pers
                creation_date: "".to_string()
            }]);

            let lock_server = server.write();
            let lock_client = client.write();

            assert_eq!(lock_server.is_local_personal, false);
            assert_eq!(lock_client.is_local_personal, true);
            assert_eq!(lock_client.auth_store.username(), USERNAME);
            assert_eq!(lock_server.auth_store.username(), USERNAME);
            assert_eq!(lock_client.auth_store.full_name(), FULL_NAME);
            assert_eq!(lock_server.auth_store.full_name(), FULL_NAME);
            assert_eq!(lock_server.cid, lock_server.cid);

            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_byte_map() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            let dummy = Vec::from("Hello, world!");
            let dummy2 = Vec::from("Hello, world!");

            assert!(pers_cl.store_byte_map_value(client.get_cid(), 1234, "thekey", "sub_key", dummy.clone()).await.unwrap().is_none());
            assert_eq!(pers_cl.get_byte_map_value(client.get_cid(), 1234, "thekey", "sub_key").await.unwrap().unwrap(), dummy.clone());
            assert_eq!(pers_cl.get_byte_map_values_by_key(client.get_cid(), 1234, "thekey").await.unwrap().remove("sub_key").unwrap(), dummy.clone());
            assert_eq!(pers_cl.remove_byte_map_value(client.get_cid(), 1234, "thekey", "sub_key").await.unwrap().unwrap(), dummy.clone());
            assert!(pers_cl.remove_byte_map_value(client.get_cid(), 1234, "thekey", "sub_key").await.unwrap().is_none());

            assert!(pers_se.store_byte_map_value(server.get_cid(), 1234, "helloworld", "sub_key", dummy2.clone()).await.unwrap().is_none());
            assert_eq!(pers_se.store_byte_map_value(server.get_cid(), 1234, "helloworld", "sub_key", dummy.clone()).await.unwrap().unwrap(), dummy2.clone());
            assert_eq!(pers_se.get_byte_map_value(server.get_cid(), 1234, "helloworld","sub_key").await.unwrap().unwrap(), dummy.clone());
            assert_eq!(pers_se.get_byte_map_values_by_key(server.get_cid(), 1234, "helloworld").await.unwrap().remove("sub_key").unwrap(), dummy.clone());
            assert_eq!(pers_se.remove_byte_map_value(server.get_cid(), 1234, "helloworld", "sub_key").await.unwrap().unwrap(), dummy.clone());
            assert!(pers_se.remove_byte_map_value(server.get_cid(), 1234, "helloworld", "sub_key").await.unwrap().is_none());
            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_byte_map2() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, _pers_se| async move {
            let (client, _server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            let dummy = Vec::from("Hello, world!");
            assert!(pers_cl.store_byte_map_value(client.get_cid(), 1234, "thekey", "sub_key1", dummy.clone()).await.unwrap().is_none());
            assert!(pers_cl.store_byte_map_value(client.get_cid(), 1234, "thekey", "sub_key2", dummy.clone()).await.unwrap().is_none());
            assert!(pers_cl.store_byte_map_value(client.get_cid(), 1234, "thekey", "sub_key3", dummy.clone()).await.unwrap().is_none());
            assert!(pers_cl.store_byte_map_value(client.get_cid(), 1234, "unrelated", "sub_key4", dummy.clone()).await.unwrap().is_none());

            let map = pers_cl.get_byte_map_values_by_key(client.get_cid(), 1234, "thekey").await.unwrap();
            assert!(map.contains_key("sub_key1"));
            assert!(map.contains_key("sub_key2"));
            assert!(map.contains_key("sub_key3"));
            assert_eq!(map.len(), 3);

            for val in map.values() {
                assert_eq!(val.as_slice(), dummy.as_slice());
            }

            let del_map = pers_cl.remove_byte_map_values_by_key(client.get_cid(), 1234, "thekey").await.unwrap();
            assert_eq!(del_map, map);

            assert_eq!(pers_cl.get_byte_map_value(client.get_cid(), 1234, "unrelated", "sub_key4").await.unwrap().unwrap(), dummy.clone());
            let del_map2 = pers_cl.remove_byte_map_values_by_key(client.get_cid(), 1234, "thekey").await.unwrap();
            assert_eq!(del_map2, HashMap::new());

            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_cnac_meta() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            let cl2 = pers_cl.get_client_by_username(USERNAME).await?.unwrap();
            let se2 = pers_se.get_client_by_username(USERNAME).await?.unwrap();

            assert_eq!(client.get_cid(), cl2.get_cid());
            assert_eq!(server.get_cid(), se2.get_cid());

            assert_eq!(pers_se.get_username_by_cid(client.get_cid()).await.unwrap().unwrap(), USERNAME);
            assert_eq!(pers_cl.get_username_by_cid(client.get_cid()).await.unwrap().unwrap(), USERNAME);

            assert_eq!(pers_se.get_cid_by_username(USERNAME), client.get_cid());
            assert_eq!(pers_cl.get_cid_by_username(USERNAME), client.get_cid());

            let lock_server = se2.write();
            let lock_client = cl2.write();

            assert_eq!(lock_server.is_local_personal, false);
            assert_eq!(lock_client.is_local_personal, true);
            assert_eq!(lock_client.auth_store.username(), USERNAME);
            assert_eq!(lock_server.auth_store.username(), USERNAME);
            assert_eq!(lock_client.auth_store.full_name(), FULL_NAME);
            assert_eq!(lock_server.auth_store.full_name(), FULL_NAME);
            assert_eq!(lock_server.cid, lock_server.cid);
            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_delete_cnac_by_cid() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            pers_cl.delete_cnac_by_cid(client.get_cid()).await?;
            pers_se.delete_cnac_by_cid(server.get_cid()).await?;

            assert!(pers_cl.get_cnac_by_cid(client.get_cid()).await?.is_none());
            assert!(pers_se.get_cnac_by_cid(server.get_cid()).await?.is_none());

            assert!(pers_cl.get_client_by_username(USERNAME).await?.is_none());
            assert!(pers_se.get_client_by_username(USERNAME).await?.is_none());

            assert!(pers_se.get_registered_impersonal_cids(None).await?.is_none());
            assert!(pers_se.get_client_metadata(client.get_cid()).await.unwrap().is_none());
            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_register_p2p() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, _server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            let peer = PEERS.get(0).unwrap();
            let (peer_cnac, peer_container) = container.create_peer_cnac(peer.0.as_str(), peer.1.as_str(), peer.2.as_str(), BackendType::InMemory).await;
            let peer_pers = &peer_container.client_acc_mgr.get_persistence_handler().clone();
            register_peers(&pers_cl,
                           client.get_cid(),
                           USERNAME,
                           peer_pers,
            peer_cnac.get_cid(),
                peer.0.as_str(),
                &pers_se
            ).await;

            assert_eq!(pers_cl.get_hyperlan_peer_list(client.get_cid()).await.unwrap().unwrap(), vec![peer_cnac.get_cid()]);
            assert_eq!(peer_pers.get_hyperlan_peer_list(peer_cnac.get_cid()).await.unwrap().unwrap(), vec![client.get_cid()]);

            assert_eq!(peer_pers.get_hyperlan_peer_by_cid(peer_cnac.get_cid(), client.get_cid()).await.unwrap().unwrap(), MutualPeer {
                parent_icid: 0,
                cid: client.get_cid(),
                username: Some(USERNAME.to_string())
            });

            assert_eq!(pers_cl.get_hyperlan_peer_by_cid(client.get_cid(), peer_cnac.get_cid()).await.unwrap().unwrap(), MutualPeer {
                parent_icid: 0,
                cid: peer_cnac.get_cid(),
                username: Some(peer.0.to_string())
            });

            assert_eq!(pers_se.get_hyperlan_peer_by_cid(client.get_cid(), peer_cnac.get_cid()).await.unwrap().unwrap(), MutualPeer {
                parent_icid: 0,
                cid: peer_cnac.get_cid(),
                username: Some(peer.0.to_string())
            });

            assert_eq!(pers_se.get_hyperlan_peer_by_cid(peer_cnac.get_cid(), client.get_cid()).await.unwrap().unwrap(), MutualPeer {
                parent_icid: 0,
                cid: client.get_cid(),
                username: Some(USERNAME.to_string())
            });

            assert_eq!(pers_cl.get_hyperlan_peers(client.get_cid(), &vec![peer_cnac.get_cid()]).await.unwrap(), vec![MutualPeer{
                parent_icid: 0,
                cid: peer_cnac.get_cid(),
                username: Some(peer.0.to_string())
            }]);

            assert_eq!(peer_pers.get_hyperlan_peers(peer_cnac.get_cid(), &vec![client.get_cid()]).await.unwrap(), vec![MutualPeer{
                parent_icid: 0,
                cid: client.get_cid(),
                username: Some(USERNAME.to_string())
            }]);

            assert_eq!(pers_cl.get_hyperlan_peers(client.get_cid(), &vec![peer_cnac.get_cid()]).await.unwrap(), vec![MutualPeer{
                parent_icid: 0,
                cid: peer_cnac.get_cid(),
                username: Some(peer.0.to_string())
            }]);

            assert_eq!(peer_pers.hyperlan_peers_are_mutuals(peer_cnac.get_cid(), &vec![client.get_cid()]).await.unwrap(), vec![true]);
            assert_eq!(pers_cl.hyperlan_peers_are_mutuals(client.get_cid(), &vec![peer_cnac.get_cid()]).await.unwrap(), vec![true]);
            assert_eq!(pers_se.hyperlan_peers_are_mutuals(peer_cnac.get_cid(), &vec![client.get_cid()]).await.unwrap(), vec![true]);
            assert_eq!(pers_se.hyperlan_peers_are_mutuals(client.get_cid(), &vec![peer_cnac.get_cid()]).await.unwrap(), vec![true]);

            assert!(peer_pers.hyperlan_peer_exists(peer_cnac.get_cid(), client.get_cid()).await.unwrap());
            assert!(pers_cl.hyperlan_peer_exists(client.get_cid(), peer_cnac.get_cid()).await.unwrap());
            assert!(pers_se.hyperlan_peer_exists(peer_cnac.get_cid(), client.get_cid()).await.unwrap());
            assert!(pers_se.hyperlan_peer_exists(client.get_cid(), peer_cnac.get_cid()).await.unwrap());

            peer_container.client_acc_mgr.purge().await?;
            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_deregister_p2p() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, _server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            let peer = PEERS.get(0).unwrap();
            let (peer_cnac, peer_container) = container.create_peer_cnac(peer.0.as_str(), peer.1.as_str(), peer.2.as_str(), BackendType::InMemory).await;
            let peer_pers = &peer_container.client_acc_mgr.get_persistence_handler().clone();
            register_peers(&pers_cl,
                           client.get_cid(),
                           USERNAME,
                           peer_pers,
                           peer_cnac.get_cid(),
                           peer.0.as_str(),
                           &pers_se
            ).await;

            let server_seen_peers = pers_se.get_hyperlan_peer_list_as_server(client.get_cid()).await.unwrap().unwrap();
            assert_eq!(server_seen_peers, vec![
                MutualPeer {
                    parent_icid: 0,
                    cid: peer_cnac.get_cid(),
                    username: Some(peer.0.to_string())
                }
            ]);

            // TODO: Change the below function
            let _ = pers_cl.synchronize_hyperlan_peer_list_as_client(&client, server_seen_peers).await.unwrap();
            assert_eq!(pers_cl.get_hyperlan_peer_list(client.get_cid()).await.unwrap().unwrap(), vec![peer_cnac.get_cid()]);

            deregister_peers(&pers_cl,
                           client.get_cid(),
                           peer_pers,
                           peer_cnac.get_cid(),
                           &pers_se
            ).await;

            assert!(peer_pers.get_hyperlan_peer_by_cid(peer_cnac.get_cid(), client.get_cid()).await.unwrap().is_none());
            assert!(pers_cl.get_hyperlan_peer_by_cid(client.get_cid(), peer_cnac.get_cid()).await.unwrap().is_none());
            assert!(pers_se.get_hyperlan_peer_by_cid(peer_cnac.get_cid(), client.get_cid()).await.unwrap().is_none());
            assert!(pers_se.get_hyperlan_peer_by_cid(client.get_cid(), peer_cnac.get_cid()).await.unwrap().is_none());

            assert!(peer_pers.get_hyperlan_peer_by_username(peer_cnac.get_cid(), USERNAME).await.unwrap().is_none());
            assert!(pers_cl.get_hyperlan_peer_by_username(client.get_cid(), peer.0.as_str()).await.unwrap().is_none());
            assert!(pers_se.get_hyperlan_peer_by_username(peer_cnac.get_cid(), USERNAME).await.unwrap().is_none());
            assert!(pers_se.get_hyperlan_peer_by_username(client.get_cid(), peer.0.as_str()).await.unwrap().is_none());

            peer_container.client_acc_mgr.purge().await?;
            Ok(())
        }).await
    }

    /*
    #[tokio::test]
    async fn test_synchronize_p2p_list() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, _server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;

        }).await
    }*/

    #[tokio::test]
    async fn test_deregister_client_from_server() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, _server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            let peer = PEERS.get(0).unwrap();
            let (peer_cnac, peer_container) = container.create_peer_cnac(peer.0.as_str(), peer.1.as_str(), peer.2.as_str(), BackendType::InMemory).await;
            let peer_pers = &peer_container.client_acc_mgr.get_persistence_handler().clone();
            register_peers(&pers_cl,
                           client.get_cid(),
                           USERNAME,
                           peer_pers,
                           peer_cnac.get_cid(),
                           peer.1.as_str(),
                           &pers_se
            ).await;

            deregister_client_from_server(&pers_cl, client.get_cid(), &pers_se).await;

            assert!(pers_cl.get_cnac_by_cid(client.get_cid()).await.unwrap().is_none());
            assert!(pers_se.get_cnac_by_cid(client.get_cid()).await.unwrap().is_none());
            assert!(pers_se.get_cnac_by_cid(peer_cnac.get_cid()).await.unwrap().is_some());
            assert!(pers_se.get_hyperlan_peer_by_cid(peer_cnac.get_cid(), client.get_cid()).await.unwrap().is_none());
            assert!(pers_se.get_hyperlan_peer_by_cid(client.get_cid(), peer_cnac.get_cid()).await.unwrap().is_none());

            deregister_client_from_server(peer_pers, peer_cnac.get_cid(), &pers_se).await;

            assert!(!pers_se.username_exists(USERNAME).await.unwrap());
            assert!(!pers_se.username_exists(peer.0.as_str()).await.unwrap());
            assert!(!pers_cl.username_exists(USERNAME).await.unwrap());
            assert!(!peer_pers.username_exists(peer.0.as_str()).await.unwrap());

            peer_container.client_acc_mgr.purge().await?;
            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_register_p2p_many() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, _server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            let mut peer_map = HashMap::new();

            let mut peer_containers = vec![];

            for peer in PEERS.iter() {
                let (peer_cnac, peer_container) = container.create_peer_cnac(peer.0.as_str(), peer.1.as_str(), peer.2.as_str(), BackendType::InMemory).await;
                assert!(peer_map.insert(peer.0.to_string(), peer_cnac.get_cid()).is_none());
                let peer_pers = &peer_container.client_acc_mgr.get_persistence_handler().clone();
                register_peers(&pers_cl,
                               client.get_cid(),
                               USERNAME,
                               peer_pers,
                               peer_cnac.get_cid(),
                               peer.0.as_str(),
                               &pers_se
                ).await;

                assert!(pers_se.username_exists(USERNAME).await.unwrap());
                assert!(pers_se.username_exists(peer.0.as_str()).await.unwrap());
                assert!(pers_cl.username_exists(USERNAME).await.unwrap());
                assert!(peer_pers.username_exists(peer.0.as_str()).await.unwrap());

                assert_eq!(peer_pers.get_hyperlan_peer_by_cid(peer_cnac.get_cid(), client.get_cid()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: client.get_cid(),
                    username: Some(USERNAME.to_string())
                });

                assert_eq!(pers_cl.get_hyperlan_peer_by_cid(client.get_cid(), peer_cnac.get_cid()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: peer_cnac.get_cid(),
                    username: Some(peer.0.to_string())
                });

                assert_eq!(pers_se.get_hyperlan_peer_by_cid(client.get_cid(), peer_cnac.get_cid()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: peer_cnac.get_cid(),
                    username: Some(peer.0.to_string())
                });

                assert_eq!(pers_se.get_hyperlan_peer_by_cid(peer_cnac.get_cid(), client.get_cid()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: client.get_cid(),
                    username: Some(USERNAME.to_string())
                });

                assert_eq!(pers_se.get_hyperlan_peer_by_username(client.get_cid(), peer.0.as_str()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: peer_cnac.get_cid(),
                    username: Some(peer.0.to_string())
                });

                assert_eq!(pers_cl.get_hyperlan_peer_by_username(client.get_cid(), peer.0.as_str()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: peer_cnac.get_cid(),
                    username: Some(peer.0.to_string())
                });

                assert_eq!(pers_se.get_hyperlan_peer_by_username(peer_cnac.get_cid(), USERNAME).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: client.get_cid(),
                    username: Some(USERNAME.to_string())
                });

                assert_eq!(peer_pers.get_hyperlan_peer_by_username(peer_cnac.get_cid(), USERNAME).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: client.get_cid(),
                    username: Some(USERNAME.to_string())
                });

                peer_containers.push(peer_container);
            }

            let list = pers_se.get_hyperlan_peer_list_as_server(client.get_cid()).await.unwrap().unwrap();

            assert_eq!(list.len(), peer_map.len());

            for peer in PEERS.iter() {
                assert!(list.contains(&MutualPeer {
                    parent_icid: 0,
                    cid: peer_map.get(peer.0.as_str()).cloned().unwrap(),
                    username: Some(peer.0.to_string())
                }))
            }

            for peer_container in peer_containers {
                peer_container.client_acc_mgr.purge().await?;
            }

            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_register_p2p_many_list() -> Result<(), AccountError> {
        test_harness(|container, pers_cl, pers_se| async move {
            let (client, _server) = container.create_cnac(USERNAME, PASSWORD, FULL_NAME).await;
            let mut peer_containers = vec![];
            let mut peer_cids = vec![client.get_cid()];

            for peer in PEERS.iter() {
                let (peer_cnac, peer_container) = container.create_peer_cnac(peer.0.as_str(), peer.1.as_str(), peer.2.as_str(), BackendType::InMemory).await;
                let peer_pers = &peer_container.client_acc_mgr.get_persistence_handler().clone();

                peer_cids.push(peer_cnac.get_cid());

                register_peers(&pers_cl,
                               client.get_cid(),
                               USERNAME,
                               peer_pers,
                               peer_cnac.get_cid(),
                               peer.0.as_str(),
                               &pers_se
                ).await;

                assert_eq!(peer_pers.get_hyperlan_peer_by_cid(peer_cnac.get_cid(), client.get_cid()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: client.get_cid(),
                    username: Some(USERNAME.to_string())
                });

                assert_eq!(pers_cl.get_hyperlan_peer_by_cid(client.get_cid(), peer_cnac.get_cid()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: peer_cnac.get_cid(),
                    username: Some(peer.0.to_string())
                });

                assert_eq!(pers_se.get_hyperlan_peer_by_cid(client.get_cid(), peer_cnac.get_cid()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: peer_cnac.get_cid(),
                    username: Some(peer.0.to_string())
                });

                assert_eq!(pers_se.get_hyperlan_peer_by_cid(peer_cnac.get_cid(), client.get_cid()).await.unwrap().unwrap(), MutualPeer {
                    parent_icid: 0,
                    cid: client.get_cid(),
                    username: Some(USERNAME.to_string())
                });

                peer_containers.push(peer_container);
            }

            let client_peers = pers_cl.get_hyperlan_peer_list(client.get_cid()).await.unwrap().unwrap();
            assert_eq!(client_peers.len(), PEERS.len());
            let impersonals = pers_se.get_registered_impersonal_cids(None).await.unwrap().unwrap();
            assert_eq!(impersonals.len(), peer_cids.len());
            for cid in peer_cids {
                assert!(impersonals.contains(&cid));
            }

            for peer_container in peer_containers {
                peer_container.client_acc_mgr.purge().await?;
            }

            Ok(())
        }).await
    }

    async fn register_peers(peer0_pers: &PersistenceHandler, peer0_cid: u64, peer0_username: &str, peer1_pers: &PersistenceHandler, peer1_cid: u64, peer1_username: &str, server_pers: &PersistenceHandler) {
        peer0_pers.register_p2p_as_client(peer0_cid, peer1_cid, peer1_username.to_string()).await.unwrap();
        peer1_pers.register_p2p_as_client(peer1_cid, peer0_cid, peer0_username.to_string()).await.unwrap();
        server_pers.register_p2p_as_server(peer0_cid, peer1_cid).await.unwrap();
    }

    async fn deregister_peers(peer0_pers: &PersistenceHandler, peer0_cid: u64, peer1_pers: &PersistenceHandler, peer1_cid: u64, server_pers: &PersistenceHandler) {
        peer0_pers.deregister_p2p_as_client(peer0_cid, peer1_cid).await.unwrap();
        peer1_pers.deregister_p2p_as_client(peer1_cid, peer0_cid).await.unwrap();
        server_pers.deregister_p2p_as_server(peer0_cid, peer1_cid).await.unwrap();
    }

    async fn deregister_client_from_server(pers_cl: &PersistenceHandler, client_cid: u64, server_pers: &PersistenceHandler) {
        pers_cl.delete_cnac_by_cid(client_cid).await.unwrap();
        server_pers.delete_cnac_by_cid(client_cid).await.unwrap();
    }

    fn gen(cid: u64, version: u32, endpoint_bob_cid: Option<u64>) -> (StackedRatchet, StackedRatchet) {
        let opts = ConstructorOpts::new_vec_init(Some(KemAlgorithm::Lightsaber + EncryptionAlgorithm::AES_GCM_256_SIV), 1);
        let mut alice = StackedRatchetConstructor::new_alice(opts.clone(), cid, version, None).unwrap();
        let bob = StackedRatchetConstructor::new_bob(cid,version, opts,alice.stage0_alice()).unwrap();
        alice.stage1_alice(&BobToAliceTransferType::Default(bob.stage0_bob().unwrap())).unwrap();
        let bob = if let Some(cid) = endpoint_bob_cid { bob.finish_with_custom_cid(cid).unwrap() } else { bob.finish().unwrap() };
        (alice.finish().unwrap(), bob)
    }

    async fn acc_mgr(backend: BackendType) -> AccountManager {
        AccountManager::new(backend, None, None, None).await.unwrap()
    }
}