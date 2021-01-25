#![feature(async_closure)]

#[cfg(test)]
mod tests {

    use hyxe_user::prelude::HyperNodeAccountInformation;
    use hyxe_user::account_manager::AccountManager;
    use secstr::SecVec;
    use hyxe_fs::hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;
    use hyxe_fs::hyxe_crypt::hyper_ratchet::HyperRatchet;
    use std::net::IpAddr;
    use std::str::FromStr;
    use hyxe_user::client_account::ClientNetworkAccount;
    use hyxe_user::network_account::NetworkAccount;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "info");
        env_logger::init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn load_nac() {
        setup_log();
        let account_manager = acc_mgr().await;
        println!("Loaded NAC: {:?}", account_manager.get_local_nac());
    }

    #[tokio::test]
    async fn test_ratchet_versions() {
        setup_log();
        log::info!("Executing load_cnacs ...");
            let account_manager = acc_mgr().await;
            account_manager.visit_all_users_blocking(|cnac| {
                log::info!("visiting {}", cnac.get_id());
                for version in cnac.get_hyper_ratchet_versions() {
                    cnac.borrow_hyper_ratchet(Some(version), |hyper_ratchet_opt| {
                        let hyper_ratchet = hyper_ratchet_opt.unwrap();
                        log::info!("Borrowing drill vers: {}", hyper_ratchet.version());
                        assert_eq!(version, hyper_ratchet.version());
                    });
                }

                cnac.blocking_save_to_local_fs().unwrap();
            });
    }

    #[tokio::test]
    async fn delete_cnac_by_username() {
        setup_log();
        let args: Vec<String> = std::env::args().collect();
        let username = args.last().unwrap().clone();

        log::info!("Deleting username: {}", &username);
        let account_manager = acc_mgr().await;
        if !account_manager.delete_client_by_username(&username) {
            log::error!("Unable to delete user {} from the internal system. Now syncing files ...", username)
        } else {
            log::info!("Deleted the user {} from the internal system. Now syncing files ...", username);
        }

        account_manager.async_save_to_local_fs().await.unwrap()
    }

    fn gen(cid: u64, version: u32) -> (HyperRatchet, HyperRatchet) {
        let mut alice = HyperRatchetConstructor::new_alice(None, cid, version, None);
        let bob = HyperRatchetConstructor::new_bob(0, cid, version, alice.stage0_alice()).unwrap();
        alice.stage1_alice(bob.stage0_bob().unwrap()).unwrap();
        (alice.finish().unwrap(), bob.finish().unwrap())
    }

    async fn acc_mgr() -> AccountManager {
        AccountManager::new((IpAddr::from_str("1.2.3.4").unwrap(), 12345).into(), None).await.unwrap()
    }

    #[tokio::test]
    async fn create_cnac_then_ser_deser_then_check_login() {
        setup_log();
        let cid = rand::random::<u64>();
        let (alice, _bob) = gen(cid, 0);
        let acc_manager = acc_mgr().await;
        let local_nac = acc_manager.get_local_nac();


        let username = format!("tbraun96{}", cid);
        let password = SecVec::new("mrmoney10".as_bytes().to_vec());
        let password_hash = "mrmoney10".as_bytes().to_vec();

        let cnac = local_nac.create_client_account(cid, None, username.clone(), password, "Thomas P Braun", password_hash, alice).unwrap();
        cnac.validate_credentials(&username, SecVec::new("mrmoney10".as_bytes().to_vec())).unwrap();
        log::info!("Validation success");
        acc_manager.async_save_to_local_fs().await.unwrap();
        std::mem::drop((acc_manager, cnac));
        let acc_manager = acc_mgr().await;
        let cnac = acc_manager.get_client_by_cid(cid).unwrap();
        cnac.validate_credentials(&username, SecVec::new("mrmoney10".as_bytes().to_vec())).unwrap();
    }

    #[tokio::test]
    async fn create_cnac() {
        setup_log();
        //let args: Vec<String> = std::env::args().collect();
        //let username = args.last().unwrap().clone();
        let account_manager = acc_mgr().await;
        let node_nac = account_manager.get_local_nac();
        let possible_cid = node_nac.generate_possible_cids()[0];

        let username = format!("tbraun96{}", possible_cid);
        let password = SecVec::new("mrmoney10".as_bytes().to_vec());
        let password_hash = "mrmoney10".as_bytes().to_vec();

        let (alice, _bob) = gen(possible_cid,0);

        log::info!("Loaded NAC with NID {}", node_nac.get_id());
        // nac_other: Option<NetworkAccount>, username: T, password: SecVec<u8>, full_name: V, post_quantum_container: &PostQuantumContainer, toolset_bytes: Option<K>
        let cnac = node_nac.create_client_account(possible_cid, None, username, password, "Thomas P Braun", password_hash,alice).unwrap();
        log::info!("CNAC successfully constructed | {:?}", &cnac);
        let (alice_1, _bob_1) = gen(possible_cid,1);
        cnac.register_new_hyper_ratchet(alice_1).unwrap();

        let range = cnac.get_hyper_ratchet_versions();
        log::info!("Range: {:?}", &range);

        for version in range {
            cnac.borrow_hyper_ratchet(Some(version), |hyper_ratchet_opt| {
                let hyper_ratchet = hyper_ratchet_opt.unwrap();
                log::info!("Borrowing hyper ratchet vers: {}. Expects: {}", hyper_ratchet.version(), version);
                debug_assert_eq!(version, hyper_ratchet.version());
            });
        }

        const CREATE_COUNT: usize = 6;
        for vers in 2..(2+CREATE_COUNT) {
            let (alice_n, _) = gen(possible_cid,vers as u32);
            cnac.register_new_hyper_ratchet(alice_n).unwrap();
        }

        let range = cnac.get_hyper_ratchet_versions();

        for version in range {
            cnac.borrow_hyper_ratchet(Some(version), |hyper_ratchet_opt| {
                let hyper_ratchet = hyper_ratchet_opt.unwrap();
                log::info!("Borrowing hyper ratchet vers: {}. Expects: {}", hyper_ratchet.version(), version);
                debug_assert_eq!(version, hyper_ratchet.version());
            });
        }

        cnac.async_save_to_local_fs().await.unwrap();
    }


    #[tokio::test]
    async fn encrypt_decrypt_from_cnac() {
        setup_log();
        let account_manager = acc_mgr().await;
        account_manager.visit_all_users_blocking(|cnac| {
            log::info!("Visiting user: {:?}", cnac);
            let versions = cnac.get_hyper_ratchet_versions();
            for version in versions {
                let ratchet = cnac.get_hyper_ratchet(Some(version)).unwrap();
                assert_eq!(ratchet.version(), version);
                let plaintext = Vec::from("Hello, world!");
                let ciphertext = ratchet.encrypt(&plaintext).unwrap();
                assert_ne!(plaintext, ciphertext);
                let decrypted = ratchet.decrypt(ciphertext).unwrap();
                assert_eq!(decrypted, plaintext);
            }
        });
    }

    #[tokio::test]
    async fn delete_all_users() {
        setup_log();
        let account_manager = acc_mgr().await;
        let account_count = account_manager.get_registered_local_cids().unwrap_or_default().len();
        assert!(account_manager.async_save_to_local_fs().await.is_ok());
        assert_eq!(account_count, account_manager.purge());
    }

    #[tokio::test]
    async fn hyperlan_peer_adding() {
        let _account_manager = acc_mgr().await;
        let nac = NetworkAccount::default();
        let cid0 = 10;
        let username0 = "thomas0";

        let cid1 = 11;
        let username1 = "thomas1";

        let hr0 = gen(cid0, 0);
        let hr1 = gen(cid1, 0);
        let cnac0 = ClientNetworkAccount::new(cid0, true, nac.clone(), username0, SecVec::new(Vec::new()), "Thomas Braun", Vec::new(), hr0.0).unwrap();
        let _cnac1 = ClientNetworkAccount::new(cid1, true, nac, username1, SecVec::new(Vec::new()), "Thomas Braun II", Vec::new(), hr1.0).unwrap();
        cnac0.insert_hyperlan_peer(cid1, username1);
        assert!(cnac0.hyperlan_peer_exists(cid1));
        assert!(cnac0.hyperlan_peer_exists_by_username(username1));

        cnac0.remove_hyperlan_peer(cid1).unwrap();

        assert!(!cnac0.hyperlan_peer_exists(cid1));
        assert!(!cnac0.hyperlan_peer_exists_by_username(username1));

        cnac0.insert_hyperlan_peer(cid1, username1);
        assert!(cnac0.hyperlan_peer_exists(cid1));
        assert!(cnac0.hyperlan_peer_exists_by_username(username1));

        cnac0.remove_hyperlan_peer_by_username(username1).unwrap();
        assert!(!cnac0.hyperlan_peer_exists(cid1));
        assert!(!cnac0.hyperlan_peer_exists_by_username(username1));

    }
}