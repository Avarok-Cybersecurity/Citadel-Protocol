#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use hyxe_crypt::prelude::PostQuantumContainer;
    use hyxe_crypt::prelude::algorithm_dictionary::{KemAlgorithm, EncryptionAlgorithm};
    use openssl::pkey::{PKey, Private};
    use hyxe_user::misc::AccountError;
    use openssl::hash::MessageDigest;
    use jwt::{PKeyWithDigest, SignWithKey};
    use hyxe_user::account_manager::AccountManager;
    use hyxe_user::client_account::ClientNetworkAccount;
    use hyxe_crypt::argon::argon_container::{ArgonContainerType, ClientArgonContainer, ArgonSettings};
    use hyxe_user::hypernode_account::HyperNodeAccountInformation;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::hyper_ratchet::constructor::{HyperRatchetConstructor, BobToAliceTransferType};
    use ez_pqcrypto::constructor_opts::ConstructorOpts;

    #[allow(unused_must_use)]
    fn setup_log() {
        std::env::set_var("RUST_LOG", "trace");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn jwt() {
        setup_log();
        const USER: u64 = 999;
        const API_KEY: &str = "AIzaSyDtYt9f0c7x3uL7EhALL6isXXD0q_wGBpA";
        let auth = hyxe_user::external_services::google_auth::GoogleAuth::load_from_google_services_file("/Users/nologik/googlesvc.json").await.unwrap();
        let jwt = auth.sign_new_custom_jwt_auth(USER).unwrap();
        log::info!("JWT: {}", jwt);

        let mut firebase_rtdb = firebase_rtdb::FirebaseRTDB::new_from_jwt("https://verisend-d3aec-default-rtdb.firebaseio.com/", jwt, API_KEY).await.unwrap();
        let mut map = HashMap::new();
        map.insert("cid", "777");
        map.insert("name", "A peer");

        let resp = firebase_rtdb.root().await.unwrap().child("users").child(USER.to_string()).child("peers").final_node("777").post(&map).await.unwrap();
        log::info!("RESP: {}", resp);

        firebase_rtdb.renew_token().await.unwrap();

        let resp = firebase_rtdb.root().await.unwrap().child("users").child(USER.to_string()).child("peers").child("second").final_node("777").post(&map).await.unwrap();
        log::info!("RESP: {}", resp);
    }

    fn gen(cid: u64, version: u32, endpoint_bob_cid: Option<u64>, opts: ConstructorOpts) -> (HyperRatchet, HyperRatchet) {
        let mut alice = HyperRatchetConstructor::new_alice(vec![opts.clone()], cid, version, None);
        let bob = HyperRatchetConstructor::new_bob(cid, version, vec![opts.clone()],  alice.stage0_alice()).unwrap();
        alice.stage1_alice(&BobToAliceTransferType::Default(bob.stage0_bob().unwrap())).unwrap();
        let bob = if let Some(cid) = endpoint_bob_cid { bob.finish_with_custom_cid(cid).unwrap() } else { bob.finish().unwrap() };
        (alice.finish().unwrap(), bob)
    }

    #[tokio::test]
    async fn create_cnac_test() {
        let _ = create_cnac(None).await;
    }

    async fn create_cnac(account_mgr: Option<AccountManager>) -> ClientNetworkAccount {
        setup_log();
        //let args: Vec<String> = std::env::args().collect();
        //let username = args.last().unwrap().clone();
        let account_manager = if let Some(acc_mgr) = account_mgr { acc_mgr } else { acc_mgr(None, backend()).await };
        let node_nac = account_manager.get_local_nac();
        let possible_cid = node_nac.client_only_generate_possible_cids().unwrap()[0];

        let username = format!("tbraun96{}", possible_cid);
        let password = SecBuffer::from("mrmoney10".as_bytes().to_vec());
        let password_hash = "mrmoney10".as_bytes().to_vec();

        let (alice, _bob) = gen(possible_cid,0, None);

        log::info!("Loaded NAC with NID {}", node_nac.get_id());
        // nac_other: Option<NetworkAccount>, username: T, password: SecVec<u8>, full_name: V, post_quantum_container: &PostQuantumContainer, toolset_bytes: Option<K>
        let argon_container = ArgonContainerType::Client(ClientArgonContainer::from(ArgonSettings::new_defaults(vec![])));
        let cnac = node_nac.create_client_account(possible_cid, None, username.clone(), "thomas braun", argon_container, ).await.unwrap();
        log::info!("CNAC successfully constructed | {:?}", &cnac);
        let (alice_1, _bob_1) = gen(possible_cid,1, None);
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
            let (alice_n, _) = gen(possible_cid,vers as u32, None);
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

        assert!(account_manager.debug_insert_cnac(cnac.clone()));
        account_manager.save().await.unwrap();

        assert!(account_manager.get_client_by_cid(cnac.get_cid()).await.unwrap().is_some());
        assert!(account_manager.get_client_by_username(&username).await.unwrap().is_some());
        cnac
    }
}