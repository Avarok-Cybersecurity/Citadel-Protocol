#![feature(async_closure)]

#[cfg(test)]
mod tests {

    use hyxe_user::prelude::HyperNodeAccountInformation;
    use hyxe_user::account_manager::AccountManager;
    use secstr::SecVec;
    use hyxe_fs::hyxe_crypt::hyper_ratchet::HyperRatchet;
    use std::net::IpAddr;
    use std::str::FromStr;
    use hyxe_user::client_account::ClientNetworkAccount;
    use hyxe_user::network_account::NetworkAccount;
    use dirs2::home_dir;
    use hyxe_crypt::hyper_ratchet::constructor::{BobToAliceTransferType, HyperRatchetConstructor};
    use hyxe_crypt::fcm::fcm_ratchet::{FcmRatchet, FcmRatchetConstructor};
    use hyxe_crypt::toolset::Toolset;
    use hyxe_crypt::hyper_ratchet::Ratchet;
    use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
    use hyxe_crypt::fcm::keys::FcmKeys;
    use hyxe_crypt::sec_bytes::SecBuffer;
    use hyxe_user::fcm::data_structures::{FcmTicket, RawFcmPacket, RawFcmPacketStore};
    use std::collections::HashMap;

    #[allow(unused_must_use)]
    fn setup_log() {
        std::env::set_var("RUST_LOG", "info");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn load_nac() {
        setup_log();
        let account_manager = acc_mgr(None).await;
        println!("Loaded NAC: {:?}", account_manager.get_local_nac());
    }

    #[test]
    fn serde() {
        let mut map = HashMap::new();
        map.insert(0u64, RawFcmPacket::from("Hello, world!"));
        let mut map2 = HashMap::new();
        map2.insert(1u64, map);
        let val = RawFcmPacketStore::from(map2);
        let serded = val.serialize();
        println!("{:?}", &serded);
        let deserded = RawFcmPacketStore::deserialize_from(serded.as_bytes()).unwrap();
        println!("{:?}", deserded.inner.len());
        deserded.inner.get(&1).unwrap().get(&0).unwrap();
    }

    #[tokio::test]
    async fn fcm() {
        let acc_mgr_0 = acc_mgr(Some("1.2.2.0")).await;
        let acc_mgr_1 = acc_mgr(Some("1.2.2.1")).await;
        let user0 = create_cnac(Some(acc_mgr_0.clone())).await;
        let user1 = create_cnac(Some(acc_mgr_1.clone())).await;
        acc_mgr_0.register_hyperlan_p2p_at_endpoints(user0.get_cid(), user1.get_cid(), user1.get_username()).unwrap();
        acc_mgr_1.register_hyperlan_p2p_at_endpoints(user1.get_cid(), user0.get_cid(), user0.get_username()).unwrap();

        // now, create an HR for both
        let (hr_alice, hr_bob) = gen_fcm(user0.get_cid(), 0, Some(user1.get_cid()));
        assert_eq!(hr_alice.get_cid(), user0.get_cid());
        assert_eq!(hr_bob.get_cid(), user1.get_cid());
        assert_eq!(hr_alice.version(), hr_bob.version());

        let api_key = "AAAAsdc2buM:APA91bFGIgSp9drZGpM6rsTVWD_4A28QZVjBG9ty0ijwXn0k-peMNiivzCuSzojR7ESN13txcD7pZMyYJC_LPdjRk56EdXnUfIYDgVVbTN8VmWiVd82uJv2kEgcoGL-Flh1HXWZlVSf8";
        let alice_cl_key = "abcdefgh";
        let bob_cl_key = "e2xixMK2SKe66ryMXa1HUR:APA91bFeFWyYjh_9tPRGlDleBfUwiOLsBDXhA8__LmyYYiI8a9P4U2JcBPHtWjEnTbLxeF0ImX0nNemVZDBGxw3OYMb_UD0i2FG4UsqiOqbrMvY6dlWVYxWOy4PSDSSQS0cAgyndyR14";
        let alice_keys = FcmKeys::new(api_key, alice_cl_key);
        let bob_keys = FcmKeys::new(api_key, bob_cl_key);

        user0.visit_mut(|mut inner| {
            let toolset = Toolset::new(hr_alice.get_cid(), hr_alice.clone());
            let endpoint_container = PeerSessionCrypto::new_fcm(toolset, true, bob_keys);
            inner.fcm_crypt_container.insert(user1.get_cid(), endpoint_container);
        });

        user1.visit_mut(|mut inner| {
            let toolset = Toolset::new(hr_bob.get_cid(), hr_bob.clone());
            let endpoint_container = PeerSessionCrypto::new_fcm(toolset, false, alice_keys);
            inner.fcm_crypt_container.insert(user0.get_cid(), endpoint_container);
        });

        let input = "s6ZxbnhOXhcAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAADAAAAUAcAn+RvpBzkXNKr3cklyUhh/7Y/a/FcfEbgCguo//43hgR1C5QH9wnQobwnBj21htBMQV/Et9BKijQzudTdZbLXd8/DeMdQ4xlb3/XJXN6u+mEA12RnjySShx7AIYV+ZfKAT6VdKpLOHguUigjAOFjOlaaLFjTsLx6KtwyYiQ4/svwIUaBTnH5mYrRAjQOn1e+E8oeHoEOznw4scn/mVDIwhhCJ9oimmdEKVz5GVqhq9g5WZYUntT0hOgj4+WYtvqqu8rS0EqGWf16ODNGFmsW55+3kLxMm4Daw5S5QNVXSMId77Eoni+rcjepZeJebEo8yhqO3C3tbeBhcFJjuoMBt3tb3efk6mDY41oiRqZaTZfHUOTedZ3sguyPEZMrVa62ngRUcHHFheqe/7kHdrNtPuFLbI3+bIudNEaUqG/gk+H+6c3+4+/7mFXIItmyF1/+qRN0sOiv2BqUeE+IcKyvnpBWjWNBgJRBvzV31V2ayT0D1M/0Y2b4maULZA/7XHlwyF4qofTQBjPI+6bLs/jZky0DgPkU/9XP+56N30d5wKfGDyyhezFO2lDP4YG1W3udwMB2Mo0yM9C+Nwjs5bB4AUB4+Dmt/qLy2GyBDAIHMb87ULazfy3ZtfgOwnBNebwu+XmGJiA92Q0nn5LVjqvMuW/GPvdQXRF8f58DYLF758EO4GRwDXOYwY2sC468dGWdiGaNOezAZbK0wXvzsesEi6vMNEYuXsH3yvZwI6zyb4XlXZ32x/EG3+36EvAVUJArzlkWOuReToJKcMSFM0LUQYaLhqMHkMhO+pxsePcKuL4DQSIQVg9QxjITUuqDTTk3Wnj2m2hj2ujeHtKi2NPbVN9Sauzk7Tlgiz9c20FMDjfyH9WFpWZUu1pwdKYKIrvq4HF8gSX7As1Q7tG0fs/ikAAcE2c9ShMseax4zJ70d23qkdZqpgStT19l7upN2snm9/OU9ujXGgUQx7XF1XiusrVpEn+LoGMVPR2SzZpzbZ7Zjrx8pALscaOMM9Ud8nWYjCAsOPwxRShz0QGTm3rSKsU/0idza46czc8uZeJv3DVraF7hnhh8yZ+t29rql/2gbecr7F1JBtD/KrbM0u0EH+F0XUaB0aXIfA9YGL/aUR7WftfV045H1r+vwlBDme2UoXIIvTfK/uFS6vi8TSP9jBeYdzOQzwEWNaiB6kYGMVUaS94OWzgn3gTN3zNbhZJvOXVgtsj1U67N4GPmFaiYuy1TyRw1IlZLosvxjOn4mRmqa4wf+Ku0iBdSfklCt7PT0AJyxLYjemT255mx4euzGu8Z3ap4w5uUvOWNDiZJHDwnY+9jCox0TRzyVCImbdID43XsyLVEMoFBwPcAyrxTKi2DhXSR0es6+URWZWE3wqhbty8Km11oxI/2GfwtiwfMOnkypDszMglpXsDgzy6oZqzdbHeCzyJwQC4y+2NOlnTgzII9I3dh6alAudz41YE+VbL8nfP1RndFXEa03biSr9MBrXQ3Hpv9RHUdDwreT11CYu1HvL01ysROdtqejA1E9ZAG2Ihbz9i4pjYemxLgUchRKEq5b36udHpniCrAUkhRziNos26WaZX7MaI0xnNZmYlQ3hXkwCDe1/9MGYiqhou4J/ekWtFverTyqDrq+I2QTV0mAEF14hRrW+PXSjWK24JGklWHnRXTWGda6zmp+17rc+NzcN7cxzJMosXtWRwTE8kvCfpvK5JatKo6cq131c3WbqpsbV8hOISFcNXi6MooJGViyR3cHQbbEA0CYoxrZVhFXfLQDsaEJXyCXyB7robsgQHV+imyQ7NP/iwNKYOitrgI1xdhIp9PHBEgo4lE0CEc++LGY3/tvWdC8Uph/MUo1jI8G6CFJthjt+S2IXmUnrgQ/wQ36kL4gEzjV";
        // test blocking process
        log::info!("{:?}", hyxe_user::fcm::fcm_packet_processor::blocking_process(input, &acc_mgr_0));

        // now, start the simulation
        user0.blocking_fcm_send_to(user1.get_cid(), SecBuffer::from("Hello, bob! From alice"), 0,acc_mgr_0.fcm_client()).unwrap();

        acc_mgr_0.purge();
        acc_mgr_1.purge();
    }

    #[test]
    fn fcm_ticket() {
        use serde::{Serialize, Deserialize};
        #[derive(Serialize, Deserialize)]
        enum Test {
            Stars(FcmTicket),
            Banners(FcmTicket, u8)
        }
        let ticket = Test::Stars(FcmTicket::new(123, 456, 789));
        println!("{}", serde_json::to_string(&ticket).unwrap());
    }

    #[tokio::test]
    async fn test_ratchet_versions() {
        setup_log();
        log::info!("Executing load_cnacs ...");
            let account_manager = acc_mgr(None).await;
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
        let account_manager = acc_mgr(None).await;
        if !account_manager.delete_client_by_username(&username) {
            log::error!("Unable to delete user {} from the internal system. Now syncing files ...", username)
        } else {
            log::info!("Deleted the user {} from the internal system. Now syncing files ...", username);
        }

        account_manager.async_save_to_local_fs().await.unwrap()
    }

    fn gen_fcm(cid: u64, version: u32, endpoint_bob_cid: Option<u64>) -> (FcmRatchet, FcmRatchet) {
        let mut alice = FcmRatchetConstructor::new_alice(cid, version);
        let bob = FcmRatchetConstructor::new_bob(alice.stage0_alice()).unwrap();
        alice.stage1_alice(&bob.stage0_bob().unwrap()).unwrap();
        let bob = if let Some(cid) = endpoint_bob_cid { bob.finish_with_custom_cid(cid).unwrap() } else { bob.finish().unwrap() };
        (alice.finish().unwrap(), bob)
    }

    fn gen(cid: u64, version: u32, endpoint_bob_cid: Option<u64>) -> (HyperRatchet, HyperRatchet) {
        let mut alice = HyperRatchetConstructor::new_alice(None, cid, version, None);
        let bob = HyperRatchetConstructor::new_bob(0, cid, version, alice.stage0_alice()).unwrap();
        alice.stage1_alice(&BobToAliceTransferType::Default(bob.stage0_bob().unwrap())).unwrap();
        let bob = if let Some(cid) = endpoint_bob_cid { bob.finish_with_custom_cid(cid).unwrap() } else { bob.finish().unwrap() };
        (alice.finish().unwrap(), bob)
    }

    async fn acc_mgr(pseudo_ip: Option<&str>) -> AccountManager {
        let home_dir = format!("{}/tmp/{}", home_dir().unwrap().to_str().unwrap(), pseudo_ip.unwrap_or("1.2.3.4"));
        println!("Home dir: {}", &home_dir);
        AccountManager::new_local((IpAddr::from_str(pseudo_ip.unwrap_or("1.2.3.4")).unwrap(), 12345).into(), Some(home_dir)).unwrap()
    }

    #[tokio::test]
    async fn create_cnac_then_ser_deser_then_check_login() {
        setup_log();
        let cid = rand::random::<u64>();
        let (alice, _bob) = gen(cid, 0, None);
        let acc_manager = acc_mgr(None).await;
        let local_nac = acc_manager.get_local_nac();


        let username = format!("tbraun96{}", cid);
        let password = SecVec::new("mrmoney10".as_bytes().to_vec());
        // fake hash
        let password_hash = "mrmoney10".as_bytes().to_vec();

        let cnac = local_nac.create_client_account(cid, None, username.clone(), password, "Thomas P Braun", password_hash, alice).unwrap();
        cnac.validate_credentials(&username, SecVec::new("mrmoney10".as_bytes().to_vec())).unwrap();
        log::info!("Validation success");
        acc_manager.async_save_to_local_fs().await.unwrap();
        std::mem::drop((acc_manager, cnac));
        let acc_manager = acc_mgr(None).await;
        let cnac = acc_manager.get_client_by_cid(cid).unwrap();
        cnac.validate_credentials(&username, SecVec::new("mrmoney10".as_bytes().to_vec())).unwrap();
    }

    #[tokio::test]
    async fn create_cnac_test() {
        let _ = create_cnac(None).await;
    }

    async fn create_cnac(account_mgr: Option<AccountManager>) -> ClientNetworkAccount {
        setup_log();
        //let args: Vec<String> = std::env::args().collect();
        //let username = args.last().unwrap().clone();
        let account_manager = if let Some(acc_mgr) = account_mgr { acc_mgr } else { acc_mgr(None).await };
        let node_nac = account_manager.get_local_nac();
        let possible_cid = node_nac.generate_possible_cids()[0];

        let username = format!("tbraun96{}", possible_cid);
        let password = SecVec::new("mrmoney10".as_bytes().to_vec());
        let password_hash = "mrmoney10".as_bytes().to_vec();

        let (alice, _bob) = gen(possible_cid,0, None);

        log::info!("Loaded NAC with NID {}", node_nac.get_id());
        // nac_other: Option<NetworkAccount>, username: T, password: SecVec<u8>, full_name: V, post_quantum_container: &PostQuantumContainer, toolset_bytes: Option<K>
        let cnac = node_nac.create_client_account(possible_cid, None, username, password, "Thomas P Braun", password_hash,alice).unwrap();
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
        account_manager.async_save_to_local_fs().await.unwrap();
        cnac
    }


    #[tokio::test]
    async fn encrypt_decrypt_from_cnac() {
        setup_log();
        let account_manager = acc_mgr(None).await;
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
        let account_manager = acc_mgr(None).await;
        let account_count = account_manager.get_registered_local_cids().unwrap_or_default().len();
        assert!(account_manager.async_save_to_local_fs().await.is_ok());
        assert_eq!(account_count, account_manager.purge());
    }

    #[tokio::test]
    async fn hyperlan_peer_adding() {
        let account_manager = acc_mgr(None).await;
        let dirs = account_manager.get_directory_store().clone();

        let nac = NetworkAccount::default();
        let cid0 = 10;
        let username0 = "thomas0";

        let cid1 = 11;
        let username1 = "thomas1";

        let hr0 = gen(cid0, 0, None);
        let hr1 = gen(cid1, 0, None);
        let cnac0 = ClientNetworkAccount::<HyperRatchet, FcmRatchet>::new(cid0, true, nac.clone(), username0, SecVec::new(Vec::new()), "Thomas Braun", Vec::new(), hr0.0, dirs.clone()).unwrap();
        let _cnac1 = ClientNetworkAccount::<HyperRatchet, FcmRatchet>::new(cid1, true, nac, username1, SecVec::new(Vec::new()), "Thomas Braun II", Vec::new(), hr1.0, dirs).unwrap();
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