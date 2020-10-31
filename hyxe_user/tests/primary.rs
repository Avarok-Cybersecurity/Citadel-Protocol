#![feature(async_closure)]
#[cfg(test)]
mod tests {
    pub const ALGORITHM: u8 = hyxe_fs::hyxe_crypt::prelude::algorithm_dictionary::FIRESABER;
    use hyxe_user::network_account::NetworkAccount;
    use hyxe_fs::hyxe_crypt::prelude::PostQuantumContainer;
    use hyxe_user::account_loader::{load_cnac_files, load_node_nac};
    use hyxe_user::prelude::HyperNodeAccountInformation;
    use hyxe_fs::hyxe_crypt::drill::SecurityLevel;
    use futures::Future;
    use hyxe_user::account_manager::AccountManager;
    use secstr::SecVec;

    fn block_on<F: Future>(future: F) {
        std::env::set_var("RUST_LOG", "info");
        env_logger::init();
        tokio::runtime::Runtime::new().unwrap().block_on(future);
    }

    #[test]
    fn create_nac() {
        block_on(
        async {
            match NetworkAccount::new_local().await {
                Ok(nac) => {
                    println!("NAC creation success!");
                    if let Err(e) = nac.async_save_to_local_fs().await {
                        eprintln!("Error saving NAC: {}", e.to_string());
                    }
                },
                Err(e) => {
                    eprintln!("Error: {}", e.to_string());
                }
            }
        });
    }

    #[test]
    fn load_nac() {
        block_on(async {
            let mut cnacs = load_cnac_files().await.unwrap_or_default();
            load_node_nac(&mut cnacs).await.and_then(|nac| {
                println!("Loaded NAC with nid {}", nac.get_id());
                Ok(())
            }).map_err(|err| {
                println!("Err: {}", err.to_string());
            }).unwrap();

            for cnac in cnacs {
                cnac.1.async_save_to_local_fs().await.unwrap()
            }
        });
    }

    #[test]
    fn test_quantum_cnac() {
        println!("Executing load_cnacs ...");
        block_on(
            async {
                match load_cnac_files().await {
                    Ok(vec) => {
                        println!("CNACS loaded: {}", vec.len());
                        for (_, cnac) in vec {
                            println!("{}", cnac.get_id());
                            for version in cnac.get_drill_versions().await {
                                cnac.borrow_drill(Some(version),|drill_opt| {
                                    if let Some(drill) = drill_opt {
                                        println!("Borrowing drill vers: {}", drill.get_version());
                                        debug_assert_eq!(version, drill.get_version());
                                    }
                                }).await;
                            }

                            cnac.async_save_to_local_fs().await.unwrap();
                        }
                    },
                    Err(err) => {
                        println!("Err: {}", err.to_string());
                    }
                }
            });
    }

    #[test]
    fn delete_cnac_by_username() {
        let args: Vec<String> = std::env::args().collect();
        let username = args.last().unwrap().clone();

        log::info!("Deleting username: {}", &username);
        block_on(async {
            match AccountManager::new().await {
                Ok(account_manager) => {
                    if !account_manager.delete_client_by_username(&username).await {
                        log::error!("Unable to delete user {} from the internal system. Now syncing files ...", username)
                    } else {
                        log::info!("Deleted the user {} from the internal system. Now syncing files ...", username);
                    }

                    account_manager.async_save_to_local_fs().await.unwrap()
                },

                Err(err) => {
                    panic!("Error loading account manager: {}", err.to_string());
                }
            }
        });
    }

    #[test]
    fn create_cnac_then_ser_deser_then_check_login() {
        block_on(async {
            let ref pqc = PostQuantumContainer::new_alice(Some(ALGORITHM));
            let acc_manager = AccountManager::new().await.unwrap();
            let local_nac = acc_manager.get_local_nac();

            let username = "tbraun96";
            let password = SecVec::new("mrmoney10".as_bytes().to_vec());

            match local_nac.create_client_account::<_, _,&[u8]>(None, username, password, "Thomas P Braun", pqc, None).await {
                Ok(ref cnac) => unsafe {
                    match cnac.validate_credentials("tbraun96", SecVec::new("mrmoney10".as_bytes().to_vec())).await {
                        Ok(_) => {
                            log::info!("Validation success");
                            let bytes = cnac.generate_bytes_async().await.unwrap();
                            let deser = hyxe_user::account_loader::load_cnac_from_bytes(bytes).await.unwrap();
                            match deser.validate_credentials("tbraun96", SecVec::new("mrmoney10".as_bytes().to_vec())).await {
                                Ok(_) => {
                                    log::info!("Validation success (part II)");
                                },

                                Err(err) => {
                                    log::error!("Validation failure (part II). Reason: {:?}", err);
                                }
                            }
                        },

                        Err(err) => {
                            log::error!("Validation failure. Reason: {:?}", err);
                        }
                    }
                },

                Err(err) => {
                    log::error!("Error: {:?}", err);
                }
            }
        });
    }

    #[test]
    fn create_cnac() {
        //let args: Vec<String> = std::env::args().collect();
        //let username = args.last().unwrap().clone();
        let username = "tbraun96";
        let password = SecVec::new("mrmoney10".as_bytes().to_vec());
        let ref pqc = PostQuantumContainer::new_alice(Some(ALGORITHM));
        block_on( async {
            let mut cnacs = load_cnac_files().await.unwrap_or_default();
            let node_nac = load_node_nac(&mut cnacs).await.unwrap();

                println!("Loaded NAC with NID {}", node_nac.get_id());
                // nac_other: Option<NetworkAccount>, username: T, password: SecVec<u8>, full_name: V, post_quantum_container: &PostQuantumContainer, toolset_bytes: Option<K>
                match node_nac.create_client_account::<_, _, &[u8]>(None, username, password, "Thomas P Braun", pqc, None).await {
                    Ok(cnac) => {
                        println!("CNAC successfully constructed");
                        cnac.update_toolset(None).await.unwrap();
                        let range = cnac.get_drill_versions().await;

                        debug_assert_eq!(range.clone().count(), 2);
                        for version in range {
                            cnac.borrow_drill(Some(version), |drill_opt| {
                                let drill = drill_opt.unwrap();
                                println!("Borrowing drill vers: {}. Expects: {}", drill.get_version(), version);
                                debug_assert_eq!(version, drill.get_version());
                            }).await;
                        }

                        cnac.update_toolset(Some(10)).await.unwrap();
                        let range = cnac.get_drill_versions().await;
                        debug_assert_eq!(range.clone().count(), 12);

                        for version in range {
                            cnac.borrow_drill(Some(version), |drill_opt| {
                                let drill = drill_opt.unwrap();
                                println!("Borrowing drill vers: {}. Expects: {}", drill.get_version(), version);
                                debug_assert_eq!(version, drill.get_version());
                            }).await;
                        }

                        cnac.update_toolset(Some(40)).await.unwrap();
                        let range = cnac.get_drill_versions().await;
                        debug_assert_eq!(range.clone().count(), 52);

                        for version in range {
                            cnac.borrow_drill(Some(version), |drill_opt| {
                                let drill = drill_opt.unwrap();
                                println!("Borrowing drill vers: {}. Expects: {}", drill.get_version(), version);
                                debug_assert_eq!(version, drill.get_version());
                            }).await;
                        }

                        cnac.update_toolset(Some(hyxe_fs::hyxe_crypt::toolset::MAX_DRILLS_IN_MEMORY)).await.unwrap();
                        let range = cnac.get_drill_versions().await;
                        debug_assert_eq!(range.clone().count(), hyxe_fs::hyxe_crypt::toolset::MAX_DRILLS_IN_MEMORY);

                        for version in range {
                            cnac.borrow_drill(Some(version), |drill_opt| {
                                let drill = drill_opt.unwrap();
                                println!("Borrowing drill vers: {}. Expects: {}", drill.get_version(), version);
                                debug_assert_eq!(version, drill.get_version());
                            }).await;
                        }

                        /*match cnac.async_save_to_local_fs().await {
                            Ok(_) => {
                                println!("Saved CNAC to disk successfully");
                            },
                            Err(err) => {
                                println!("ERR: {}", err.to_string());
                            }
                        }*/
                    },
                    Err(err) => {
                        println!("ERR: {}", err.to_string());
                    }
                }

            /*for cnac in cnacs {
                cnac.1.async_save_to_local_fs().await.unwrap()
            }*/
        });
    }

    #[test]
    fn load_cnacs() {
        println!("Executing load_cnacs ...");
        block_on(
        async {
            match load_cnac_files().await {
                Ok(vec) => {
                    println!("CNACS loaded: {}", vec.len());
                    for (_, cnac) in vec {
                        println!("{}", cnac.get_id());
                        for version in cnac.get_drill_versions().await {
                            cnac.borrow_drill(Some(version),|drill_opt| {
                                if let Some(drill) = drill_opt {
                                    println!("Borrowing drill vers: {}", drill.get_version());
                                    debug_assert_eq!(version, drill.get_version());
                                }
                            }).await;
                        }

                        let username = cnac.get_username().await;
                        println!("Username loaded: {}", &username);
                        if username == "tbraun96" {
                            unsafe { cnac.validate_credentials("tbraun96", SecVec::new("mrmoney10".as_bytes().to_vec())).await.unwrap() };
                        }

                        cnac.async_save_to_local_fs().await.unwrap();
                    }
                },
                Err(err) => {
                    println!("Err: {}", err.to_string());
                }
            }
        });
    }

    #[test]
    fn encrypt_decrypt_from_cnac() {
        let msg = "hello world!";
        let msg_bytes = Vec::from(msg);
        block_on(
            async {
                match load_cnac_files().await {
                    Ok(mut vec) => {
                        println!("CNACS loaded: {}", vec.len());
                        let mut first = 0;
                        for (id, cnac) in &vec {
                            println!("{}", cnac.get_id());
                            if first == 0 {
                                first = *id;
                            }
                            cnac.clone().async_save_to_local_fs().await.unwrap();
                        }
                        let cnac = vec.remove(&first).unwrap();
                        let drill = cnac.read().await.toolset.get_most_recent_drill().unwrap().clone();
                        let encrypted_bytes = drill.encrypt_to_vec(msg.as_bytes(), 0, SecurityLevel::DIVINE).unwrap();
                        assert_ne!(encrypted_bytes, msg_bytes);
                        let decrypted_bytes = drill.decrypt_to_vec(encrypted_bytes.as_slice(), 0, SecurityLevel::DIVINE).unwrap();
                        assert_eq!(decrypted_bytes, msg_bytes);
                    },
                    Err(err) => {
                        println!("Err: {}", err.to_string());
                    }
                }
            });


    }

    #[test]
    fn update_toolset() {
        block_on(async {
            match load_cnac_files().await {
                Ok(mut vec) => {
                    println!("CNACS loaded: {}", vec.len());
                    let mut first = 0;
                    for (id, _) in &vec {
                        if first == 0 {
                            first = *id;
                        }
                        println!("{}", id);
                    }
                    let cnac = vec.remove(&first).unwrap();
                    let mut write = cnac.write().await;
                    for _ in 0..100usize {
                        write.toolset.update().await.and_then(|_|{
                            //println!("Update done");
                            Ok(())
                        }).unwrap();
                    }
                    std::mem::drop(write);
                    cnac.async_save_to_local_fs().await.unwrap();

                    for cnac in vec {
                        cnac.1.async_save_to_local_fs().await.unwrap();
                    }

                },
                Err(err) => {
                    println!("Err: {}", err.to_string());
                }
            }
          });
    }

    #[test]
    fn delete_all_users() {
        block_on(async {
            let account_manager = AccountManager::new().await.unwrap();
            debug_assert!(account_manager.delete_all_users().await);
            debug_assert!(account_manager.async_save_to_local_fs().await.is_ok());
        });
    }

    #[test]
    fn network_map_create() {
        block_on(async {
            let account_manager = AccountManager::new().await.unwrap();
            account_manager.async_save_to_local_fs().await.unwrap();
        });
    }
}