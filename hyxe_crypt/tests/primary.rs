#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use ez_pqcrypto::algorithm_dictionary::{
        CryptoParameters, EncryptionAlgorithm, KemAlgorithm, KEM_ALGORITHM_COUNT,
    };
    use ez_pqcrypto::constructor_opts::ConstructorOpts;
    use hyxe_crypt::argon::argon_container::{
        ArgonSettings, ArgonStatus, AsyncArgon, ServerArgonContainer,
    };
    #[cfg(not(coverage))]
    use hyxe_crypt::argon::autotuner::calculate_optimal_argon_params;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
    use hyxe_crypt::net::crypt_splitter::{
        par_scramble_encrypt_group, scramble_encrypt_group, GroupReceiver,
    };
    use hyxe_crypt::secure_buffer::sec_bytes::SecBuffer;
    use hyxe_crypt::secure_buffer::sec_string::SecString;
    use hyxe_crypt::stacked_ratchet::{Ratchet, StackedRatchet};
    use hyxe_crypt::toolset::{Toolset, UpdateStatus, MAX_HYPER_RATCHETS_IN_MEMORY};
    use std::convert::TryFrom;
    use std::time::Instant;

    #[tokio::test]
    #[cfg(not(coverage))]
    async fn argon_autotuner() {
        lusna_logging::setup_log();
        let start_time = Instant::now();
        let final_cfg = calculate_optimal_argon_params(500_u16, Some(32), None)
            .await
            .unwrap();
        log::trace!(target: "lusna", "DONE. Elapsed time: {:?}", start_time.elapsed());
        log::trace!(target: "lusna", "{:?}", final_cfg)
    }

    #[tokio::test]
    async fn argon() {
        lusna_logging::setup_log();

        // Client config should be a weaker version that the server version, since the client doesn't actually store the password on their own device. Still, if login time can in total be kept under 2s, then it's good
        let client_config = ArgonSettings::new_gen_salt(
            "Thomas P Braun".as_bytes().to_vec(),
            8,
            32,
            1024 * 64,
            4,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
        );
        // client hashes their password
        match AsyncArgon::hash(SecBuffer::from("password"), client_config.clone())
            .await
            .unwrap()
        {
            ArgonStatus::HashSuccess(hashed_password) => {
                log::trace!(target: "lusna", "Hash success!");
                // now, the client stores the config in their CNAC to be able to hash again in the future. Next, client sends the hashed password through an encrypted stream to the server
                let server_recv = hashed_password;
                // The server creates their own version of the settings, which should be dependent on the capabilities of that server. (Aim for 0.5s < x < 1.0s hash time)
                let server_config = ArgonSettings::new_gen_salt(
                    "Thomas P Braun".as_bytes().to_vec(),
                    8,
                    32,
                    1024 * 64,
                    4,
                    vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
                );
                // the server then hashes the server_recv
                match AsyncArgon::hash(server_recv.clone(), server_config.clone())
                    .await
                    .unwrap()
                {
                    ArgonStatus::HashSuccess(hashed_password_x2) => {
                        // The server saves this hashed output to the backend. Then, if a client wants to login, they have to hash their password
                        let server_argon_container =
                            ServerArgonContainer::new(server_config, hashed_password_x2.clone());

                        match AsyncArgon::hash(SecBuffer::from("password"), client_config.clone())
                            .await
                            .unwrap()
                        {
                            ArgonStatus::HashSuccess(hashed_password_v2) => {
                                //assert_eq!(hashed_password_v2.as_ref(), server_recv.as_ref());
                                // client sends to server to verify
                                match AsyncArgon::verify(
                                    hashed_password_v2,
                                    server_argon_container.clone(),
                                )
                                .await
                                .unwrap()
                                {
                                    ArgonStatus::VerificationSuccess => {
                                        log::trace!(target: "lusna", "Verification success!");
                                        return;
                                    }

                                    n => {
                                        log::error!(target: "lusna", "{:?}", n);
                                    }
                                }
                            }

                            n => {
                                log::error!(target: "lusna", "{:?}", n);
                            }
                        }
                    }

                    n => {
                        log::error!(target: "lusna", "{:?}", n);
                    }
                }
            }

            n => {
                log::error!(target: "lusna", "{:?}", n);
            }
        }

        panic!("Failed somewhere");
    }

    /*
    #[test]
    fn onion_packets() {
        onion_packet::<StackedRatchet>();
        #[cfg(feature = "fcm")]
            onion_packet::<hyxe_crypt::fcm::fcm_ratchet::FcmRatchet>();
    }

    fn onion_packet<R: Ratchet>() {
        lusna_logging::setup_log();
        const LEN: usize = 5;
        const HEADER_LEN: usize = 50;
        let message = "Hello, world!";
        let algo = KemAlgorithm::Kyber1024_90s + EncryptionAlgorithm::Xchacha20Poly_1305;

        let chain = CryptoRelayChain::<R>::from_iter((0..LEN).into_iter().map(|_idx| rand::random::<u64>())
            .map(|cid| {
                let mut alice_hr = R::Constructor::new_alice(vec![ConstructorOpts::new_init(Some(algo))], 0, 0, None);
                let transfer = alice_hr.stage0_alice();
                let bob_hr = R::Constructor::new_bob(0, 0, vec![ConstructorOpts::new_init(Some(algo))], transfer).unwrap();
                let transfer = bob_hr.stage0_bob().unwrap();
                alice_hr.stage1_alice(&transfer).unwrap();
                let toolset = Toolset::new(cid, alice_hr.finish().unwrap());
                let container = PeerSessionCrypto::new(toolset, true);
                container
            }));

        log::trace!(target: "lusna", "Generated chain!");

        let onion_packet = chain.encrypt(message, 0, HEADER_LEN, |_ratchet, _target_cid, buffer| {
            for x in 0..HEADER_LEN {
                buffer.put_u8(x as u8);
            }
        }).unwrap();

        println!("Onion packet: {:?}", &onion_packet);
        let cids_order_decrypt = chain.target_cid_list.as_ref().unwrap().iter().rev().cloned().collect::<Vec<u64>>();
        println!("{:?}\n", &cids_order_decrypt);
        let output = chain.links.iter().rfold(onion_packet, |mut acc, (cid, container)| {
            println!("At {} (onion packet len: {})", cid, acc.len());
            let (pqc, drill) = container.get_hyper_ratchet(None).unwrap().message_pqc_drill(None);
            let payload = acc.split_off(HEADER_LEN);
            drill.aes_gcm_decrypt(0, pqc, payload)
                .map(|vec| bytes::BytesMut::from(&vec[..])).unwrap()
        });

        assert_eq!(message, String::from_utf8(output.to_vec()).unwrap());
    }*/

    #[test]
    fn secstring() {
        lusna_logging::setup_log();
        let mut val = SecString::new();
        assert_eq!(val.len(), 0);
        val.push('h');
        val.push('e');
        //val.clear();
        let mut basic = val.clone();
        assert_eq!(val.len(), 2);
        assert_eq!(basic.len(), 2);
        assert_eq!(basic.as_str(), "he");

        basic.push('y');
        assert_ne!(val.as_str(), basic.as_str());

        let retrieved = basic.into_buffer();
        let serde = bincode2::serialize(&retrieved).unwrap();
        let retrieved = bincode2::deserialize::<SecString>(&serde)
            .unwrap()
            .into_buffer();
        // at this point, basic should have dropped, but the memory should not have been zeroed out
        assert_eq!(retrieved, "hey");
    }

    #[test]
    fn secbytes() {
        lusna_logging::setup_log();
        let buf = SecBuffer::from("Hello, world!");
        let serde = bincode2::serialize(&buf).unwrap();
        std::mem::drop(buf);
        let buf = bincode2::deserialize::<SecBuffer>(&serde).unwrap();

        assert_eq!(buf.as_ref(), b"Hello, world!");
        let cloned = buf.clone();
        let ptr = cloned.as_ref().as_ptr();
        let len = cloned.as_ref().len();
        let ptr_slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        assert_eq!(cloned.as_ref(), ptr_slice);
        let retrieved = buf.into_buffer();

        assert_eq!(&*retrieved, b"Hello, world!");
    }

    #[test]
    fn hyper_ratchets() {
        lusna_logging::setup_log();
        for x in 0u8..KEM_ALGORITHM_COUNT {
            for sec in 0..SecurityLevel::DIVINE.value() {
                let _ = hyper_ratchet::<StackedRatchet, _>(
                    KemAlgorithm::try_from(x).unwrap() + EncryptionAlgorithm::AES_GCM_256_SIV,
                    Some(sec.into()),
                    false,
                );
                let _ = hyper_ratchet::<StackedRatchet, _>(
                    KemAlgorithm::try_from(x).unwrap() + EncryptionAlgorithm::Xchacha20Poly_1305,
                    Some(sec.into()),
                    false,
                );
            }
        }
    }

    #[test]
    fn hyper_ratchets_fcm() {
        lusna_logging::setup_log();
        for x in 0u8..KEM_ALGORITHM_COUNT {
            for sec in 0..SecurityLevel::DIVINE.value() {
                let _ = hyper_ratchet::<hyxe_crypt::fcm::fcm_ratchet::ThinRatchet, _>(
                    KemAlgorithm::try_from(x).unwrap() + EncryptionAlgorithm::AES_GCM_256_SIV,
                    Some(sec.into()),
                    true,
                );
                let _ = hyper_ratchet::<hyxe_crypt::fcm::fcm_ratchet::ThinRatchet, _>(
                    KemAlgorithm::try_from(x).unwrap() + EncryptionAlgorithm::Xchacha20Poly_1305,
                    Some(sec.into()),
                    true,
                );
            }
        }
    }

    #[test]
    fn security_levels() {
        lusna_logging::setup_log();
        for sec in 0..SecurityLevel::DIVINE.value() {
            let ratchet = hyper_ratchet::<StackedRatchet, _>(
                KemAlgorithm::Firesaber + EncryptionAlgorithm::AES_GCM_256_SIV,
                Some(sec.into()),
                false,
            );
            for x in 0..sec {
                assert!(ratchet.verify_level(Some(x.into())).is_ok())
            }

            for x in (sec + 1)..SecurityLevel::CUSTOM(255).value() {
                assert!(ratchet.verify_level(Some(x.into())).is_err())
            }
        }
    }

    fn hyper_ratchet<R: Ratchet, Z: Into<CryptoParameters>>(
        algorithm: Z,
        security_level: Option<SecurityLevel>,
        is_fcm: bool,
    ) -> R {
        let algorithm = algorithm.into();
        log::trace!(target: "lusna", "Using {:?} with {:?} @ {:?} security level | is FCM: {}", algorithm.kem_algorithm, algorithm.encryption_algorithm, security_level, is_fcm);
        let algorithm = Some(algorithm);
        let count = (security_level.unwrap_or_default().value() + 1) as usize;
        let mut alice_hyper_ratchet = R::Constructor::new_alice(
            ConstructorOpts::new_vec_init(algorithm, count),
            99,
            0,
            security_level,
        )
        .unwrap();
        let transfer = alice_hyper_ratchet.stage0_alice();

        let bob_hyper_ratchet = R::Constructor::new_bob(
            99,
            0,
            ConstructorOpts::new_vec_init(algorithm, count),
            transfer,
        )
        .unwrap();
        let transfer = bob_hyper_ratchet.stage0_bob().unwrap();

        alice_hyper_ratchet.stage1_alice(&transfer).unwrap();

        let alice_hyper_ratchet = alice_hyper_ratchet.finish().unwrap();
        let bob_hyper_ratchet = bob_hyper_ratchet.finish().unwrap();

        const MESSAGE: &[u8] = b"Hello, world!" as &[u8];
        const HEADER_LEN: usize = 50;

        let mut packet = BytesMut::with_capacity(MESSAGE.len() + HEADER_LEN);

        for x in 0..50 {
            packet.put_u8(x);
        }

        packet.put(MESSAGE);

        let plaintext_packet = packet.clone();

        alice_hyper_ratchet
            .protect_message_packet(security_level, HEADER_LEN, &mut packet)
            .unwrap();
        assert_ne!(packet, plaintext_packet);

        let mut header = packet.split_to(HEADER_LEN);
        bob_hyper_ratchet
            .validate_message_packet(security_level, &header[..], &mut packet)
            .unwrap();

        header.unsplit(packet);

        assert_eq!(header, plaintext_packet);
        alice_hyper_ratchet
    }

    #[test]
    fn toolsets() {
        toolset::<StackedRatchet>();
        #[cfg(feature = "fcm")]
        toolset::<hyxe_crypt::fcm::fcm_ratchet::ThinRatchet>();
    }

    fn toolset<R: Ratchet>() {
        lusna_logging::setup_log();
        const COUNT: u32 = 100;
        let security_level = SecurityLevel::LOW;

        let (alice, _bob) = gen::<R>(0, 0, security_level);

        let mut toolset = Toolset::new(0, alice);

        for x in 1..COUNT {
            let res = toolset
                .update_from(gen::<R>(0, x, security_level).0)
                .unwrap();
            match res {
                UpdateStatus::Committed { .. } => {
                    assert!(x < MAX_HYPER_RATCHETS_IN_MEMORY as u32);
                    assert_eq!(0, toolset.get_oldest_hyper_ratchet_version());
                    assert_eq!(x, toolset.get_most_recent_hyper_ratchet_version());
                }

                UpdateStatus::CommittedNeedsSynchronization { old_version, .. } => {
                    assert_eq!(old_version, 0); // we're not truncating it yet, so it should be 0
                    assert!(x + 1 > MAX_HYPER_RATCHETS_IN_MEMORY as u32);
                    assert_eq!(0, toolset.get_oldest_hyper_ratchet_version()); // this shouldn't change because the oldest needs to be manually removed
                    assert_eq!(x, toolset.get_most_recent_hyper_ratchet_version());
                }
            }
        }

        for x in 0..COUNT {
            if toolset.deregister_oldest_hyper_ratchet(x).is_ok() {
                assert_eq!(x + 1, toolset.get_oldest_hyper_ratchet_version());
            } else {
                assert_eq!(toolset.len(), MAX_HYPER_RATCHETS_IN_MEMORY);
                assert_eq!(
                    toolset.get_oldest_hyper_ratchet_version(),
                    COUNT - MAX_HYPER_RATCHETS_IN_MEMORY as u32
                );
            }
        }

        let _res = toolset
            .update_from(gen::<R>(0, COUNT, security_level).0)
            .unwrap();
        assert_eq!(toolset.len(), MAX_HYPER_RATCHETS_IN_MEMORY + 1);
        assert_eq!(
            toolset.get_oldest_hyper_ratchet_version(),
            toolset.get_most_recent_hyper_ratchet_version() - MAX_HYPER_RATCHETS_IN_MEMORY as u32
        );

        toolset
            .deregister_oldest_hyper_ratchet(
                toolset.get_most_recent_hyper_ratchet_version()
                    - MAX_HYPER_RATCHETS_IN_MEMORY as u32,
            )
            .unwrap();
        assert_eq!(toolset.len(), MAX_HYPER_RATCHETS_IN_MEMORY);
    }

    fn gen<R: Ratchet>(cid: u64, version: u32, sec: SecurityLevel) -> (R, R) {
        let count = sec.value() as usize + 1;
        let algorithm = EncryptionAlgorithm::AES_GCM_256_SIV + KemAlgorithm::Firesaber;
        let mut alice = R::Constructor::new_alice(
            ConstructorOpts::new_vec_init(Some(algorithm), count),
            cid,
            version,
            Some(sec),
        )
        .unwrap();
        let bob = R::Constructor::new_bob(
            cid,
            version,
            ConstructorOpts::new_vec_init(Some(algorithm), count),
            alice.stage0_alice(),
        )
        .unwrap();
        alice.stage1_alice(&bob.stage0_bob().unwrap()).unwrap();
        (alice.finish().unwrap(), bob.finish().unwrap())
    }

    #[test]
    fn toolset_wrapping_vers_all() {
        toolset_wrapping_vers::<StackedRatchet>();
        #[cfg(feature = "fcm")]
        toolset_wrapping_vers::<hyxe_crypt::fcm::fcm_ratchet::ThinRatchet>();
    }

    fn toolset_wrapping_vers<R: Ratchet>() {
        lusna_logging::setup_log();
        let vers = u32::MAX - 1;
        let cid = 10;
        let hr = gen::<R>(cid, vers, SecurityLevel::LOW);
        let mut toolset = Toolset::new_debug(cid, hr.0, vers, vers);
        let r = toolset.get_hyper_ratchet(vers).unwrap();
        assert_eq!(r.version(), vers);

        const COUNT: usize = 100;
        let mut insofar = 0;
        let mut cur_vers = vers.wrapping_add(1);
        loop {
            if insofar >= COUNT {
                break;
            }

            toolset
                .update_from(gen::<R>(cid, cur_vers, SecurityLevel::LOW).0)
                .unwrap();
            let ratchet = toolset.get_hyper_ratchet(cur_vers).unwrap();
            assert_eq!(ratchet.version(), cur_vers);
            cur_vers = cur_vers.wrapping_add(1);
            insofar += 1;
        }

        assert_eq!(toolset.get_oldest_hyper_ratchet().unwrap().version(), vers);
        let mut amt_culled = 0;
        for _ in 0..COUNT {
            if toolset.len() == MAX_HYPER_RATCHETS_IN_MEMORY {
                continue;
            }
            toolset
                .deregister_oldest_hyper_ratchet(vers.wrapping_add(amt_culled))
                .unwrap();
            amt_culled += 1;
            assert_eq!(
                toolset.get_oldest_hyper_ratchet().unwrap().version(),
                vers.wrapping_add(amt_culled)
            );
        }
    }

    #[test]
    fn scrambler_transmission_all() {
        scrambler_transmission::<StackedRatchet>();
        #[cfg(feature = "fcm")]
        scrambler_transmission::<hyxe_crypt::fcm::fcm_ratchet::ThinRatchet>();
    }

    fn scrambler_transmission<R: Ratchet>() {
        lusna_logging::setup_log();

        const SECURITY_LEVEL: SecurityLevel = SecurityLevel::LOW;
        const HEADER_SIZE_BYTES: usize = 44;

        let mut data = BytesMut::with_capacity(1000);
        let (ratchet_alice, ratchet_bob) = gen::<R>(10, 0, SECURITY_LEVEL);
        println!("Ratchet created. Creating PQC");

        // do 1000 for real tests on linux
        for x in 0..1500_usize {
            data.put_u8((x % 256) as u8);
            let input_data = &data[..=x];

            //let input_data: &[u8] = include_bytes!("C:/Users/tbrau/input.txt");
            //let input_data = r#"Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved."#;
            //let input_data = b"Hello";

            let mut scramble_transmitter =
                par_scramble_encrypt_group::<_, _, _, HEADER_SIZE_BYTES>(
                    input_data,
                    SECURITY_LEVEL,
                    &ratchet_alice,
                    HEADER_SIZE_BYTES,
                    0,
                    0,
                    0,
                    |_vec, _drill, _target_cid, _, buffer| {
                        for x in 0..HEADER_SIZE_BYTES {
                            buffer.put_u8(x as u8)
                        }
                    },
                )
                .unwrap();

            let config = scramble_transmitter.get_receiver_config();
            let mut receiver = GroupReceiver::new(config.clone(), 0, 0);
            log::trace!(target: "lusna", "{:?}", &config);

            while let Some(mut packet) = scramble_transmitter.get_next_packet() {
                //log::trace!(target: "lusna", "Packet {} (wave id: {}) obtained and ready to transmit to receiver", packet.vector.true_sequence, packet.vector.wave_id);
                let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                let _result = receiver.on_packet_received(
                    0,
                    packet.vector.true_sequence,
                    packet.vector.wave_id,
                    &ratchet_bob,
                    packet_payload,
                );
                //println!("Wave {} result: {:?}", packet.vector.wave_id, result);
            }

            //println!("Possibly done with the descrambling/decryption process ... ");

            let decrypted_descrambled_plaintext = receiver.finalize();
            debug_assert_eq!(decrypted_descrambled_plaintext.as_slice(), input_data);
        }
        println!("Done");
    }

    #[test]
    fn simulate_packet_loss_all() {
        simulate_packet_loss::<StackedRatchet>();
        #[cfg(feature = "fcm")]
        simulate_packet_loss::<hyxe_crypt::fcm::fcm_ratchet::ThinRatchet>();
    }

    fn simulate_packet_loss<R: Ratchet>() {
        lusna_logging::setup_log();
        let mut start_data = Vec::with_capacity(4 * 5000);
        for x in 0..5000i32 {
            for val in &x.to_be_bytes() {
                start_data.push(*val);
            }
        }

        for lvl in 0..=10 {
            let security_level: SecurityLevel = SecurityLevel::for_value(lvl).unwrap();

            let (alice_ratchet, bob_ratchet) = gen::<R>(10, 0, security_level);
            //let input_data: &[u8] = include_bytes!("/Users/nologik/Downloads/TheBridge.pdf");
            let input_data = &start_data[..];
            let now = Instant::now();
            let byte_len = input_data.len();

            const HEADER_SIZE_BYTES: usize = 50;

            let mut scramble_transmitter = scramble_encrypt_group(
                input_data,
                security_level,
                &alice_ratchet,
                HEADER_SIZE_BYTES,
                0,
                0,
                0,
                |_vec, _drill, _target_cid, _obj_id, buffer| {
                    for x in 0..HEADER_SIZE_BYTES {
                        buffer.put_u8(x as u8)
                    }
                },
            )
            .unwrap();

            let delta = now.elapsed();
            let rate = ((byte_len as f32) / (delta.as_secs_f32())) / 1_000_000f32;
            println!(
                "[{:?}] Done cryptscrambling in {}ms (Rate: {}Mb/s)= {}/{}",
                security_level,
                delta.as_millis(),
                rate,
                byte_len,
                delta.as_secs_f32()
            );
            let config = scramble_transmitter.get_receiver_config();
            println!("{:?}", &config);
            let mut receiver = GroupReceiver::new(config.clone(), 0, 0);

            let mut seq = 0;
            let now = Instant::now();
            let mut retransmission_resimulate_container = Vec::new();
            while let Some(mut packet) = scramble_transmitter.get_next_packet() {
                //log::trace!(target: "lusna", "Packet {} (wave id: {}) obtained and ready to transmit to receiver", packet.vector.true_sequence, packet.vector.wave_id);

                // Don't transmit the 11, 12, 13, 14th packets to simulate packet loss
                if seq <= 1 || seq > 5 {
                    let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                    let _result = receiver.on_packet_received(
                        packet.vector.group_id,
                        packet.vector.true_sequence,
                        packet.vector.wave_id,
                        &bob_ratchet,
                        packet_payload,
                    );
                    // println!("Wave {} result: {:?}", packet.vector.wave_id, result);
                } else {
                    retransmission_resimulate_container.push(packet);
                }

                seq += 1;
            }

            let delta = now.elapsed();
            let rate = ((byte_len as f32) / (delta.as_secs_f32())) / 1_000_000f32;
            println!(
                "[{:?}] Done de-cryptscrambling in {}ms (Rate: {}Mb/s)= {}/{}",
                security_level,
                delta.as_millis(),
                rate,
                byte_len,
                delta.as_secs_f32()
            );

            let packets_lost_vectors = receiver
                .get_retransmission_vectors_for(0, 0, &bob_ratchet)
                .unwrap();
            debug_assert_eq!(packets_lost_vectors.len(), 4);

            // Simulate retransmission
            for mut packet in retransmission_resimulate_container.into_iter() {
                let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                let _result = receiver.on_packet_received(
                    packet.vector.group_id,
                    packet.vector.true_sequence,
                    packet.vector.wave_id,
                    &bob_ratchet,
                    packet_payload,
                );
            }

            println!("Possibly done with the descrambling/decryption process ...");

            let decrypted_descrambled_plaintext = receiver.finalize();
            debug_assert_eq!(decrypted_descrambled_plaintext.as_slice(), input_data);
        }
    }

    #[cfg(feature = "filesystem")]
    #[tokio::test]
    async fn encrypt_decrypt_test() {
        use bytes::{BufMut, BytesMut};
        use hyxe_crypt::drill::SecurityLevel;
        use hyxe_crypt::net::crypt_splitter::{GroupReceiver, GroupReceiverStatus};
        use std::time::Instant;
        use tokio::sync::mpsc::channel;

        use hyxe_crypt::prelude::algorithm_dictionary::{
            CryptoParameters, EncryptionAlgorithm, KemAlgorithm,
        };
        use hyxe_crypt::prelude::{ConstructorOpts, Drill, PacketVector};
        use hyxe_crypt::stacked_ratchet::constructor::{
            BobToAliceTransferType, StackedRatchetConstructor,
        };
        use hyxe_crypt::stacked_ratchet::StackedRatchet;
        use hyxe_crypt::streaming_crypt_scrambler::scramble_encrypt_source;

        lusna_logging::setup_log();
        fn gen(
            algo: impl Into<CryptoParameters>,
            drill_vers: u32,
        ) -> (StackedRatchet, StackedRatchet) {
            let opts = algo.into();
            let mut alice_base = StackedRatchetConstructor::new_alice(
                ConstructorOpts::new_vec_init(Some(opts), 1),
                0,
                0,
                None,
            )
            .unwrap();
            let bob_base = StackedRatchetConstructor::new_bob(
                0,
                drill_vers,
                ConstructorOpts::new_vec_init(Some(opts), 1),
                alice_base.stage0_alice(),
            )
            .unwrap();
            alice_base
                .stage1_alice(&BobToAliceTransferType::Default(
                    bob_base.stage0_bob().unwrap(),
                ))
                .unwrap();

            (alice_base.finish().unwrap(), bob_base.finish().unwrap())
        }

        fn header_inscribe(_: &PacketVector, _: &Drill, _: u32, _: u64, packet: &mut BytesMut) {
            for x in 0..HEADER_LEN {
                packet.put_u8((x % 255) as u8)
            }
        }

        let (alice, bob) = gen(
            KemAlgorithm::Firesaber + EncryptionAlgorithm::Xchacha20Poly_1305,
            0,
        );
        let security_level = SecurityLevel::LOW;
        const HEADER_LEN: usize = 52;
        let cmp = include_bytes!("../../resources/TheBridge.pdf");
        let std_file = std::fs::File::open("../resources/TheBridge.pdf").unwrap();
        let (group_sender_tx, mut group_sender_rx) = channel(1);
        let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let (bytes, _num_groups) = scramble_encrypt_source::<_, _, HEADER_LEN>(
            std_file,
            None,
            99,
            group_sender_tx,
            stop_rx,
            security_level,
            alice.clone(),
            HEADER_LEN,
            9,
            0,
            header_inscribe,
        )
        .unwrap();

        println!("Ran function, now awaiting results ...");
        let mut _i: usize = 0;
        let now = Instant::now();
        let mut bytes_ret = Vec::new();
        let _compressed_len: usize = 0;
        let _decompressed_len: usize = 0;

        while let Some(gs) = group_sender_rx.recv().await {
            let mut gs = gs.unwrap();
            let config = gs.get_receiver_config();
            //println!("RECEIVED GS {} w {} packets", i, gs.packets_in_ram.len());
            let mut receiver = GroupReceiver::new(config.clone(), 0, 0);
            //println!("{:?}", &receiver);
            let group_id = config.group_id;
            let mut _seq = 0;
            let _now = Instant::now();
            'here: while let Some(mut packet) = gs.get_next_packet() {
                let packet_payload = packet.packet.split_off(HEADER_LEN);
                let result = receiver.on_packet_received(
                    group_id as u64,
                    packet.vector.true_sequence,
                    packet.vector.wave_id,
                    &bob,
                    packet_payload,
                );
                //dbg!(&result);
                match result {
                    GroupReceiverStatus::GROUP_COMPLETE(_group_id) => {
                        bytes_ret.extend_from_slice(receiver.finalize().as_slice());
                        /*
                        let mut bytes = receiver.finalize();
                        //let slice = bytes.as_slice();
                        println!("Compressed len: {}", bytes.len());
                        compressed_len += bytes.len();
                        //let len = flate2::bufread::DeflateDecoder::new(bytes.as_slice()).read_to_end(&mut bytes_ret).unwrap();
                        let decompressed = flate3::inflate(bytes.as_slice());
                        println!("Decompressed len: {:?}", decompressed.len());
                        decompressed_len += decompressed.len();
                        bytes_ret.extend(decompressed.into_iter());*/
                        break 'here;
                    }

                    _ => {}
                }
                //seq += 1;
            }
            //i += 1;
        }

        let delta = now.elapsed();
        let megabytes = bytes as f32 / 1_000_000f32;
        let mbs = megabytes / delta.as_secs_f32();
        println!(
            "Done receiving all. {} time, {} bytes. {} Mb/s",
            delta.as_millis(),
            bytes,
            mbs
        );
        //println!("Decompressed len: {} | Compressed len: {} | Ratio: {}", decompressed_len, compressed_len, (decompressed_len as f32 / compressed_len as f32));

        assert_eq!(bytes, bytes_ret.len());
        if bytes_ret.as_slice() != cmp as &[u8] {
            println!("{:?} != {:?}", &bytes_ret.as_slice()[..10], &cmp[..10]);
            println!(
                "{:?} != {:?}",
                &bytes_ret.as_slice()[bytes_ret.len() - 10..],
                &cmp[cmp.len() - 10..]
            );
            panic!("Vectors not equal")
        }
    }

    /*
    #[test]
    fn create_dummy_file() {
        const LEN: usize = 4_187_593_113; // 3.9 gigabytes
        let mut file = std::fs::File::create("C:/Users/tbrau/dummy.bin").unwrap();
        let slab = (0..u8::MAX).into_iter().collect::<Vec<u8>>();
        let mut written = 0;
        while written < LEN {
            file.write_all(slab.as_slice()).unwrap();
            written += u8::MAX as usize;
        }

        file.flush().unwrap();
        file.sync_all().unwrap();
    }*/
}
