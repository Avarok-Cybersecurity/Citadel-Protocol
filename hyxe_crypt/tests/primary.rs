#[cfg(test)]
mod tests {
    use hyxe_crypt::sec_string::SecString;
    use hyxe_crypt::sec_bytes::SecBuffer;
    use hyxe_crypt::toolset::{Toolset, MAX_HYPER_RATCHETS_IN_MEMORY, UpdateStatus};
    use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
    use hyxe_crypt::relay_chain::CryptoRelayChain;
    use std::iter::FromIterator;
    use bytes::{BufMut, BytesMut};
    use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_crypt::net::crypt_splitter::{scramble_encrypt_group, GroupReceiver, par_scramble_encrypt_group};
    use std::time::Instant;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "hyxe_crypt=info");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[test]
    fn onion_packet() {
        setup_log();
        const LEN: usize = 5;
        const HEADER_LEN: usize = 50;
        let message = "Hello, world!";

        let chain: CryptoRelayChain = CryptoRelayChain::from_iter((0..LEN).into_iter().map(|_idx| rand::random::<u64>())
            .map(|cid| {
                let mut alice_hr = HyperRatchetConstructor::new_alice(None, 0, 0, None);
                let transfer = alice_hr.stage0_alice();
                let bob_hr = HyperRatchetConstructor::new_bob(0, 0, 0, transfer).unwrap();
                let transfer = bob_hr.stage0_bob().unwrap();
                alice_hr.stage1_alice(transfer).unwrap();
                let toolset = Toolset::new(cid, alice_hr.finish().unwrap());
                let container = PeerSessionCrypto::new(toolset, true);
                container
            }));

        log::info!("Generated chain!");

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
    }

    #[test]
    fn secstring() {
        setup_log();
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
        let retrieved = bincode2::deserialize::<SecString>(&serde).unwrap().into_buffer();
        // at this point, basic should have dropped, but the memory should not have been zeroed out
        assert_eq!(retrieved, "hey");

        let ptr = val.as_ptr();
        let len = val.len();
        // drop val to zero-out the memory
        std::mem::drop(val);
        // check to see if the values are zeroed
        let slice = unsafe { &*std::ptr::slice_from_raw_parts(ptr, len) };
        assert_eq!(slice, &[0, 0]);
    }

    #[test]
    fn secbytes() {
        setup_log();
        println!("ABT to make3");
        let buf = SecBuffer::from("Hello, world!");
        let serde = bincode2::serialize(&buf).unwrap();
        let buf = bincode2::deserialize::<SecBuffer>(&serde).unwrap();
        assert_eq!(buf.as_ref(), b"Hello, world!");
        let cloned = buf.clone();
        let ptr = cloned.as_ref().as_ptr();
        let len = cloned.as_ref().len();
        let retrieved = buf.into_buffer();
        assert_eq!(retrieved, b"Hello, world!");
        assert_eq!(retrieved, cloned.as_ref());
        std::mem::drop(cloned);
        let slice = unsafe { &*std::ptr::slice_from_raw_parts(ptr, len) };
        assert_eq!(slice, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn hyper_ratchet() {
        setup_log();
        let algorithm = Some(0);
        let security_level = Some(SecurityLevel::TRANSCENDENT(10));
        let mut alice_hyper_ratchet = HyperRatchetConstructor::new_alice(algorithm, 99, 0, security_level);
        let transfer = alice_hyper_ratchet.stage0_alice();

        let bob_hyper_ratchet = HyperRatchetConstructor::new_bob(algorithm.unwrap(), 99, 0, transfer).unwrap();
        let transfer = bob_hyper_ratchet.stage0_bob().unwrap();

        alice_hyper_ratchet.stage1_alice(transfer).unwrap();

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

        alice_hyper_ratchet.protect_message_packet(security_level, HEADER_LEN, &mut packet).unwrap();
        assert_ne!(packet, plaintext_packet);

        let mut header = packet.split_to(HEADER_LEN);
        bob_hyper_ratchet.validate_message_packet(security_level, &header[..], &mut packet).unwrap();

        header.unsplit(packet);

        assert_eq!(header, plaintext_packet);
    }

    #[test]
    fn toolset() {
        setup_log();
        const COUNT: u32 = 100;

        fn gen(drill_vers: u32) -> (HyperRatchet, HyperRatchet) {
            let mut alice_base = HyperRatchetConstructor::new_alice(None, 0, drill_vers, None);
            let bob_base = HyperRatchetConstructor::new_bob(0, 0, drill_vers, alice_base.stage0_alice()).unwrap();
            alice_base.stage1_alice(bob_base.stage0_bob().unwrap()).unwrap();

            (alice_base.finish().unwrap(), bob_base.finish().unwrap())
        }

        let (alice, _bob) = gen(0);

        let mut toolset = Toolset::new(0, alice);

        for x in 1..COUNT {
            let res = toolset.update_from(gen(x).0).unwrap();
            match res {
                UpdateStatus::Committed { .. } => {
                    assert!(x + 1 <= MAX_HYPER_RATCHETS_IN_MEMORY as u32);
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
            if let Ok(_) = toolset.deregister_oldest_hyper_ratchet(x) {
                assert_eq!(x + 1, toolset.get_oldest_hyper_ratchet_version());
            } else {
                assert_eq!(toolset.len(), MAX_HYPER_RATCHETS_IN_MEMORY);
                assert_eq!(toolset.get_oldest_hyper_ratchet_version(), COUNT - MAX_HYPER_RATCHETS_IN_MEMORY as u32);
            }
        }

        let _res = toolset.update_from(gen(COUNT).0).unwrap();
        assert_eq!(toolset.len(), MAX_HYPER_RATCHETS_IN_MEMORY + 1);
        assert_eq!(toolset.get_oldest_hyper_ratchet_version(), toolset.get_most_recent_hyper_ratchet_version() - MAX_HYPER_RATCHETS_IN_MEMORY as u32);

        toolset.deregister_oldest_hyper_ratchet(toolset.get_most_recent_hyper_ratchet_version() - MAX_HYPER_RATCHETS_IN_MEMORY as u32).unwrap();
        assert_eq!(toolset.len(), MAX_HYPER_RATCHETS_IN_MEMORY);
    }

    fn gen(cid: u64, version: u32, sec: SecurityLevel) -> (HyperRatchet, HyperRatchet) {
        let algorithm = 0;
        let mut alice = HyperRatchetConstructor::new_alice(Some(algorithm), cid, version, Some(sec));
        let bob = HyperRatchetConstructor::new_bob(algorithm, cid, version, alice.stage0_alice()).unwrap();
        alice.stage1_alice(bob.stage0_bob().unwrap()).unwrap();
        (alice.finish().unwrap(), bob.finish().unwrap())
    }

    #[test]
    fn toolset_wrapping_vers() {
        setup_log();
        let vers = u32::MAX - 1;
        let cid = 10;
        let hr = gen(cid, vers, SecurityLevel::LOW);
        let mut toolset = Toolset::new_debug(cid, hr.0, vers, vers);
        let r = toolset.get_hyper_ratchet(vers).unwrap();
        assert_eq!(r.version(), vers);

        const COUNT: usize  = 100;
        let mut insofar = 0;
        let mut cur_vers = vers.wrapping_add(1);
        loop {
            if insofar >= COUNT {
                break;
            }

            toolset.update_from(gen(cid,cur_vers, SecurityLevel::LOW).0).unwrap();
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
            toolset.deregister_oldest_hyper_ratchet(vers.wrapping_add(amt_culled)).unwrap();
            amt_culled += 1;
            assert_eq!(toolset.get_oldest_hyper_ratchet().unwrap().version(), vers.wrapping_add(amt_culled));
        }
    }

    #[test]
    fn scrambler_transmission() {
        setup_log();

        const SECURITY_LEVEL: SecurityLevel = SecurityLevel::LOW;
        const HEADER_SIZE_BYTES: usize = 44;

        let mut data = BytesMut::with_capacity(1000);
        let (ratchet_alice, ratchet_bob) = gen(10, 0, SECURITY_LEVEL);
        println!("Ratchet created. Creating PQC");

        // do 1000 for real tests on linux
        for x in 0..(1500 as usize) {
            data.put_u8((x % 256) as u8);
            let input_data = &data[..=x];

            //let input_data: &[u8] = include_bytes!("C:/Users/tbrau/input.txt");
            //let input_data = r#"Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved."#;
            //let input_data = b"Hello";

            let mut scramble_transmitter = par_scramble_encrypt_group(input_data, SECURITY_LEVEL, &ratchet_alice, HEADER_SIZE_BYTES, 0, 0, 0, |_vec, _drill, _target_cid, _, buffer| {
                for x in 0..HEADER_SIZE_BYTES {
                    buffer.put_u8(x as u8)
                }
            }).unwrap();

            let config = scramble_transmitter.get_receiver_config();
            let mut receiver = GroupReceiver::new(config.clone(), 0, 0);
            log::info!("{:?}", &config);

            while let Some(mut packet) = scramble_transmitter.get_next_packet() {
                //log::info!("Packet {} (wave id: {}) obtained and ready to transmit to receiver", packet.vector.true_sequence, packet.vector.wave_id);
                let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                let _result = receiver.on_packet_received(0, packet.vector.true_sequence, packet.vector.wave_id, &ratchet_bob, packet_payload);
                //println!("Wave {} result: {:?}", packet.vector.wave_id, result);
            }

            //println!("Possibly done with the descrambling/decryption process ... ");

            let decrypted_descrambled_plaintext = receiver.finalize();
            debug_assert_eq!(decrypted_descrambled_plaintext.as_slice(), input_data);
        }
        println!("Done");
    }

    #[test]
    fn simulate_packet_loss() {
        setup_log();
        let mut start_data = Vec::with_capacity(4 * 5000);
        for x in 0..5000i32 {
            for val in &x.to_be_bytes() {
                start_data.push(*val);
            }
        }

        for lvl in 0..=10 {
            let security_level: SecurityLevel = SecurityLevel::for_value(lvl).unwrap();

            let (alice_ratchet, bob_ratchet) = gen(10, 0, security_level);
            //let input_data: &[u8] = include_bytes!("/Users/nologik/Downloads/TheBridge.pdf");
            let input_data = &start_data[..];
            let now = Instant::now();
            let byte_len = input_data.len();

            const HEADER_SIZE_BYTES: usize = 50;

            let mut scramble_transmitter = scramble_encrypt_group(input_data, security_level, &alice_ratchet, HEADER_SIZE_BYTES, 0, 0, 0, |_vec, _drill, _target_cid, _obj_id, buffer| {
                for x in 0..HEADER_SIZE_BYTES {
                    buffer.put_u8(x as u8)
                }
            }).unwrap();

            let delta = now.elapsed();
            let rate = ((byte_len as f32) / (delta.as_secs_f32())) / 1_000_000f32;
            println!("[{:?}] Done cryptscrambling in {}ms (Rate: {}Mb/s)= {}/{}", security_level, delta.as_millis(), rate, byte_len, delta.as_secs_f32());
            let config = scramble_transmitter.get_receiver_config();
            println!("{:?}", &config);
            let mut receiver = GroupReceiver::new(config.clone(), 0, 0);

            let mut seq = 0;
            let now = Instant::now();
            let mut retransmission_resimulate_container = Vec::new();
            while let Some(mut packet) = scramble_transmitter.get_next_packet() {
                //log::info!("Packet {} (wave id: {}) obtained and ready to transmit to receiver", packet.vector.true_sequence, packet.vector.wave_id);

                // Don't transmit the 11, 12, 13, 14th packets to simulate packet loss
                if seq <= 1 || seq > 5 {
                    let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                    let _result = receiver.on_packet_received(packet.vector.group_id, packet.vector.true_sequence, packet.vector.wave_id, &bob_ratchet, packet_payload);
                    // println!("Wave {} result: {:?}", packet.vector.wave_id, result);
                } else {
                    retransmission_resimulate_container.push(packet);
                }

                seq += 1;
            }

            let delta = now.elapsed();
            let rate = ((byte_len as f32) / (delta.as_secs_f32())) / 1_000_000f32;
            println!("[{:?}] Done de-cryptscrambling in {}ms (Rate: {}Mb/s)= {}/{}", security_level, delta.as_millis(), rate, byte_len, delta.as_secs_f32());

            let packets_lost_vectors = receiver.get_retransmission_vectors_for(0, 0, &bob_ratchet).unwrap();
            debug_assert_eq!(packets_lost_vectors.len(), 4);

            // Simulate retransmission
            for mut packet in retransmission_resimulate_container.into_iter() {
                let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                let _result = receiver.on_packet_received(packet.vector.group_id, packet.vector.true_sequence, packet.vector.wave_id, &bob_ratchet, packet_payload);
            }

            println!("Possibly done with the descrambling/decryption process ...");

            let decrypted_descrambled_plaintext = receiver.finalize();
            debug_assert_eq!(decrypted_descrambled_plaintext.as_slice(), input_data);
        }
    }
}

/*
#[cfg(test)]
mod tests {
    #[test]
    fn encrypted_memory_compare() {
        let val = 100;
        let val2 = 101;
        let _ptr = &val as *const i32 as *const u8;
        let _ptr2 = &val2 as *const i32 as *const u8;

        let input = "Hello, world!";
        let _bytes = input.as_bytes();

        let (mut ema, key) = unsafe { EncryptedMemoryArtifact::new(input).unwrap() };
        let input_sec = SecVec::new(input.as_bytes().to_vec());
        let (status, new_key) = unsafe { ema.read_compare(key, input_sec) };
        assert!(status);
        let input_sec = SecVec::new(input.as_bytes().to_vec());
        let (status, _new_key) = unsafe { ema.read_compare(new_key, input_sec) };
        assert!(status);
    }
}
*/