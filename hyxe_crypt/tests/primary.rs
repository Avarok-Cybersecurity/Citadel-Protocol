#[cfg(test)]
mod tests {
    use hyxe_crypt::sec_string::SecString;
    use hyxe_crypt::sec_bytes::SecBuffer;
    use hyxe_crypt::toolset::Toolset;
    use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
    use hyxe_crypt::relay_chain::CryptoRelayChain;
    use std::iter::FromIterator;
    use bytes::{BufMut, BytesMut};
    use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "info");
        env_logger::init();
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
                let mut alice_hr = HyperRatchetConstructor::new_alice(None);
                let transfer = alice_hr.stage0_alice();
                let bob_hr = HyperRatchetConstructor::new_bob(0, 0, 0, transfer).unwrap();
                let transfer = bob_hr.stage0_bob().unwrap();
                alice_hr.stage1_alice(transfer).unwrap();
                let toolset = Toolset::new(cid, alice_hr.finish().unwrap());
                let container = PeerSessionCrypto::new(toolset);
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
            let (pqc, drill) = container.get_hyper_ratchet(None).unwrap().message_pqc_drill();
            let payload = acc.split_off(HEADER_LEN);
            drill.aes_gcm_decrypt(0, pqc, payload)
                .map(|vec| bytes::BytesMut::from(&vec[..])).unwrap()
        });

        assert_eq!(message, String::from_utf8(output.to_vec()).unwrap());
    }

    #[test]
    fn secstring() {
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
        assert_eq!(slice, &[0,0]);
    }

    #[test]
    fn secbytes() {
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
        assert_eq!(slice, &[0,0,0,0,0,0,0,0,0,0,0,0,0]);
    }

    #[test]
    fn hyper_ratchet() {
        let algorithm = Some(0);
        let mut alice_hyper_ratchet = HyperRatchetConstructor::new_alice(algorithm);
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

        alice_hyper_ratchet.protect_message_packet(HEADER_LEN, &mut packet).unwrap();
        assert_ne!(packet, plaintext_packet);

        let mut header = packet.split_to(HEADER_LEN);
        bob_hyper_ratchet.validate_message_packet(&header[..], &mut packet).unwrap();

        header.unsplit(packet);

        assert_eq!(header, plaintext_packet);
    }

    #[test]
    fn toolset() {
        setup_log();
        fn gen(drill_vers: u32) -> (HyperRatchet, HyperRatchet) {
            let mut alice_base = HyperRatchetConstructor::new_alice(None);
            let bob_base = HyperRatchetConstructor::new_bob(0, 0, drill_vers, alice_base.stage0_alice()).unwrap();
            alice_base.stage1_alice(bob_base.stage0_bob().unwrap()).unwrap();

            (alice_base.finish().unwrap(), bob_base.finish().unwrap())
        }

        let (alice, _bob) = gen(0);

        let mut toolset = Toolset::new(0, alice);

        for x in 1..100 {
            assert!(toolset.update_from(gen(x).0).is_some());
        }
    }
}
/*#![feature(const_fn, slice_from_raw_parts)]
/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

pub mod prelude {
    pub use std::time::Instant;

    pub use std::ops::DerefMut;

    pub use hyxe_crypt::prelude::*;
    pub use futures::executor::block_on;
    pub use zerocopy::AsBytes;

    pub use crate::ORIGINAL_TEXT;
}

pub const ORIGINAL_TEXT: &[u8] = b"Hello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a testHello World! This is a test";


#[cfg(test)]
mod tests {

    mod post_quantum {
        use zerocopy::AsBytes;
        use ez_pqcrypto::prelude::*;
        use crate::ORIGINAL_TEXT;

        #[test]
        fn test_post_quantum() {
            /*
            let mut alice_package = PostQuantumAlgorithmData_babybear::new_alice();
            let bob_package = PostQuantumAlgorithmData_babybear::new_bob(alice_package.get_public_key());
            alice_package.alice_on_receive_ciphertext(bob_package.get_ciphertext());

            let mut output_alice = BytesMut::new();

            alice_package.encrypt_data(ORIGINAL_TEXT, &mut output_alice);
            //println!("Orig len: {}\nEncrypted len: {}", ORIGINAL_TEXT.len(), output_alice.len());
            //for (byte0, byte1) in ORIGINAL_TEXT.iter().zip(output_alice.as_bytes().iter()) {
                //println!("Orig: {}, Enc: {}", byte0, byte1);
            //}

            let mut output_bob = BytesMut::new();
            bob_package.decrypt_data(output_alice.as_bytes(), &mut output_bob);
            //println!("Orig len: {}\nEncrypted len: {}", ORIGINAL_TEXT.len(), output_bob.len());
            assert_eq!(ORIGINAL_TEXT, output_bob.as_bytes());
            */
        }
    }

    /**/

    use std::time::Instant;

    use hyxe_crypt::encrypted_memory_artifact::EncryptedMemoryArtifact;
    use hyxe_crypt::misc::{mlock, munlock};
    use secstr::SecVec;
    use futures::executor::block_on;
    use crate::prelude::Drill;
    use hyxe_crypt::drill_algebra::{PacketVector, generate_packet_vector, generate_packet_coordinates_inv};
    use std::ops::Deref;
    use crate::ORIGINAL_TEXT;
    use bytes::{BytesMut, Buf, BufMut, Bytes};
    use zerocopy::AsBytes;
    use hyxe_crypt::drill::SecurityLevel;
    use aead::Buffer;
    use hyxe_crypt::prelude::{algorithm_dictionary, PostQuantumContainer};
    use hyxe_crypt::net::crypt_splitter::{scramble_encrypt_group, GroupReceiver, GroupReceiverStatus, par_scramble_encrypt_group, par_encrypt_group_unified};
    use as_slice::AsSlice;
    use hyxe_crypt::toolset::Toolset;
    use hyxe_crypt::drill_update::generate_offset_map;

    #[test]
    fn serde_toolset() {
        let mut toolset = Toolset::new(0).unwrap();

        let ser = toolset.serialize_to_vec().unwrap();
        println!("Serialized size: {}", ser.len());
    }

    #[test]
    fn serde_drill() {
        let drill = Drill::new(0, 0).unwrap();
        let offset_map = generate_offset_map(&drill);
        // there's an implicit debug_assert in the function above to validate the port mapping differential mechanism
        let ser = drill.serialize_to_vec().unwrap();
        println!("Serialized size: {}", ser.len());
    }

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

    #[test]
    fn pid_wid_test() {
        block_on(async {
            Drill::new(101, 0)
        }).and_then(|ref drill| {
            for input in 0..1000 {
                let coordinates = generate_packet_vector(input, 0, drill);
                println!("Packet coordinates: -> WID: {} | Local Port: {} | Remote Port: {}", coordinates.wave_id, coordinates.local_port, coordinates.remote_port);
                let recovered_index = generate_packet_coordinates_inv(coordinates.wave_id, coordinates.local_port, coordinates.remote_port, drill).unwrap();
                println!("Recovered index {}", recovered_index);
                assert_eq!(recovered_index, input);
            }
            Ok(())
        }).unwrap();
    }

    #[test]
    fn aes_gcm() {
        use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
        use aead::{Aead, NewAead};
        use aead::generic_array::{GenericArray, typenum::U128};
        use aead::heapless::Vec;
        use ez_pqcrypto::prelude::*;

        let algorithm = algorithm_dictionary::FIRESABER;
        // Alice wants to share data with Bob. She first creates a PostQuantumContainer
        let mut alice_container = PostQuantumContainer::new_alice(Some(algorithm));
        // Then, alice sends her public key to Bob. She must also send the byte value of algorithm_dictionary::BABYBEAR to him
        let alice_public_key = alice_container.get_public_key();
        let algorithm_byte_value = alice_container.get_algorithm_idx();
        //
        // Then, Bob gets the public key. To process it, he must create a PostQuantumContainer for himself
        let bob_container = PostQuantumContainer::new_bob(algorithm_byte_value, alice_public_key).unwrap();
        // Internally, this computes the CipherText. The next step is to send this CipherText back over to alice
        let bob_ciphertext = bob_container.get_ciphertext().unwrap();
        //
        // Next, alice received Bob's ciphertext. She must now run an update on her internal data in order to get the shared secret
        alice_container.alice_on_receive_ciphertext(bob_ciphertext).unwrap();

        assert_eq!(alice_container.get_shared_secret().unwrap(), bob_container.get_shared_secret().unwrap());

        let key = GenericArray::clone_from_slice(alice_container.get_shared_secret().unwrap());
        let aead = Aes256Gcm::new(key);

        let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message

        let mut original_message = format!("");
        let original_message = &mut original_message;

        for x in 0..30 {
            *original_message = format!("{}{}", original_message.clone(), x % 10);
            //let mut buffer: Vec<u8, U128> = Vec::new();
            //buffer.extend_from_slice(original_message.as_bytes());

            println!("Encrypting data!");
            let buffer = aead.encrypt(nonce, original_message.as_bytes()).expect("encryption failure!");

            let buffer_plaintext = original_message.clone();
            println!("Plaintext length: {}", buffer_plaintext.len());
            let _buffer_ciphertext = String::from_utf8_lossy((buffer.as_ref()));
            println!("Ciphertext len: {}", buffer.len());

            assert_ne!(buffer.as_bytes(), original_message.as_bytes());
            println!("Decrypting data!");
            println!("__________________________");

            let decrypted = aead.decrypt(nonce, buffer.as_bytes()).expect("decryption failure!");
            assert_eq!(decrypted.as_bytes(), original_message.as_bytes());
        }

    }

    fn create_post_quantum_container() -> PostQuantumContainer {
        use ez_pqcrypto::prelude::*;

        let algorithm = algorithm_dictionary::FIRESABER;
        // Alice wants to share data with Bob. She first creates a PostQuantumContainer
        let mut alice_container = PostQuantumContainer::new_alice(Some(algorithm));
        // Then, alice sends her public key to Bob. She must also send the byte value of algorithm_dictionary::BABYBEAR to him
        let alice_public_key = alice_container.get_public_key();
        let algorithm_byte_value = alice_container.get_algorithm_idx();
        //
        // Then, Bob gets the public key. To process it, he must create a PostQuantumContainer for himself
        let bob_container = PostQuantumContainer::new_bob(algorithm_byte_value, alice_public_key).unwrap();
        // Internally, this computes the CipherText. The next step is to send this CipherText back over to alice
        let bob_ciphertext = bob_container.get_ciphertext().unwrap();
        //
        // Next, alice received Bob's ciphertext. She must now run an update on her internal data in order to get the shared secret
        alice_container.alice_on_receive_ciphertext(bob_ciphertext).unwrap();

        assert_eq!(alice_container.get_shared_secret().unwrap(), bob_container.get_shared_secret().unwrap());
        alice_container
    }

    #[test]
    fn scrambler_transmission() {
        std::env::set_var("RUST_LOG", "hyxe_crypt=info");
        env_logger::init();
            let mut data = BytesMut::with_capacity(1000);
            let drill = Drill::new(101, 0).unwrap();
            println!("Drill created. Creating PQC");
            let pqc = create_post_quantum_container();
            log::info!("PQC created");

        // do 1000 for real tests on linux
            for x in 0..(1000 as usize) {
                data.put_u8((x % 256) as u8);
                let input_data = &data[..=x];

                //let input_data: &[u8] = include_bytes!("C:/Users/tbrau/input.txt");
                //let input_data = r#"Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved."#;
                //let input_data = b"Hello";
                const SECURITY_LEVEL: SecurityLevel = SecurityLevel::DIVINE;
                const HEADER_SIZE_BYTES: usize = 44;

                let mut scramble_transmitter = scramble_encrypt_group(input_data, SECURITY_LEVEL, &drill, &pqc,HEADER_SIZE_BYTES, 0,0, 0,|_vec, _drill, _target_cid, _, buffer| {
                    for x in 0..HEADER_SIZE_BYTES {
                        buffer.put_u8(x as u8)
                    }
                }).unwrap();

                let config = scramble_transmitter.get_receiver_config();
                let mut receiver = GroupReceiver::new(config.clone(), &drill, 0, 0);
                log::info!("{:?}", &config);

                while let Some(mut packet) = scramble_transmitter.get_next_packet() {
                    //log::info!("Packet {} (wave id: {}) obtained and ready to transmit to receiver", packet.vector.true_sequence, packet.vector.wave_id);
                    let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                    let result = receiver.on_packet_received(packet.vector.true_sequence, packet.vector.wave_id, &drill, &pqc, packet_payload);
                    //println!("Wave {} result: {:?}", packet.vector.wave_id, result);
                }

                //println!("Possibly done with the descrambling/decryption process ... ");

                let decrypted_descrambled_plaintext = receiver.finalize();
                debug_assert_eq!(decrypted_descrambled_plaintext.as_slice(), input_data.as_bytes());
            }
        println!("Done");
    }

    #[test]
    fn scrambler_transmission_unified() {
        std::env::set_var("RUST_LOG", "hyxe_crypt=info");
        env_logger::init();
        let mut data = BytesMut::with_capacity(1000);
        let drill = Drill::new(101, 0).unwrap();
        println!("Drill created. Creating PQC");
        let pqc = create_post_quantum_container();
        log::info!("PQC created");

        // do 1000 for real tests on linux
        for x in 0..(1000 as usize) {
            data.put_u8((x % 256) as u8);
            let input_data = &data[..=x];

            //let input_data: &[u8] = include_bytes!("C:/Users/tbrau/input.txt");
            //let input_data = r#"Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved.Please read the "legal small print," and other information about the eBook and Project Gutenberg at the bottom of this file.  Included isimportant information about your specific rights and restrictions inhow the file may be used.  You can also find out about how to make adonation to Project Gutenberg, and how to get involved."#;
            //let input_data = b"Hello";
            const SECURITY_LEVEL: SecurityLevel = SecurityLevel::DIVINE;
            const HEADER_SIZE_BYTES: usize = 44;

            let mut scramble_transmitter = par_encrypt_group_unified(input_data, &drill, &pqc,HEADER_SIZE_BYTES, 0,0, 0,|_vec, _drill, _target_cid, _, buffer| {
                for x in 0..HEADER_SIZE_BYTES {
                    buffer.put_u8(x as u8)
                }
            }).unwrap();

            let config = scramble_transmitter.get_receiver_config();
            let mut receiver = GroupReceiver::new(config.clone(), &drill, 0, 0);
            log::info!("{:?}", &config);

            while let Some(mut packet) = scramble_transmitter.get_next_packet() {
                //log::info!("Packet {} (wave id: {}) obtained and ready to transmit to receiver", packet.vector.true_sequence, packet.vector.wave_id);
                let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                let result = receiver.on_packet_received(packet.vector.true_sequence, packet.vector.wave_id, &drill, &pqc, packet_payload);
                //println!("Wave {} result: {:?}", packet.vector.wave_id, result);
            }

            //println!("Possibly done with the descrambling/decryption process ... ");

            let decrypted_descrambled_plaintext = receiver.finalize();
            debug_assert_eq!(decrypted_descrambled_plaintext.as_slice(), input_data.as_bytes());
        }
        println!("Done");
    }

    #[test]
    fn simulate_packet_loss() {
        std::env::set_var("RUST_LOG", "info");
        env_logger::init();
        block_on(async {
            for lvl in 0..=4 {
                let drill = Drill::new(101, 0).unwrap();
                println!("Drill created. Creating PQC");
                let pqc = create_post_quantum_container();
                log::info!("PQC created!");

                let input_data: &[u8] = include_bytes!("C:\\Users\\tbrau\\pic.jpg");
                let now = Instant::now();
                let byte_len = input_data.len();
                //let input_data = b"Hello, world!";
                let SECURITY_LEVEL: SecurityLevel = SecurityLevel::for_value(lvl).unwrap();

                const HEADER_SIZE_BYTES: usize = 50;

                let mut scramble_transmitter = par_scramble_encrypt_group(input_data, SECURITY_LEVEL, &drill, &pqc,HEADER_SIZE_BYTES, 0,0, 0,|_vec, _drill, _target_cid, _obj_id, buffer| {
                    for x in 0..HEADER_SIZE_BYTES {
                        buffer.put_u8(x as u8)
                    }
                }).unwrap();
                let delta = now.elapsed();
                let rate = ((byte_len as f32)/(delta.as_secs_f32()))/1_000_000f32;
                println!("[{:?}] Done cryptscrambling in {}ms (Rate: {}Mb/s)= {}/{}", SECURITY_LEVEL, delta.as_millis(), rate, byte_len, delta.as_secs_f32());
                let config = scramble_transmitter.get_receiver_config();
                let mut receiver = GroupReceiver::new(config.clone(), &drill, 0, 0);
                log::info!("{:?}", &config);

                let mut seq = 0;
                let now = Instant::now();
                while let Some(mut packet) = scramble_transmitter.get_next_packet() {
                    //log::info!("Packet {} (wave id: {}) obtained and ready to transmit to receiver", packet.vector.true_sequence, packet.vector.wave_id);

                    // Don't transmit the 11, 12, 13, 14th packets to simulate packet loss
                    //if seq <= 10 || seq >= 15 {
                    let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                    let result = receiver.on_packet_received(packet.vector.true_sequence, packet.vector.wave_id, &drill, &pqc, packet_payload);
                    // println!("Wave {} result: {:?}", packet.vector.wave_id, result);
                    // } else {
                    //    retransmission_resimulate_container.push(packet);
                    //}

                    seq += 1;
                }

                let delta = now.elapsed();
                let rate = ((byte_len as f32)/(delta.as_secs_f32()))/1_000_000f32;
                println!("[{:?}] Done de-cryptscrambling in {}ms (Rate: {}Mb/s)= {}/{}", SECURITY_LEVEL, delta.as_millis(), rate, byte_len, delta.as_secs_f32());

                /*
                let packets_lost_vectors = receiver.get_retransmission_vectors_for(0, 0, &drill).unwrap();
                debug_assert_eq!(packets_lost_vectors.len(), 4);

                // Simulate retransmission
                for mut packet in retransmission_resimulate_container.into_iter() {
                    let packet_payload = packet.packet.split_off(HEADER_SIZE_BYTES);
                    let _result = receiver.on_packet_received(packet.vector.true_sequence, packet.vector.wave_id, &drill, &pqc, packet_payload);
                }*/

                println!("Possibly done with the descrambling/decryption process ...");

                let decrypted_descrambled_plaintext = receiver.finalize();
                debug_assert_eq!(decrypted_descrambled_plaintext.as_slice(), input_data);
            }
        });
    }

    #[test]
    fn serialize_deserialize_toolset() {
        block_on( async {
            let mut toolset = Toolset::new(0).unwrap();
            let serialized = toolset.serialize_to_vec().unwrap();
            let _deserialized = Toolset::deserialize_from_bytes(serialized).unwrap();
        });
    }
}
*/