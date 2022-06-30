#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use rand::prelude::ThreadRng;
    use rand::RngCore;

    use ez_pqcrypto::PostQuantumContainer;
    use ez_pqcrypto::bytes_in_place::EzBuffer;
    use ez_pqcrypto::replay_attack_container::unordered::HISTORY_LEN;
    use ez_pqcrypto::algorithm_dictionary::{KemAlgorithm, EncryptionAlgorithm, KEM_ALGORITHM_COUNT};
    use enum_primitive::FromPrimitive;
    use std::iter::FromIterator;
    use std::convert::TryFrom;
    use ez_pqcrypto::constructor_opts::ConstructorOpts;

    fn gen(kem_algorithm: KemAlgorithm, encryption_algorithm: EncryptionAlgorithm) -> (PostQuantumContainer, PostQuantumContainer) {
        log::trace!(target: "lusna", "Test algorithm {:?} w/ {:?}", kem_algorithm, encryption_algorithm);
        let mut alice_container = PostQuantumContainer::new_alice(ConstructorOpts::new_init(Some(kem_algorithm + encryption_algorithm))).unwrap();
        let bob_container = PostQuantumContainer::new_bob(ConstructorOpts::new_init(Some(kem_algorithm + encryption_algorithm)), alice_container.get_public_key()).unwrap();
        alice_container.alice_on_receive_ciphertext(bob_container.get_ciphertext().unwrap()).unwrap();
        (alice_container, bob_container)
    }

    #[test]
    fn runit() {
        run(0, EncryptionAlgorithm::AES_GCM_256_SIV).unwrap();
        run(0, EncryptionAlgorithm::Xchacha20Poly_1305).unwrap()
    }

    fn run(algorithm: u8, encryption_algorithm: EncryptionAlgorithm) -> Result<(), Box<dyn std::error::Error>> {
        let kem_algorithm = KemAlgorithm::from_u8(algorithm).unwrap();
        log::trace!(target: "lusna", "Test: {:?} w/ {:?}", kem_algorithm, encryption_algorithm);
        // Alice wants to share data with Bob. She first creates a PostQuantumContainer
        let mut alice_container = PostQuantumContainer::new_alice(ConstructorOpts::new_init(Some(kem_algorithm + encryption_algorithm))).unwrap();
        // Then, alice sends her public key to Bob. She must also send the byte value of algorithm_dictionary::BABYBEAR to him
        let alice_public_key = alice_container.get_public_key();
        //
        // Then, Bob gets the public key. To process it, he must create a PostQuantumContainer for himself
        let bob_container = PostQuantumContainer::new_bob(ConstructorOpts::new_init(Some(kem_algorithm + encryption_algorithm)), alice_public_key)?;
        let eve_container = PostQuantumContainer::new_bob(ConstructorOpts::new_init(Some(kem_algorithm + encryption_algorithm)), alice_public_key)?;
        // Internally, this computes the CipherText. The next step is to send this CipherText back over to alice
        let bob_ciphertext = bob_container.get_ciphertext().unwrap();
        let _eve_ciphertext = eve_container.get_ciphertext().unwrap();
        //
        // Next, alice received Bob's ciphertext. She must now run an update on her internal data in order to get the shared secret
        alice_container.alice_on_receive_ciphertext(bob_ciphertext).unwrap();

        let alice_ss = alice_container.get_shared_secret().unwrap();
        let bob_ss = bob_container.get_shared_secret().unwrap();
        let eve_ss = eve_container.get_shared_secret().unwrap();

        assert_eq!(alice_ss, bob_ss);
        assert_ne!(eve_ss, alice_ss);
        assert_ne!(eve_ss, bob_ss);

        let plaintext = b"Hello, world!";
        let nonce = &Vec::from_iter(0..(encryption_algorithm.nonce_len()) as u8);

        let mut ciphertext = alice_container.encrypt(plaintext, nonce).unwrap();
        let mut ptr = &mut ciphertext[..];

        //let decrypted = bob_container.decrypt(ciphertext, nonce).unwrap();
        let decrypted_len = bob_container.decrypt_in_place(&mut ptr, nonce).unwrap();

        debug_assert_eq!(plaintext, &ptr[..decrypted_len]);
        Ok(())
    }

    #[test]
    fn in_place_sequential() {
        const HEADER_LEN: usize = 50;
        const TOTAL_LEN: usize = HEADER_LEN;

        let kem_algorithm = KemAlgorithm::Firesaber;
        let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256_SIV;
        let nonce_len = encryption_algorithm.nonce_len();
        let (alice_container, bob_container) = gen(kem_algorithm, encryption_algorithm);

        let mut buf = BytesMut::with_capacity(TOTAL_LEN);
        for x in 0..TOTAL_LEN {
            buf.put_u8(x as u8);
        }

        log::trace!(target: "lusna", "[ {} ] {:?}", buf.len(), &buf[..]);
        let nonce = Vec::from_iter(0..nonce_len as u8);
        alice_container.protect_packet_in_place(HEADER_LEN, &mut buf, &nonce).unwrap();

        log::trace!(target: "lusna", "[ {} ] {:?}", buf.len(), &buf[..]);
        let mut header = buf.split_to(HEADER_LEN);
        bob_container.validate_packet_in_place(&header, &mut buf, &nonce).unwrap();
        header.unsplit(buf);
        let buf = header;

        log::trace!(target: "lusna", "[ {} ] {:?}", buf.len(), &buf[..]);
    }

    #[test]
    // this will work in ordered mode, but panic in unordered
    #[cfg(not(feature = "unordered"))]
    fn in_place_out_of_order() {
        const HEADER_LEN: usize = 50;
        const TOTAL_LEN: usize = HEADER_LEN + 150;

        let kem_algorithm = KemAlgorithm::Firesaber;
        let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256_SIV;
        let (alice_container, bob_container) = gen(kem_algorithm, encryption_algorithm);

        for y in 0..1 {
            log::trace!(target: "lusna", "At {}", y);
            let mut buf = BytesMut::with_capacity(TOTAL_LEN);
            for x in 0..TOTAL_LEN {
                buf.put_u8(x as u8);
            }

            let mut buf2 = buf.clone();

            log::trace!(target: "lusna", "[ {} ] {:?}", buf.len(), &buf[..]);
            let nonce: [u8; NONCE_LENGTH_BYTES] = Default::default();
            alice_container.protect_packet_in_place(HEADER_LEN, &mut buf, &nonce).unwrap();
            alice_container.protect_packet_in_place(HEADER_LEN, &mut buf2, &nonce).unwrap();

            // pretend someone grabs the header + ciphertext
            let mut intercepted_packet = buf.clone();

            // to simulate out-of order delivery, protect a new packet in place and validate that one
            log::trace!(target: "lusna", "[ {} ] {:?}", buf2.len(), &buf2[..]);
            let header2 = buf2.split_to(HEADER_LEN);
            assert!(bob_container.validate_packet_in_place(&header2, &mut buf2, &nonce).is_err());
            // now do them in order

            let mut header = buf.split_to(HEADER_LEN);
            bob_container.validate_packet_in_place(&header, &mut buf, &nonce).unwrap();
            // since we are using in-place decryption, the first attempt will corrupt the payload, thus invalidating the packet's
            // decryption operation, even though it may correct. As such, this proves it is NECESSARY that packets
            // arrive IN-ORDER!!
            assert!(bob_container.validate_packet_in_place(&header2, &mut buf2, &nonce).is_err());
            // now, let's see what happens when we try validating the intercepted packet (replay attack)
            let intercepted_header = intercepted_packet.split_to(HEADER_LEN);
            assert!(bob_container.validate_packet_in_place(&intercepted_header, &mut intercepted_packet, &nonce).is_err());
            // Therefore: packets MUST be in order, and repeat attempts will invalidate the decryption attempt, as desired
            header.unsplit(buf);
            let buf = header;

            log::trace!(target: "lusna", "[ {} ] {:?}", buf.len(), &buf[..]);
        }
    }

    #[test]
    // this will work in ordered mode, but panic in unordered
    #[cfg(feature = "unordered")]
    fn in_place_out_of_order_for_unordered_mode() {
        const HEADER_LEN: usize = 50;
        const TOTAL_LEN: usize = HEADER_LEN + 150;

        let kem_algorithm = KemAlgorithm::Firesaber;
        let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256_SIV;
        let nonce_len = encryption_algorithm.nonce_len() as u8;
        let (alice_container, bob_container) = gen(kem_algorithm, encryption_algorithm);
        let mut zeroth = Vec::<u8>::default();
        let mut zeroth_nonce = Vec::<u8>::from_iter(0..nonce_len);
        for y in 0..(HISTORY_LEN + 10) {
            let mut buf = Vec::with_capacity(TOTAL_LEN);
            for x in 0..TOTAL_LEN {
                buf.put_u8(x as u8);
            }

            let mut buf2 = buf.clone();

            log::trace!(target: "lusna", "[{} @ {} ] {:?}", y, buf.len(), &buf[..]);
            let nonce = vec![0; 12];
            alice_container.protect_packet_in_place(HEADER_LEN, &mut buf, &nonce).unwrap();
            alice_container.protect_packet_in_place(HEADER_LEN, &mut buf2, &nonce).unwrap();

            // pretend someone grabs the header + ciphertext
            let mut intercepted_packet = buf.clone();
            if y == 0 {
                zeroth = intercepted_packet.clone();
                zeroth_nonce = nonce.clone();
            }

            // to simulate out-of order delivery, protect a new packet in place and validate that one
            log::trace!(target: "lusna", "[{} @ {} ] {:?}", y, buf2.len(), &buf2[..]);
            let header2 = buf2.split_to(HEADER_LEN);
            assert!(bob_container.validate_packet_in_place(&header2, &mut buf2, &nonce).is_ok());
            // now do them in order

            let mut header = buf.split_to(HEADER_LEN);
            bob_container.validate_packet_in_place(&header, &mut buf, &nonce).unwrap();
            // since we are using in-place decryption, the first attempt will corrupt the payload, thus invalidating the packet's
            // decryption operation, even though it may correct. As such, this proves it is NECESSARY that packets
            // arrive IN-ORDER!!
            assert!(bob_container.validate_packet_in_place(&header2, &mut buf2, &nonce).is_err());
            // now, let's see what happens when we try validating the intercepted packet (replay attack)
            let intercepted_header = intercepted_packet.split_to(HEADER_LEN);
            assert!(bob_container.validate_packet_in_place(&intercepted_header, &mut intercepted_packet, &nonce).is_err());
            // Therefore: packets MUST be in order, and repeat attempts will invalidate the decryption attempt, as desired
            header.unsplit(buf);
            let buf = header;

            log::trace!(target: "lusna", "[{} @ {} ] {:?}", y, buf.len(), &buf[..]);
        }
        let header = zeroth.split_to(HEADER_LEN);
        assert!(bob_container.validate_packet_in_place(header, &mut zeroth, zeroth_nonce).is_err());
    }

    #[test]
    #[cfg(feature = "unordered")]
    fn unordered_mode() {
        const HEADER_LEN: usize = 50;
        const TOTAL_LEN: usize = HEADER_LEN + 150;

        lusna_logging::setup_log();

        let kem_algorithm = KemAlgorithm::Firesaber;
        let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256_SIV;
        let nonce_len = encryption_algorithm.nonce_len();
        let (alice_container, bob_container) = gen(kem_algorithm, encryption_algorithm);

        let mut packet0 = (0..TOTAL_LEN as u8).into_iter().collect::<Vec<u8>>();
        let nonce = Vec::from_iter(0..nonce_len as u8);
        // encrypt the packet, but don't verify it
        alice_container.protect_packet_in_place(HEADER_LEN, &mut packet0, &nonce).unwrap();
        // In theory, in unordered mode, we don't have to verify packet0 before HISTORY_LEN+1 packets
        for _y in 0..HISTORY_LEN+10 {
            let mut packet_n = (0..TOTAL_LEN as u8).into_iter().collect::<Vec<u8>>();
            alice_container.protect_packet_in_place(HEADER_LEN, &mut packet_n, &nonce).unwrap();
            let header = packet_n.split_to(HEADER_LEN);
            bob_container.validate_packet_in_place(&header, &mut packet_n, &nonce).unwrap();
        }

        let header = packet0.split_to(HEADER_LEN);
        assert!(alice_container.validate_packet_in_place(&header, &mut packet0, &nonce).is_err());
    }

    /*
    #[test]
    // for asymmetric crypto (public crypto)
    fn signing() {
        use pqcrypto::traits::sign::SignedMessage;

        let (public_key, secret_key) = pqcrypto::sign::falcon512::keypair();
        let message = b"Hello, world!";
        let signed_message = pqcrypto::sign::falcon512::sign(message, &secret_key);
        let signed_message = signed_message.as_bytes();
        debug_assert_ne!(signed_message, message);

        log::trace!(target: "lusna", "Unsigned len: {}\nSigned len: {}", message.len(), signed_message.len());

        let signed_message_received = pqcrypto::sign::falcon512::SignedMessage::from_bytes(signed_message).unwrap();
        let opened_message = pqcrypto::sign::falcon512::open(&signed_message_received, &public_key).unwrap();
        debug_assert_eq!(opened_message.as_slice(), message);
    }*/

    #[test]
    fn test_all_kems() {
        lusna_logging::setup_log();
        for algorithm in 0..KEM_ALGORITHM_COUNT {
            log::trace!(target: "lusna", "About to test {:?}", KemAlgorithm::try_from(algorithm).unwrap());
            run(algorithm, EncryptionAlgorithm::AES_GCM_256_SIV).unwrap();
            run(algorithm, EncryptionAlgorithm::Xchacha20Poly_1305).unwrap();
        }
    }

    #[test]
    fn parse() {
        assert_eq!(KemAlgorithm::Kyber1024_90s, KemAlgorithm::try_from(5).unwrap());
    }

    #[test]
    fn test_serialize_deserialize() {
        lusna_logging::setup_log();
        let kem_algorithm = KemAlgorithm::Kyber1024_90s;
        let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256_SIV;
        let (alice_container, bob_container) = gen(kem_algorithm, encryption_algorithm);

        let nonce = &mut [0u8; 12];
        ThreadRng::default().fill_bytes(nonce);
        let msg = "hello, world!";

        let enc = alice_container.encrypt(msg, &nonce).unwrap();
        let enc2 = bob_container.encrypt(msg, &nonce).unwrap();

        let _ = bob_container.decrypt(&enc, &nonce).unwrap();
        let _ = alice_container.decrypt(&enc2, &nonce).unwrap();

        let al_pub0 = alice_container.get_public_key();
        let al_ss0 = alice_container.get_shared_secret().unwrap();
        let al_secr0 = alice_container.get_secret_key().unwrap();

        let bob_pub0 = bob_container.get_public_key();
        let bob_ss0 = bob_container.get_shared_secret().unwrap();
        //let _bob_secr0 = bob_container.get_secret_key().unwrap();

        let serialized_alice = alice_container.serialize_to_vector().unwrap();
        let pqq_alice = PostQuantumContainer::deserialize_from_bytes(&serialized_alice).unwrap();

        let serialized_bob = bob_container.serialize_to_vector().unwrap();
        let pqq_bob = PostQuantumContainer::deserialize_from_bytes(&serialized_bob).unwrap();

        let al_pub1 = pqq_alice.get_public_key();
        let al_ss1 = pqq_alice.get_shared_secret().unwrap();
        let al_secr1 = pqq_alice.get_secret_key().unwrap();

        let bob_pub1 = pqq_bob.get_public_key();
        let bob_ss1 = pqq_bob.get_shared_secret().unwrap();

        assert_eq!(al_pub0, al_pub1);
        assert_eq!(al_ss0, al_ss1);
        assert_eq!(al_secr0, al_secr1);

        assert_eq!(bob_pub0, bob_pub1);
        assert_eq!(bob_ss0, bob_ss1);

        //assert_ne!(al_pub0, bob_pub0);
        assert_eq!(bob_ss1, al_ss1);

        let _decr_alice = bob_container.decrypt(&enc, &nonce).unwrap();
        let _decr_bob = alice_container.decrypt(&enc2, &nonce).unwrap();

        // now, try out the serialized versions
        let decr_alice = pqq_bob.decrypt(&enc, &nonce).unwrap();
        let decr_bob = pqq_alice.decrypt(&enc2, &nonce).unwrap();

        assert_eq!(decr_alice, decr_bob);
    }
}