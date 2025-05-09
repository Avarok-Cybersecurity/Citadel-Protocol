#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use citadel_io::ThreadRng;
    use rand::RngCore;

    use citadel_logging::setup_log;
    use citadel_pqcrypto::bytes_in_place::EzBuffer;
    use citadel_pqcrypto::constructor_opts::ConstructorOpts;
    use citadel_pqcrypto::replay_attack_container::HISTORY_LEN;
    use citadel_pqcrypto::{EncryptionAlgorithmExt, PostQuantumContainer};
    use citadel_types::crypto::{
        AlgorithmsExt, CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SigAlgorithm,
    };
    use citadel_types::utils::validate_crypto_params;
    use std::convert::TryFrom;
    use std::fmt::Debug;
    use std::iter::FromIterator;

    lazy_static::lazy_static! {
        pub static ref PRE_SHARED_KEYS: Vec<Vec<u8>> = vec!["Hello".into(), "World".into()];
        pub static ref PRE_SHARED_KEYS2: Vec<Vec<u8>> = vec!["World".into(), "Hello".into()];
    }

    fn gen<T: AsRef<[u8]>, R: AsRef<[u8]>>(
        kem_algorithm: KemAlgorithm,
        encryption_algorithm: EncryptionAlgorithm,
        sig_alg: SigAlgorithm,
        bob_psks: &[T],
        alice_psks: &[R],
    ) -> (PostQuantumContainer, PostQuantumContainer) {
        log::trace!(target: "citadel", "Test algorithm {:?} w/ {:?}", kem_algorithm, encryption_algorithm);
        let mut alice_container = PostQuantumContainer::new_alice(ConstructorOpts::new_init(Some(
            kem_algorithm + encryption_algorithm + sig_alg,
        )))
        .unwrap();

        let tx_params = alice_container.generate_alice_to_bob_transfer().unwrap();
        let bob_container = PostQuantumContainer::new_bob(
            ConstructorOpts::new_init(Some(kem_algorithm + encryption_algorithm + sig_alg)),
            tx_params,
            bob_psks,
        )
        .unwrap();

        let tx_params = bob_container.generate_bob_to_alice_transfer().unwrap();
        alice_container
            .alice_on_receive_ciphertext(tx_params, alice_psks)
            .unwrap();
        (alice_container, bob_container)
    }

    #[test]
    fn runit() {
        run::<Vec<u8>>(
            0,
            EncryptionAlgorithm::AES_GCM_256,
            SigAlgorithm::None,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS,
        )
        .unwrap();
        run::<Vec<u8>>(
            0,
            EncryptionAlgorithm::ChaCha20Poly_1305,
            SigAlgorithm::None,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS,
        )
        .unwrap();
        run::<Vec<u8>>(
            0,
            EncryptionAlgorithm::Ascon80pq,
            SigAlgorithm::None,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS,
        )
        .unwrap();
    }

    fn run<T: AsRef<[u8]>>(
        algorithm: u8,
        encryption_algorithm: EncryptionAlgorithm,
        signature_algorithm: SigAlgorithm,
        bob_psk: &[T],
        alice_psk: &[T],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let kem_algorithm = KemAlgorithm::from_u8(algorithm).unwrap();
        log::trace!(target: "citadel", "Test: {:?} w/ {:?} w/ {:?}", kem_algorithm, encryption_algorithm, signature_algorithm);
        // Alice wants to share data with Bob. She first creates a PostQuantumContainer
        let mut alice_container = PostQuantumContainer::new_alice(ConstructorOpts::new_init(Some(
            kem_algorithm + encryption_algorithm + signature_algorithm,
        )))
        .unwrap();
        // Then, alice sends her public key to Bob. She must also send the byte value of algorithm_dictionary::BABYBEAR to him
        let tx_params = alice_container.generate_alice_to_bob_transfer().unwrap();
        //
        // Then, Bob gets the public key. To process it, he must create a PostQuantumContainer for himself
        let bob_container = PostQuantumContainer::new_bob(
            ConstructorOpts::new_init(Some(
                kem_algorithm + encryption_algorithm + signature_algorithm,
            )),
            tx_params.clone(),
            bob_psk,
        )?;
        let eve_container = PostQuantumContainer::new_bob(
            ConstructorOpts::new_init(Some(
                kem_algorithm + encryption_algorithm + signature_algorithm,
            )),
            tx_params,
            bob_psk,
        )?;
        // Internally, this computes the CipherText. The next step is to send this CipherText back over to alice
        let bob_ciphertext = bob_container.get_ciphertext().unwrap();
        let eve_ciphertext = eve_container.get_ciphertext().unwrap();
        assert_ne!(bob_ciphertext, eve_ciphertext);
        //
        // Next, alice received Bob's ciphertext. She must now run an update on her internal data in order to get the shared secret
        let tx_params = bob_container.generate_bob_to_alice_transfer().unwrap();
        alice_container
            .alice_on_receive_ciphertext(tx_params, alice_psk)
            .unwrap();

        let alice_ss = alice_container.get_shared_secret().unwrap();
        let bob_ss = bob_container.get_shared_secret().unwrap();
        let eve_ss = eve_container.get_shared_secret().unwrap();

        assert_eq!(alice_ss, bob_ss);
        assert_ne!(eve_ss, alice_ss);
        assert_ne!(eve_ss, bob_ss);

        let mut plaintext = vec![];
        for x in 0..256 {
            if x != 0 {
                plaintext.push((x % 256) as u8)
            }

            let nonce = &Vec::from_iter(0..citadel_types::crypto::LARGEST_NONCE_LEN as u8);

            let mut ciphertext = alice_container
                .encrypt(plaintext.as_slice(), nonce)
                .unwrap();
            let mut ptr = &mut ciphertext[..];

            let decrypted = bob_container.decrypt(&mut ptr, nonce).unwrap();
            assert_eq!(plaintext.as_slice(), decrypted);

            let mut ciphertext = bob_container.encrypt(plaintext.as_slice(), nonce).unwrap();
            let mut ptr = &mut ciphertext[..];

            //let decrypted = bob_container.decrypt(ciphertext, nonce).unwrap();
            let decrypted = alice_container.decrypt(&mut ptr, nonce).unwrap();

            assert_eq!(plaintext.as_slice(), decrypted);

            if kem_algorithm == KemAlgorithm::Kyber {
                // test local encryption
                local_encryption(&alice_container, &bob_container, &plaintext, nonce);
            }
        }

        Ok(())
    }

    fn local_encryption(
        alice_container: &PostQuantumContainer,
        bob_container: &PostQuantumContainer,
        plaintext: impl AsRef<[u8]>,
        nonce: impl AsRef<[u8]>,
    ) {
        let plaintext = plaintext.as_ref();
        let nonce = nonce.as_ref();
        // alice wants to save her contents on bob's machine
        let ciphertext = alice_container.local_encrypt(plaintext, nonce).unwrap();
        assert_ne!(&ciphertext, plaintext);
        // Alice sends her ciphertext remotely to bob. Bob receives ciphertext
        // prove that bob cannot get the valid ciphertext
        assert!(bob_container.local_decrypt(&ciphertext, nonce).is_err());
        assert!(bob_container.decrypt(&ciphertext, nonce).is_err());
        // Alice now wants the ciphertext back
        // prove that alice can still decrypt her data
        let decrypted = alice_container.local_decrypt(ciphertext, nonce).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn in_place_sequential() {
        const HEADER_LEN: usize = 50;

        let kem_algorithm = KemAlgorithm::Kyber;
        let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256;
        let signature_algorithm = SigAlgorithm::None;

        let (alice_container, bob_container) = gen(
            kem_algorithm,
            encryption_algorithm,
            signature_algorithm,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS,
        );

        for x in 0..256 {
            run_protection::<Vec<u8>>(&alice_container, &bob_container, HEADER_LEN, x);
            run_protection::<BytesMut>(&alice_container, &bob_container, HEADER_LEN, x);
        }
    }

    #[test]
    fn in_place_sequential_kyber() {
        const HEADER_LEN: usize = 50;

        let kem_algorithm = KemAlgorithm::Kyber;
        let encryption_algorithm = EncryptionAlgorithm::Kyber;
        let signature_algorithm = SigAlgorithm::Falcon1024;

        let (alice_container, bob_container) = gen(
            kem_algorithm,
            encryption_algorithm,
            signature_algorithm,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS,
        );

        for x in 0..256 {
            run_protection::<Vec<u8>>(&alice_container, &bob_container, HEADER_LEN, x);
            run_protection::<BytesMut>(&alice_container, &bob_container, HEADER_LEN, x);
        }
    }

    fn run_protection<T: EzBuffer + Default + Clone + Debug + PartialEq>(
        alice_container: &PostQuantumContainer,
        bob_container: &PostQuantumContainer,
        header_len: usize,
        payload_len: usize,
    ) {
        let nonce_len = alice_container.params.encryption_algorithm.nonce_len();
        let total_len = header_len + payload_len;
        let mut buf = T::default();
        for x in 0..total_len {
            buf.put_u8(x as u8);
        }

        let original = buf.clone();

        log::trace!(target: "citadel", "[ {} ] {:?}", buf.len(), buf.as_ref());
        let nonce = Vec::from_iter(0..nonce_len as u8);
        alice_container
            .protect_packet_in_place(header_len, &mut buf, &nonce)
            .unwrap();

        log::trace!(target: "citadel", "[ {} ] {:?}", buf.len(), buf.as_ref());
        let mut header = buf.split_to(header_len);
        bob_container
            .validate_packet_in_place(&header, &mut buf, &nonce)
            .unwrap();
        header.unsplit(buf);
        let buf = header;

        assert_eq!(buf, original);

        log::trace!(target: "citadel", "[ {} ] {:?}", buf.len(), buf.as_ref());
    }

    #[test]
    fn in_place_out_of_order_for_unordered_mode() {
        setup_log();
        const HEADER_LEN: usize = 50;
        const TOTAL_LEN: usize = HEADER_LEN + 150;

        let kem_algorithm = KemAlgorithm::Kyber;
        let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256;
        let signature_algorithm = SigAlgorithm::None;

        let nonce_len = encryption_algorithm.nonce_len() as u8;
        let (alice_container, bob_container) = gen(
            kem_algorithm,
            encryption_algorithm,
            signature_algorithm,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS,
        );
        let mut zeroth = Vec::<u8>::default();
        let mut zeroth_nonce = Vec::<u8>::from_iter(0..nonce_len);
        for y in 0..(HISTORY_LEN + 10) {
            let mut buf = Vec::with_capacity(TOTAL_LEN);
            for x in 0..TOTAL_LEN {
                buf.put_u8(x as u8);
            }

            let mut buf2 = buf.clone();

            log::trace!(target: "citadel", "[{} @ {} ] {:?}", y, buf.len(), &buf[..]);
            let nonce = vec![0; 12];
            alice_container
                .protect_packet_in_place(HEADER_LEN, &mut buf, &nonce)
                .unwrap();
            alice_container
                .protect_packet_in_place(HEADER_LEN, &mut buf2, &nonce)
                .unwrap();

            // pretend someone grabs the header + ciphertext
            let mut intercepted_packet = buf.clone();
            if y == 0 {
                zeroth.clone_from(&intercepted_packet);
                zeroth_nonce.clone_from(&nonce);
            }

            // to simulate out-of order delivery, protect a new packet in place and validate that one
            log::trace!(target: "citadel", "[{} @ {} ] {:?}", y, buf2.len(), &buf2[..]);
            let header2 = buf2.split_to(HEADER_LEN);
            assert!(bob_container
                .validate_packet_in_place(&header2, &mut buf2, &nonce)
                .is_ok());
            // now do them in order

            let mut header = buf.split_to(HEADER_LEN);
            bob_container
                .validate_packet_in_place(&header, &mut buf, &nonce)
                .unwrap();
            // since we are using in-place decryption, the first attempt will corrupt the payload, thus invalidating the packet's
            // decryption operation, even though it may correct. As such, this proves it is NECESSARY that packets
            // arrive IN-ORDER!!
            assert!(bob_container
                .validate_packet_in_place(&header2, &mut buf2, &nonce)
                .is_err());
            // now, let's see what happens when we try validating the intercepted packet (replay attack)
            let intercepted_header = intercepted_packet.split_to(HEADER_LEN);
            assert!(bob_container
                .validate_packet_in_place(&intercepted_header, &mut intercepted_packet, &nonce)
                .is_err());
            // Therefore: packets MUST be in order, and repeat attempts will invalidate the decryption attempt, as desired
            header.unsplit(buf);
            let buf = header;

            log::trace!(target: "citadel", "[{} @ {} ] {:?}", y, buf.len(), &buf[..]);
        }
        let header = zeroth.split_to(HEADER_LEN);
        assert!(bob_container
            .validate_packet_in_place(header, &mut zeroth, zeroth_nonce)
            .is_err());
    }

    #[test]
    fn unordered_mode() {
        const HEADER_LEN: usize = 50;
        const TOTAL_LEN: usize = HEADER_LEN + 150;

        citadel_logging::setup_log();

        let kem_algorithm = KemAlgorithm::Kyber;
        let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256;
        let signature_algorithm = SigAlgorithm::None;
        let nonce_len = encryption_algorithm.nonce_len();
        let (alice_container, bob_container) = gen(
            kem_algorithm,
            encryption_algorithm,
            signature_algorithm,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS,
        );

        let mut packet0 = (0..TOTAL_LEN as u8).collect::<Vec<u8>>();
        let nonce = Vec::from_iter(0..nonce_len as u8);
        // encrypt the packet, but don't verify it
        alice_container
            .protect_packet_in_place(HEADER_LEN, &mut packet0, &nonce)
            .unwrap();
        // In theory, in unordered mode, we don't have to verify packet0 before HISTORY_LEN+1 packets
        for _y in 0..HISTORY_LEN + 10 {
            let mut packet_n = (0..TOTAL_LEN as u8).collect::<Vec<u8>>();
            alice_container
                .protect_packet_in_place(HEADER_LEN, &mut packet_n, &nonce)
                .unwrap();
            let header = packet_n.split_to(HEADER_LEN);
            bob_container
                .validate_packet_in_place(&header, &mut packet_n, &nonce)
                .unwrap();
        }

        let header = packet0.split_to(HEADER_LEN);
        assert!(alice_container
            .validate_packet_in_place(&header, &mut packet0, &nonce)
            .is_err());
    }

    #[test]
    fn test_all_kems() {
        citadel_logging::setup_log();
        for algorithm in KemAlgorithm::list() {
            log::trace!(target: "citadel", "About to test {:?}", algorithm);
            run::<Vec<u8>>(
                algorithm.as_u8(),
                EncryptionAlgorithm::AES_GCM_256,
                SigAlgorithm::None,
                &PRE_SHARED_KEYS,
                &PRE_SHARED_KEYS,
            )
            .unwrap();
            run::<Vec<u8>>(
                algorithm.as_u8(),
                EncryptionAlgorithm::ChaCha20Poly_1305,
                SigAlgorithm::None,
                &PRE_SHARED_KEYS,
                &PRE_SHARED_KEYS,
            )
            .unwrap();
            run::<Vec<u8>>(
                algorithm.as_u8(),
                EncryptionAlgorithm::Ascon80pq,
                SigAlgorithm::None,
                &PRE_SHARED_KEYS,
                &PRE_SHARED_KEYS,
            )
            .unwrap();
            if algorithm == KemAlgorithm::Kyber {
                run::<Vec<u8>>(
                    algorithm.as_u8(),
                    EncryptionAlgorithm::Kyber,
                    SigAlgorithm::Falcon1024,
                    &PRE_SHARED_KEYS,
                    &PRE_SHARED_KEYS,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn test_kyber() {
        citadel_logging::setup_log();
        run::<Vec<u8>>(
            KemAlgorithm::Kyber.as_u8(),
            EncryptionAlgorithm::Kyber,
            SigAlgorithm::Falcon1024,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS,
        )
        .unwrap()
    }

    #[should_panic(expected = "EncryptionFailure")]
    #[test]
    fn test_kyber_bad_psks() {
        citadel_logging::should_panic_test();
        run::<Vec<u8>>(
            KemAlgorithm::Kyber.as_u8(),
            EncryptionAlgorithm::AES_GCM_256,
            SigAlgorithm::Falcon1024,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS2,
        )
        .unwrap();
    }

    #[test]
    fn parse() {
        fn test<T: AlgorithmsExt + Copy + PartialEq>() {
            let values = T::list();
            for value in values {
                let u8_repr = value.as_u8();
                assert_eq!(T::from_u8(u8_repr).unwrap(), value);
            }
        }

        test::<KemAlgorithm>();
        test::<SigAlgorithm>();
        test::<EncryptionAlgorithm>();
    }

    #[test]
    fn test_serialize_deserialize() {
        citadel_logging::setup_log();
        let kem_algorithm = KemAlgorithm::Kyber;
        let encryption_algorithm = EncryptionAlgorithm::AES_GCM_256;
        let signature_algorithm = SigAlgorithm::None;
        let (alice_container, bob_container) = gen(
            kem_algorithm,
            encryption_algorithm,
            signature_algorithm,
            &PRE_SHARED_KEYS,
            &PRE_SHARED_KEYS,
        );

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
        let pqq_alice = PostQuantumContainer::deserialize_from_bytes(serialized_alice).unwrap();

        let serialized_bob = bob_container.serialize_to_vector().unwrap();
        let pqq_bob = PostQuantumContainer::deserialize_from_bytes(serialized_bob).unwrap();

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

    #[test]
    fn test_params_parse() {
        fn serialize(params: CryptoParameters) -> CryptoParameters {
            let packed: u8 = params.into();
            CryptoParameters::try_from(packed).unwrap()
        }

        for enx in EncryptionAlgorithm::list() {
            for kex in KemAlgorithm::list() {
                for sig in SigAlgorithm::list() {
                    fn test_inner(
                        params: impl Into<CryptoParameters>,
                        enx: EncryptionAlgorithm,
                        kex: KemAlgorithm,
                        sig: SigAlgorithm,
                    ) {
                        let params = serialize(params.into());

                        assert_eq!(params.encryption_algorithm, enx);
                        assert_eq!(params.kem_algorithm, kex);
                        assert_eq!(params.sig_algorithm, sig);
                    }

                    let check_params_3 = enx + kex + sig;
                    if validate_crypto_params(&check_params_3).is_ok() {
                        // check all 3-valued combinations
                        test_inner(enx + kex + sig, enx, kex, sig);
                        test_inner(enx + sig + kex, enx, kex, sig);
                        test_inner(kex + enx + sig, enx, kex, sig);
                        test_inner(kex + sig + enx, enx, kex, sig);
                        test_inner(sig + enx + kex, enx, kex, sig);
                        test_inner(sig + kex + enx, enx, kex, sig);
                    }
                }
            }
        }
    }

    #[test]
    fn test_bad_crypto_params() {
        let bad_params = EncryptionAlgorithm::Kyber + KemAlgorithm::Kyber;
        assert!(validate_crypto_params(&bad_params).is_err());
    }
}
