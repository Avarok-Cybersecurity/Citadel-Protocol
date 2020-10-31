#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use rand::prelude::ThreadRng;
    use rand::RngCore;

    use ez_pqcrypto::{algorithm_dictionary, PostQuantumContainer, NONCE_LENGTH_BYTES};

    /*
        #[test]
        fn test_oqs() {
            oqs::init();
            let alice = oqs::kem::Kem::new(oqs::kem::Algorithm::Firesaber).unwrap();
            let (public_key, secret_key) = alice.keypair().unwrap();

            let bob = oqs::kem::Kem::new(oqs::kem::Algorithm::Firesaber).unwrap();
            let (ciphertext, bob_symmetric_key) = bob.encapsulate(public_key.as_ref()).unwrap();
            let alice_symmetric_key = alice.decapsulate(secret_key.as_ref(), ciphertext.as_ref()).unwrap();
            assert_eq!(alice_symmetric_key.as_ref(), bob_symmetric_key.as_ref());
        }*/

    #[test]
    fn default() {
        let mut working = Vec::new();
        for algorithm in 0..algorithm_dictionary::ALGORITHM_COUNT {
            // Good: 0, 1, 2, 7, 8, 9, 10 -> =15, 18, 19, 20, 36 -> =41
            if algorithm > 35 {
                if run(Some(algorithm)).is_ok() {
                    println!("Good: {}", algorithm);
                    working.push(algorithm);
                }
            }
        }

        print!("working: [");
        for good in working {
            print!("{}, ", good);
        }
        print!("]\n")
    }

    #[test]
    fn runit() {
        run(Some(0)).unwrap()
    }

    fn run(algorithm: Option<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let algorithm = algorithm.unwrap_or(algorithm_dictionary::FIRESABER);
        // Alice wants to share data with Bob. She first creates a PostQuantumContainer
        let mut alice_container = PostQuantumContainer::new_alice(Some(algorithm));
        // Then, alice sends her public key to Bob. She must also send the byte value of algorithm_dictionary::BABYBEAR to him
        let alice_public_key = alice_container.get_public_key();
        let algorithm_byte_value = alice_container.get_algorithm_idx();
        //
        // Then, Bob gets the public key. To process it, he must create a PostQuantumContainer for himself
        let bob_container = PostQuantumContainer::new_bob(algorithm_byte_value, alice_public_key)?;
        let eve_container = PostQuantumContainer::new_bob(algorithm_byte_value, alice_public_key)?;
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
        let nonce = b"unique nonceunique nonce"; // 96 bits or 12 bytes

        let ciphertext = alice_container.encrypt(plaintext, nonce).unwrap();
        let decrypted = bob_container.decrypt(ciphertext, nonce).unwrap();

        debug_assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn in_place_sequential() {
        const HEADER_LEN: usize = 50;
        const TOTAL_LEN: usize = HEADER_LEN;

        let algorithm = algorithm_dictionary::FIRESABER;
        println!("Test algorithm {}", algorithm);
        let mut alice_container = PostQuantumContainer::new_alice(Some(algorithm));
        let bob_container = PostQuantumContainer::new_bob(algorithm, alice_container.get_public_key()).unwrap();
        alice_container.alice_on_receive_ciphertext(bob_container.get_ciphertext().unwrap()).unwrap();

        let mut buf = BytesMut::with_capacity(TOTAL_LEN);
        for x in 0..TOTAL_LEN {
            buf.put_u8(x as u8);
        }

        println!("[ {} ] {:?}", buf.len(), &buf[..]);
        let nonce: [u8; NONCE_LENGTH_BYTES] = Default::default();
        alice_container.protect_packet_in_place(HEADER_LEN, &mut buf, &nonce).unwrap();

        println!("[ {} ] {:?}", buf.len(), &buf[..]);
        let mut header = buf.split_to(HEADER_LEN);
        bob_container.validate_packet_in_place(&header, &mut buf, &nonce).unwrap();
        header.unsplit(buf);
        let buf = header;

        println!("[ {} ] {:?}", buf.len(), &buf[..]);
    }

    #[test]
    fn in_place_out_of_order() {
        const HEADER_LEN: usize = 50;
        const TOTAL_LEN: usize = HEADER_LEN + 150;

        let algorithm = algorithm_dictionary::FIRESABER;
        println!("Test algorithm {}", algorithm);
        let mut alice_container = PostQuantumContainer::new_alice(Some(algorithm));
        let bob_container = PostQuantumContainer::new_bob(algorithm, alice_container.get_public_key()).unwrap();
        alice_container.alice_on_receive_ciphertext(bob_container.get_ciphertext().unwrap()).unwrap();

        for _ in 0..1 {
            let mut buf = BytesMut::with_capacity(TOTAL_LEN);
            for x in 0..TOTAL_LEN {
                buf.put_u8(x as u8);
            }

            let mut buf2 = buf.clone();

            println!("[ {} ] {:?}", buf.len(), &buf[..]);
            let nonce: [u8; NONCE_LENGTH_BYTES] = Default::default();
            alice_container.protect_packet_in_place(HEADER_LEN, &mut buf, &nonce).unwrap();
            alice_container.protect_packet_in_place(HEADER_LEN, &mut buf2, &nonce).unwrap();

            // pretend someone grabs the header + ciphertext
            let mut intercepted_packet = buf.clone();

            // to simulate out-of order delivery, protect a new packet in place and validate that one
            println!("[ {} ] {:?}", buf2.len(), &buf2[..]);
            let mut header2 = buf2.split_to(HEADER_LEN);
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

            println!("[ {} ] {:?}", buf.len(), &buf[..]);
        }
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

        println!("Unsigned len: {}\nSigned len: {}", message.len(), signed_message.len());

        let signed_message_received = pqcrypto::sign::falcon512::SignedMessage::from_bytes(signed_message).unwrap();
        let opened_message = pqcrypto::sign::falcon512::open(&signed_message_received, &public_key).unwrap();
        debug_assert_eq!(opened_message.as_slice(), message);
    }*/

    #[test]
    fn test_10() {
        for algorithm in 0..10 {
            println!("About to test {}", algorithm);
            run(Some(algorithm)).unwrap();
        }
    }

    #[test]
    fn test_serialize_deserialize() {
        let algorithm = algorithm_dictionary::FIRESABER;
        println!("Test algorithm {}", algorithm);
        let mut alice_container = PostQuantumContainer::new_alice(Some(algorithm));
        let bob_container = PostQuantumContainer::new_bob(algorithm, alice_container.get_public_key()).unwrap();
        alice_container.alice_on_receive_ciphertext(bob_container.get_ciphertext().unwrap()).unwrap();

        let nonce = &mut [0u8; 12];
        ThreadRng::default().fill_bytes(nonce);
        let msg = "hello, world!";

        let enc = alice_container.encrypt(msg, &nonce).unwrap();

        let al_pub0 = alice_container.get_public_key();
        let al_ss0 = alice_container.get_shared_secret().unwrap();
        let al_secr0 = alice_container.get_secret_key().unwrap();

        let bob_pub0 = alice_container.get_public_key();
        let bob_ss0 = alice_container.get_shared_secret().unwrap();
        let _bob_secr0 = alice_container.get_secret_key().unwrap();

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

        assert_ne!(al_pub0, bob_pub0);

        let _decr_alice = alice_container.decrypt(&enc, &nonce).unwrap();
        let _decr_bob = bob_container.decrypt(&enc, &nonce).unwrap();

        let decr_alice = pqq_alice.decrypt(&enc, &nonce).unwrap();
        let decr_bob = pqq_bob.decrypt(&enc, &nonce).unwrap();

        assert_eq!(decr_alice, decr_bob);
    }
}