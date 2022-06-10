use ez_pqcrypto::algorithm_dictionary::{KEM_ALGORITHM_COUNT, EncryptionAlgorithm, KemAlgorithm};
use std::iter::FromIterator;
use ez_pqcrypto::PostQuantumContainer;
use ez_pqcrypto::constructor_opts::ConstructorOpts;
use enum_primitive::FromPrimitive;
use std::convert::TryFrom;

#[allow(unused_must_use)]
fn setup_log() {
    std::env::set_var("RUST_LOG", "info");
    let _ = env_logger::try_init();
    log::trace!(target: "lusna", "TRACE enabled");
    log::trace!(target: "lusna", "INFO enabled");
    log::warn!(target: "lusna", "WARN enabled");
    log::error!(target: "lusna", "ERROR enabled");
}

fn main() {
    setup_log();
    for algorithm in 0..KEM_ALGORITHM_COUNT {
        log::trace!(target: "lusna", "About to test {:?}", KemAlgorithm::try_from(algorithm).unwrap());
        run(algorithm, EncryptionAlgorithm::AES_GCM_256_SIV).unwrap();
        run(algorithm, EncryptionAlgorithm::Xchacha20Poly_1305).unwrap();
    }
}

fn run(algorithm: u8, encryption_algorithm: EncryptionAlgorithm) -> Result<(), Box<dyn std::error::Error>> {
    let kem_algorithm = KemAlgorithm::from_u8(algorithm).unwrap();
    println!("Test: {:?} w/ {:?}", kem_algorithm, encryption_algorithm);
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