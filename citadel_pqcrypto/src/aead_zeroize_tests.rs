//! The symmetric ciphers' key material is wiped when they drop.
use zeroize::ZeroizeOnDrop;

fn wiped_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn every_symmetric_cipher_wipes_its_keys_on_drop() {
    wiped_on_drop::<aes::Aes256>();
    wiped_on_drop::<chacha20poly1305::ChaCha20Poly1305>();
    wiped_on_drop::<chacha20poly1305::XChaCha20Poly1305>();
}
