use bytes::BytesMut;
use std::sync::Arc;

/// Stores the functions relevant to encrypting and decrypting hole-punch related packets
#[derive(Clone)]
pub struct EncryptedConfigContainer {
    // the input into the function is the local port, which is expected to be inscribed inside the payload in an identifiable way
    generate_packet: Arc<dyn for<'a> Fn(&'a [u8]) -> BytesMut + Send + Sync + 'static>,
    // the input into the function are the encrypted bytes
    decrypt_packet: Arc<dyn for<'a> Fn(&'a [u8]) -> Option<BytesMut> + Send + Sync + 'static>
}

impl EncryptedConfigContainer {
    /// Wraps the provided functions into a portable abstraction
    pub fn new(generate_packet: impl Fn(&[u8]) -> BytesMut + Send + Sync + 'static, decrypt_packet: impl Fn(&[u8]) -> Option<BytesMut> + Send + Sync + 'static) -> Self {
        Self { generate_packet: Arc::new(generate_packet), decrypt_packet: Arc::new(decrypt_packet) }
    }

    /// Generates a packet
    pub fn generate_packet(&self, plaintext: &[u8]) -> BytesMut {
        (self.generate_packet)(plaintext)
    }

    /// Decrypts the payload, returning Some if success
    pub fn decrypt_packet(&self, ciphertext: &[u8]) -> Option<BytesMut> {
        (self.decrypt_packet)(ciphertext)
    }
}

impl Default for EncryptedConfigContainer {
    // identity transformation
    fn default() -> Self {
        Self {
            generate_packet: Arc::new(|input| BytesMut::from(input)),
            decrypt_packet: Arc::new(|input| Some(BytesMut::from(input)))
        }
    }
}