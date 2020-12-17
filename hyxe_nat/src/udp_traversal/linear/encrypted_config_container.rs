use bytes::Bytes;

/// Stores the functions relevant to encrypting and decrypting hole-punch related packets
pub struct EncryptedConfigContainer {
    // the input into the function is the local port, which is expected to be inscribed inside the payload in an identifiable way
    generate_packet: Box<dyn Fn(u16) -> Bytes + Send + Sync + 'static>,
    // the input into the function are the encrypted bytes
    decrypt_packet: Box<dyn Fn(&[u8]) -> Option<Bytes> + Send + Sync + 'static>
}

impl EncryptedConfigContainer {
    /// Wraps the provided functions into a portable abstraction
    pub fn new(generate_packet: impl Fn(u16) -> Bytes + Send + Sync + 'static, decrypt_packet: impl Fn(&[u8]) -> Option<Bytes> + Send + Sync + 'static) -> Self {
        Self { generate_packet: Box::new(generate_packet), decrypt_packet: Box::new(decrypt_packet) }
    }

    /// Generates a packet
    pub fn generate_packet(&self, local_port: u16) -> Bytes {
        (self.generate_packet)(local_port)
    }

    /// Decrypts the payload, returning Some if success
    pub fn decrypt_packet(&self, ciphertext: &[u8]) -> Option<Bytes> {
        (self.decrypt_packet)(ciphertext)
    }
}