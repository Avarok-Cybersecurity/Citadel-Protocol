use crate::group::PostQuantumKexGroup;
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use citadel_types::prelude::{SecBuffer, AES_GCM_NONCE_LENGTH_BYTES};

pub struct Kyber1024WithAes256Gcm {
    public_key: SecBuffer,
    private_key: SecBuffer,
}

impl Kyber1024WithAes256Gcm {
    pub fn new(public_key: SecBuffer, private_key: SecBuffer) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}

impl PostQuantumKexGroup for Kyber1024WithAes256Gcm {
    fn symmetric_encrypt(&self, symmetric_key: &[u8], plaintext: &[u8], nonce: &[u8]) -> SecBuffer {
        let aes =
            aes_gcm::Aes256Gcm::new_from_slice(symmetric_key).expect("Should be correct size");
        let nonce = aes_gcm::Nonce::from_slice(&nonce[..AES_GCM_NONCE_LENGTH_BYTES]);
        aes.encrypt(nonce, plaintext)
            .expect("Should be correct size")
            .into()
    }

    fn symmetric_decrypt(
        &self,
        symmetric_key: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Option<SecBuffer> {
        let aes =
            aes_gcm::Aes256Gcm::new_from_slice(symmetric_key).expect("Should be correct size");
        let nonce = aes_gcm::Nonce::from_slice(&nonce[..AES_GCM_NONCE_LENGTH_BYTES]);
        aes.decrypt(nonce, ciphertext).ok().map(|x| x.into())
    }

    fn asymmetric_encrypt(&self, public_key: &[u8], plaintext: &[u8], nonce: &[u8]) -> SecBuffer {
        kyber_pke::encrypt(public_key, plaintext, nonce)
            .expect("Should encrypt")
            .into()
    }

    fn asymmetric_decrypt(&self, ciphertext: &[u8], _nonce: &[u8]) -> Option<SecBuffer> {
        kyber_pke::decrypt(&self.private_key, ciphertext)
            .ok()
            .map(|x| x.into())
    }

    fn public_key(&self) -> &SecBuffer {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::PostQuantumKexGroup;
    use rand::RngCore;

    #[test]
    fn test_kyber1024_with_aes256_gcm() {
        let mut rng = rand::thread_rng();
        let mut symmetric_key = [0u8; 32];
        rng.fill_bytes(&mut symmetric_key);
        let mut plaintext = [0u8; 32];
        rng.fill_bytes(&mut plaintext);
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let (pk, sk) = kyber_pke::pke_keypair().unwrap();
        let group = Kyber1024WithAes256Gcm::new(pk.to_vec().into(), sk.to_vec().into());

        let ciphertext = group.symmetric_encrypt(&symmetric_key, &plaintext, &nonce);
        let decrypted = group
            .symmetric_decrypt(&symmetric_key, ciphertext.as_ref(), &nonce)
            .unwrap();
        assert_eq!(plaintext, decrypted.as_ref());
    }

    #[test]
    fn test_kyber1024_asymmetric() {
        let mut rng = rand::thread_rng();
        let mut plaintext = [0u8; 32];
        rng.fill_bytes(&mut plaintext);
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        let (pk, sk) = kyber_pke::pke_keypair().unwrap();
        let group = Kyber1024WithAes256Gcm::new(pk.to_vec().into(), sk.to_vec().into());

        let ciphertext = group.asymmetric_encrypt(group.public_key().as_ref(), &plaintext, &nonce);
        let decrypted = group
            .asymmetric_decrypt(ciphertext.as_ref(), &nonce)
            .unwrap();
        assert_eq!(plaintext, decrypted.as_ref());
    }
}
