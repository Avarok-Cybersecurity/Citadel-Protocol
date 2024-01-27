use citadel_types::prelude::SecBuffer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

pub mod group_pq_impls;

pub type IdentityHash = [u8; 16];

pub struct PostQuantumGroup {
    // The hash of our public key
    my_id_hash: Arc<IdentityHash>,
    method: Arc<dyn PostQuantumKexGroup>,
    // A mapping of peer ids to their public keys
    peer_ids: Arc<parking_lot::RwLock<HashMap<IdentityHash, SecBuffer>>>,
}

pub trait PostQuantumKexGroup: 'static {
    // The symmetric key is always randomly generated
    fn symmetric_encrypt(&self, symmetric_key: &[u8], plaintext: &[u8], nonce: &[u8]) -> SecBuffer;
    fn symmetric_decrypt(
        &self,
        symmetric_key: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Option<SecBuffer>;
    fn asymmetric_encrypt(&self, public_key: &[u8], plaintext: &[u8], nonce: &[u8]) -> SecBuffer;
    fn asymmetric_decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Option<SecBuffer>;
    fn public_key(&self) -> &SecBuffer;
}

/// We don't need cryptographic security here, just a hash function that is fast and has a low collision rate
/// The inputs should be public inputs
fn hash_function<T: AsRef<[u8]>>(input: T) -> IdentityHash {
    md5::compute(input).0
}

impl PostQuantumGroup {
    pub fn new<T: PostQuantumKexGroup>(method: T) -> Self {
        let my_id_hash = hash_function(method.public_key());

        Self {
            my_id_hash: Arc::new(my_id_hash),
            method: Arc::new(method),
            peer_ids: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }

    pub fn add_peer(&self, peer_public_key: SecBuffer) {
        let peer_id = hash_function(&peer_public_key);
        self.peer_ids.write().insert(peer_id, peer_public_key);
    }

    pub fn remove_peer(&self, peer_public_key: SecBuffer) {
        let peer_id = hash_function(&peer_public_key);
        self.peer_ids.write().remove(&peer_id);
    }

    /// The function will first generate a random symmetric key of 32 bytes in length
    /// Then, it will symmetrically encrypt it into a ciphertext using this random symmetric key and the plaintext/nonce.
    /// Then, it will asymmetrically encrypt the random symmetric key using the public key of each recipient.
    /// Finally, it will return a GroupMessage containing the ciphertext, the encrypted symmetric keys, and the nonce.
    pub fn encrypt(&self, plaintext: &[u8]) -> Transmission {
        let symmetric_key = rand::random::<[u8; 32]>();
        let nonce = rand::random::<[u8; 32]>();
        let ciphertext = self
            .method
            .symmetric_encrypt(&symmetric_key, plaintext, &nonce);

        let mut encrypted_keys = HashMap::new();
        for (peer_id, peer_public_key) in self.peer_ids.read().iter() {
            let asymmetric_nonce = rand::random::<[u8; 32]>();
            encrypted_keys.insert(
                *peer_id,
                GroupMessageTarget {
                    ciphertext: self.method.asymmetric_encrypt(
                        peer_public_key.as_ref(),
                        &symmetric_key,
                        &asymmetric_nonce,
                    ),
                    asymmetric_nonce: asymmetric_nonce.into(),
                },
            );
        }

        Transmission::Broadcast(GroupMessage {
            ciphertext,
            encrypted_keys,
            nonce: nonce.into(),
        })
    }

    pub fn decrypt(&self, mut message: GroupMessage) -> Option<SecBuffer> {
        let my_payload = message.encrypted_keys.remove(&*self.my_id_hash)?;

        let encrypted_symmetric_key = my_payload.ciphertext;
        let asymmetric_nonce = my_payload.asymmetric_nonce;
        let symmetric_key = self
            .method
            .asymmetric_decrypt(encrypted_symmetric_key.as_ref(), asymmetric_nonce.as_ref())?;
        self.method.symmetric_decrypt(
            symmetric_key.as_ref(),
            message.ciphertext.as_ref(),
            message.nonce.as_ref(),
        )
    }
}

#[derive(Serialize, Deserialize)]
pub enum Transmission {
    Broadcast(GroupMessage),
    AddPeer(AddPeer),
    RemovePeer(RemovePeer),
}

#[derive(Serialize, Deserialize)]
pub struct GroupMessage {
    ciphertext: SecBuffer,
    // A map from the hash of the public keys of the recipients to the encrypted symmetric key used to encrypt the message
    // Note: the symmetric key is always randomly generated
    encrypted_keys: HashMap<IdentityHash, GroupMessageTarget>,
    nonce: SecBuffer,
}

#[derive(Serialize, Deserialize)]
pub struct GroupMessageTarget {
    pub ciphertext: SecBuffer,
    pub asymmetric_nonce: SecBuffer,
}

#[derive(Serialize, Deserialize)]
pub struct AddPeer {
    pub peer_public_key: SecBuffer,
}

#[derive(Serialize, Deserialize)]
pub struct RemovePeer {
    pub peer_public_key: SecBuffer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::group_pq_impls::Kyber1024WithAes256Gcm;

    #[test]
    fn test_group() {
        let plaintext = b"Hello, world!" as &[u8];

        let (pk, sk) = kyber_pke::pke_keypair().unwrap();
        let (pk2, sk2) = kyber_pke::pke_keypair().unwrap();
        let group = PostQuantumGroup::new(Kyber1024WithAes256Gcm::new(
            pk.to_vec().into(),
            sk.to_vec().into(),
        ));
        let group_member2 = PostQuantumGroup::new(Kyber1024WithAes256Gcm::new(
            pk2.to_vec().into(),
            sk2.to_vec().into(),
        ));

        group.add_peer(pk2.to_vec().into());
        group_member2.add_peer(pk.to_vec().into());

        let ciphertext = group.encrypt(&plaintext);
        let Transmission::Broadcast(message) = ciphertext else {
            panic!("Should be correct type")
        };
        let decrypted = group_member2.decrypt(message).unwrap();
        assert_eq!(plaintext, decrypted.as_ref());

        // Now, try sending a message from group member2 to group member1
        let ciphertext = group_member2.encrypt(&plaintext);
        let Transmission::Broadcast(message) = ciphertext else {
            panic!("Should be correct type")
        };
        let decrypted = group.decrypt(message).unwrap();
        assert_eq!(plaintext, decrypted.as_ref());
    }
}
