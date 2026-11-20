//! An account's identity key and its pins of peers' keys, in memory: the port an agent supplies
//! with a persistent store. Real ML-DSA-65 keys.

use citadel_sdk::prelude::{transcript_message, KexAuth, P2pKexIdentity, PeerKexIdentity};
use futures::future::BoxFuture;
use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{MlDsa65, Seed, SigningKey};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct Key(SigningKey<MlDsa65>);

impl Key {
    pub fn new(byte: u8) -> Self {
        let mut seed = Seed::default();
        seed.copy_from_slice(&[byte; 32]);
        Key(SigningKey::<MlDsa65>::from_seed(&seed))
    }

    pub fn public(&self) -> Vec<u8> {
        self.0.verifying_key().encode().as_slice().to_vec()
    }
}

#[derive(Default)]
struct State {
    pins: HashMap<u64, Vec<u8>>,
    /// Read as the pin of every peer not pinned yet: a key pinned before, since replaced.
    another: Option<Vec<u8>>,
    changes: Vec<(u64, Vec<u8>)>,
    channel: Option<PeerKexIdentity>,
}

pub struct Store {
    key: Option<Key>,
    state: Mutex<State>,
}

impl Store {
    pub fn new(key: Key) -> Self {
        Store {
            key: Some(key),
            state: Mutex::default(),
        }
    }

    /// An account with no identity key.
    pub fn legacy() -> Self {
        Store {
            key: None,
            state: Mutex::default(),
        }
    }

    /// An account that pinned, for its peer, a key the peer no longer signs with.
    pub fn pinned_to_another(key: Key) -> Self {
        let store = Store::new(key);
        store.state.lock().unwrap().another = Some(Key::new(99).public());
        store
    }

    pub fn changes(&self) -> Vec<(u64, Vec<u8>)> {
        self.state.lock().unwrap().changes.clone()
    }

    /// The person accepts the key a change reported.
    pub fn accept(&self, peer_cid: u64, key: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.another = None;
        state.pins.insert(peer_cid, key);
    }

    pub fn record_channel(&self, identity: Option<PeerKexIdentity>) {
        self.state.lock().unwrap().channel = identity;
    }

    pub fn channel(&self) -> Option<PeerKexIdentity> {
        self.state.lock().unwrap().channel.clone()
    }
}

impl P2pKexIdentity for Store {
    fn sign(&self, _local_cid: u64, body: &[u8]) -> Option<KexAuth> {
        let key = self.key.as_ref()?;
        let signature: ml_dsa::Signature<MlDsa65> = key.0.sign(&transcript_message(body));
        Some(KexAuth {
            identity_key: key.public(),
            signature: signature.encode().as_slice().to_vec(),
        })
    }

    fn pinned_key(&self, _local_cid: u64, peer_cid: u64) -> Option<Vec<u8>> {
        let state = self.state.lock().unwrap();
        state
            .pins
            .get(&peer_cid)
            .or(state.another.as_ref())
            .cloned()
    }

    fn pin_first_key(
        &self,
        _local_cid: u64,
        peer_cid: u64,
        identity_key: &[u8],
    ) -> BoxFuture<'static, Result<(), String>> {
        let mut state = self.state.lock().unwrap();
        state.pins.insert(peer_cid, identity_key.to_vec());
        Box::pin(async { Ok(()) })
    }

    fn peer_key_changed(&self, _local_cid: u64, peer_cid: u64, presented: &[u8]) {
        let mut state = self.state.lock().unwrap();
        state.changes.push((peer_cid, presented.to_vec()));
    }
}
