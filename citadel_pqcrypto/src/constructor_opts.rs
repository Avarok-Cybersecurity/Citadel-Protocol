use crate::prelude::algorithm_dictionary::CryptoParameters;
use serde::{Deserialize, Serialize};

/// WARNING! `previous_shared_secret` should never leave a node; it should only be extracted from the previous PQC when bob is constructing his PQC
#[derive(Clone, Default)]
pub struct ConstructorOpts {
    pub cryptography: Option<CryptoParameters>,
    pub chain: Option<RecursiveChain>,
}

impl ConstructorOpts {
    pub fn new_init(cryptography: Option<impl Into<CryptoParameters>>) -> Self {
        Self {
            cryptography: cryptography.map(|r| r.into()),
            chain: None,
        }
    }

    pub fn new_vec_init(
        cryptography: Option<impl Into<CryptoParameters>>,
        count: usize,
    ) -> Vec<Self> {
        let settings = cryptography.map(|r| r.into()).unwrap_or_default();
        (0..count).map(|_| Self::new_init(Some(settings))).collect()
    }

    pub fn new_from_previous(
        cryptography: Option<impl Into<CryptoParameters>>,
        previous_shared_secret: RecursiveChain,
    ) -> Self {
        Self {
            cryptography: cryptography.map(|r| r.into()),
            chain: Some(previous_shared_secret),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecursiveChain {
    pub chain: [u8; 32],
    pub alice: [u8; 32],
    pub bob: [u8; 32],
    pub(crate) first: bool,
}

impl RecursiveChain {
    pub fn new<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(
        chain: T,
        alice: R,
        bob: V,
        first: bool,
    ) -> Option<Self> {
        let chain = chain.as_ref();
        let alice = alice.as_ref();
        let bob = bob.as_ref();

        if chain.len() != 32 || alice.len() != 32 || bob.len() != 32 {
            None
        } else {
            let mut chain_ret: [u8; 32] = [0u8; 32];
            let mut alice_ret: [u8; 32] = [0u8; 32];
            let mut bob_ret: [u8; 32] = [0u8; 32];

            for (idx, val) in chain.iter().enumerate() {
                chain_ret[idx] = *val;
            }

            for (idx, val) in alice.iter().enumerate() {
                alice_ret[idx] = *val;
            }

            for (idx, val) in bob.iter().enumerate() {
                bob_ret[idx] = *val;
            }

            Some(Self {
                chain: chain_ret,
                alice: alice_ret,
                bob: bob_ret,
                first,
            })
        }
    }
}
