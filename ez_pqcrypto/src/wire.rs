use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone)]
pub struct AliceToBobTransferParameters {
    pub alice_pk: Arc<oqs::kem::PublicKey>,
    pub alice_pk_sig: Arc<oqs::sig::PublicKey>,
    pub alice_sig: oqs::sig::Signature,
    pub sig_scheme: oqs::sig::Algorithm,
    pub kem_scheme: oqs::kem::Algorithm,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BobToAliceTransferParameters {
    pub bob_ciphertext: Arc<oqs::kem::Ciphertext>,
    pub bob_signature: oqs::sig::Signature,
    pub bob_pk_sig: Arc<oqs::sig::PublicKey>,
    pub bob_pk: Arc<oqs::kem::PublicKey>,
}
