use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AliceToBobTransferParameters {
    MixedAsymmetric {
        alice_pk: Arc<oqs::kem::PublicKey>,
        alice_pk_sig: Arc<oqs::sig::PublicKey>,
        alice_sig: oqs::sig::Signature,
        sig_scheme: oqs::sig::Algorithm,
        kem_scheme: oqs::kem::Algorithm,
    },
    PureSymmetric {
        alice_pk: Arc<oqs::kem::PublicKey>,
        kem_scheme: oqs::kem::Algorithm,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum BobToAliceTransferParameters {
    MixedAsymmetric {
        bob_ciphertext: Arc<oqs::kem::Ciphertext>,
        bob_signature: oqs::sig::Signature,
        bob_pk_sig: Arc<oqs::sig::PublicKey>,
        bob_pk: Arc<oqs::kem::PublicKey>,
    },
    PureSymmetric {
        bob_ciphertext: Arc<oqs::kem::Ciphertext>,
        bob_pk: Arc<oqs::kem::PublicKey>,
    },
}
