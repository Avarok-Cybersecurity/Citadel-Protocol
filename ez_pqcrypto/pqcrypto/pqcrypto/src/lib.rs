/// Post-Quantum cryptographic primitives
///
/// Packages the [PQClean][pqclean] project as Rust crates
///
/// [pqclean]: https://github.com/PQClean/PQClean/
pub use pqcrypto_traits as traits;

pub mod prelude {
    pub use pqcrypto_traits::kem::{
        Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
    };
    pub use pqcrypto_traits::sign::{
        DetachedSignature as _, PublicKey as _, SecretKey as _, SignedMessage as _,
    };
}

pub mod kem {
    /*
    pub use pqcrypto_classicmceliece::{
        mceliece348864, mceliece348864f, mceliece460896, mceliece460896f, mceliece6688128,
        mceliece6688128f, mceliece6960119, mceliece6960119f, mceliece8192128, mceliece8192128f,
    };
    pub use pqcrypto_frodo::{
        frodokem1344aes, frodokem1344shake, frodokem640aes, frodokem640shake, frodokem976aes,
        frodokem976shake,
    };
    pub use pqcrypto_hqc::{
        hqc1281cca2, hqc1921cca2, hqc1922cca2, hqc2561cca2, hqc2562cca2, hqc2563cca2,
    };
    pub use pqcrypto_kyber::{
        kyber1024, kyber102490s, kyber512, kyber51290s, kyber768, kyber76890s,
    };
    pub use pqcrypto_ledacryptkem::{ledakemlt12, ledakemlt32, ledakemlt52};
    pub use pqcrypto_newhope::{newhope1024cca, newhope1024cpa, newhope512cca, newhope512cpa};
    pub use pqcrypto_ntru::{ntruhps2048509, ntruhps2048677, ntruhps4096821, ntruhrss701};

     */
    pub use pqcrypto_saber::{firesaber, lightsaber, saber};
   /*
    pub use pqcrypto_threebears::{
        babybear, babybearephem, mamabear, mamabearephem, papabear, papabearephem,
    };*/
}

pub mod sign {
    /*
    pub use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium4};
    pub use pqcrypto_falcon::{falcon1024, falcon512};
    pub use pqcrypto_mqdss::{mqdss48, mqdss64};
    pub use pqcrypto_qtesla::{qteslapi, qteslapiii};
    pub use pqcrypto_rainbow::{
        rainbowiaclassic, rainbowiacyclic, rainbowiacycliccompressed, rainbowiiicclassic,
        rainbowiiiccyclic, rainbowiiiccycliccompressed, rainbowvcclassic, rainbowvccyclic,
        rainbowvccycliccompressed,
    };
    pub use pqcrypto_sphincsplus::{
        sphincsharaka128frobust, sphincsharaka128fsimple, sphincsharaka128srobust,
        sphincsharaka128ssimple, sphincsharaka192frobust, sphincsharaka192fsimple,
        sphincsharaka192srobust, sphincsharaka192ssimple, sphincsharaka256frobust,
        sphincsharaka256fsimple, sphincsharaka256srobust, sphincsharaka256ssimple,
        sphincssha256128frobust, sphincssha256128fsimple, sphincssha256128srobust,
        sphincssha256128ssimple, sphincssha256192frobust, sphincssha256192fsimple,
        sphincssha256192srobust, sphincssha256192ssimple, sphincssha256256frobust,
        sphincssha256256fsimple, sphincssha256256srobust, sphincssha256256ssimple,
        sphincsshake256128frobust, sphincsshake256128fsimple, sphincsshake256128srobust,
        sphincsshake256128ssimple, sphincsshake256192frobust, sphincsshake256192fsimple,
        sphincsshake256192srobust, sphincsshake256192ssimple, sphincsshake256256frobust,
        sphincsshake256256fsimple, sphincsshake256256srobust, sphincsshake256256ssimple,
    };*/
}
