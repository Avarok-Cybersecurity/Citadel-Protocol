//! The client's side of post-quantum sign-in: the OPRF client, Argon2id, ML-KEM key derivation
//! and decapsulation, and the tags. This is the only place Argon2id runs.

pub mod ksf;
mod login;
mod register;

pub use login::{ClientLogin, ClientProof, SecurityKeyAnswer, SecurityKeyRequest};
pub use register::ClientRegistration;
