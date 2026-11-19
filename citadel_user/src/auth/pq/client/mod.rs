//! The client's side of post-quantum sign-in: the OPRF client, Argon2id, ML-KEM key derivation
//! and decapsulation, and the tags. This is the only place Argon2id runs.

mod key_request;
pub mod ksf;
mod login;
mod manage;
mod manage_new;
mod register;

pub use key_request::{RelyingParty, SecurityKeyCeremony, SecurityKeyRequest};
pub use login::{ClientLogin, ClientProof, RecoveryOffer, SecurityKeyAnswer};
pub use manage::{ClientCommitted, ClientManagement};
pub use register::{ClientRegistration, IssuedRecovery, NewRecovery};
