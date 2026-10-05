//! Argon2id, the client's password key-stretching function (see `citadel_user::auth::pq::client`).
//! A server never stretches or verifies a password, so this module is absent from a wasm32 build
//! (the server's) unless `wasm-password-ksf` asks for it.
#[allow(missing_docs)]
pub mod argon_container;
