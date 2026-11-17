#![allow(dead_code)]
//! Server-side accounts for the account-layer tests: an account manager with explicit, cheap
//! Argon2 settings, and accounts registered on it.
use citadel_crypt::argon::argon_container::ArgonDefaultServerSettings;
use citadel_crypt::endpoint_crypto_container::{EndpointRatchetConstructor, PeerSessionCrypto};
use citadel_crypt::prelude::{ConstructorOpts, Toolset};
use citadel_crypt::ratchets::stacked::constructor::StackedRatchetConstructor;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecBuffer};
use citadel_user::account_manager::AccountManager;
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::backend::BackendType;
use citadel_user::prelude::ConnectionInfo;

pub type Manager = AccountManager<StackedRatchet, StackedRatchet>;

/// Below the floor on purpose: these tests are about accounts, not password hashing.
pub fn cheap_argon() -> ArgonDefaultServerSettings {
    ArgonDefaultServerSettings {
        lanes: 1,
        hash_length: 32,
        mem_cost: 1024,
        time_cost: 1,
        secret: vec![],
    }
}

pub async fn manager(backend: BackendType, argon: ArgonDefaultServerSettings) -> Manager {
    Manager::new(backend, Some(argon), None, None)
        .await
        .unwrap()
}

fn crypto(cid: u64) -> PeerSessionCrypto<StackedRatchet> {
    let opts = ConstructorOpts::new_vec_init(
        Some(KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256),
        Default::default(),
    );
    let mut alice = StackedRatchetConstructor::new_alice(opts.clone(), cid, 0).unwrap();
    let mut bob = StackedRatchetConstructor::new_bob::<Vec<u8>>(
        cid,
        opts,
        alice.stage0_alice().unwrap(),
        &[],
    )
    .unwrap();
    alice
        .stage1_alice::<Vec<u8>>(bob.stage0_bob().unwrap(), &[])
        .unwrap();
    PeerSessionCrypto::new(Toolset::new(cid, bob.finish().unwrap()), false)
}

/// Registers `username` the way the server does, and returns its CID and the registration's
/// client half (the settings a client keeps to log in later).
pub async fn register(mgr: &Manager, username: &str, password: &str) -> (u64, ProposedCredentials) {
    let cid = mgr.get_persistence_handler().get_cid_by_username(username);
    let creds = ProposedCredentials::new_register("Full Name", username, SecBuffer::from(password))
        .await
        .unwrap();
    mgr.register_impersonal_hyperlan_client_network_account(
        ConnectionInfo::new("127.0.0.1:12345").unwrap(),
        creds.clone(),
        crypto(cid),
    )
    .await
    .unwrap();
    (cid, creds)
}

/// A directory under the OS temp dir that no other test uses.
pub fn fresh_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{tag}_{}", uuid::Uuid::new_v4().as_u128()))
}

pub fn file_backend(dir: &std::path::Path) -> BackendType {
    BackendType::new(format!("file:{}/", dir.display())).unwrap()
}
