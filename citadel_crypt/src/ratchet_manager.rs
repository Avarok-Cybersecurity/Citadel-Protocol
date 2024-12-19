//! Ratchet Manager - Secure Key Ratcheting Protocol Implementation
//!
//! This module implements a secure key ratcheting protocol manager that handles the
//! communication and state management between two peers (Alice and Bob) during key
//! updates and ratcheting operations.
//!
//! # Features
//! - Manages bidirectional communication for key ratcheting between peers
//! - Handles state synchronization during ratchet updates
//! - Supports Pre-Shared Keys (PSKs) for additional security
//! - Implements truncation of old ratchet states
//! - Provides safe access to underlying crypto container
//!
//! # Usage
//! The RatchetManager requires a Sink for sending messages, a Stream for receiving messages,
//! and a Ratchet implementation. It manages the full key ratcheting protocol between peers:
//!
//! ```rust,no_run
//! use citadel_crypt::endpoint_crypto_container::PeerSessionCrypto;
//! use citadel_crypt::ratchet_manager::{RatchetManager, RatchetMessage};
//!
//! async fn example<S, I, R>(
//!     sender: S,
//!     receiver: I,
//!     container: PeerSessionCrypto<R>,
//!     psks: &[Vec<u8>]
//! ) -> Result<(), Box<dyn std::error::Error>>
//! where
//!     S: Sink<RatchetMessage> + Unpin,
//!     I: Stream<Item = RatchetMessage> + Unpin,
//!     R: Ratchet,
//! {
//!     let mut manager = RatchetManager::new(sender, receiver, container, psks);
//!     // Trigger a ratchet update
//!     manager.rekey().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//! - The ratcheting protocol is asynchronous and requires both peers to complete their respective roles
//! - The protocol ensures forward secrecy through regular key updates
//! - Truncation of old ratchet states helps manage memory usage while maintaining security
//!
//! # Related Components
//! - [`PeerSessionCrypto`]: The underlying crypto container managed by this component
//! - [`Ratchet`]: The trait defining the ratcheting behavior
//! - [`EndpointRatchetConstructor`]: Handles the construction of new ratchet states
//!

use crate::endpoint_crypto_container::{
    EndpointRatchetConstructor, KemTransferStatus, PeerSessionCrypto,
};
use crate::misc::CryptError;
use crate::ratchets::Ratchet;
use atomic::Atomic;
use bytemuck::NoUninit;
use citadel_io::tokio::sync::Mutex as TokioMutex;
use citadel_io::tokio_stream::Stream;
use citadel_io::{Mutex, RwLock};
use futures::{Sink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub struct RatchetManager<S, I, R>
where
    R: Ratchet,
{
    sender: Arc<TokioMutex<S>>,
    receiver: Arc<Mutex<Option<I>>>,
    container: Arc<RwLock<PeerSessionCrypto<R>>>,
    cid: u64,
    psks: Arc<Vec<Vec<u8>>>,
    role: Arc<Atomic<RekeyRole>>,
    constructor: Arc<Mutex<Option<R::Constructor>>>,
    is_initiator: bool,
    state: Arc<Atomic<RekeyState>>,
    local_listener:
        Arc<Mutex<Option<citadel_io::tokio::sync::oneshot::Sender<Option<CryptError>>>>>,
}

impl<S, I, R: Ratchet> Clone for RatchetManager<S, I, R> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            receiver: self.receiver.clone(),
            container: self.container.clone(),
            cid: self.cid,
            psks: self.psks.clone(),
            role: self.role.clone(),
            constructor: self.constructor.clone(),
            is_initiator: self.is_initiator,
            state: self.state.clone(),
            local_listener: self.local_listener.clone(),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, NoUninit)]
#[repr(u8)]
pub enum RekeyState {
    Running,
    Halted,
    Idle,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, NoUninit, Serialize, Deserialize)]
#[repr(u8)]
pub enum RekeyRole {
    Idle,
    Leader,
    Loser,
}

#[derive(Serialize, Deserialize)]
pub enum RatchetMessage {
    AliceToBob {
        payload: Vec<u8>,
        earliest_ratchet_version: u32,
        latest_ratchet_version: u32,
    }, // Serialized transfer
    BobToAlice(Vec<u8>, RekeyRole), // Serialized transfer + sender's role
    Truncate(u32),                  // Version to truncate
    LeaderCanFinish {
        latest_version: u32,
    },
    LoserCanFinish,
}

impl Debug for RatchetMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetMessage::AliceToBob { .. } => write!(f, "AliceToBob"),
            RatchetMessage::BobToAlice(_, role) => write!(f, "BobToAlice(sender_role: {:?})", role),
            RatchetMessage::Truncate(_) => write!(f, "Truncate"),
            RatchetMessage::LeaderCanFinish { .. } => write!(f, "LeaderCanFinish"),
            RatchetMessage::LoserCanFinish => write!(f, "LoserCanFinish"),
        }
    }
}

impl<S, I, R> RatchetManager<S, I, R>
where
    S: Sink<RatchetMessage> + Send + Unpin + 'static,
    I: Stream<Item = RatchetMessage> + Send + Unpin + 'static,
    R: Ratchet,
    <S as futures::Sink<RatchetMessage>>::Error: std::fmt::Debug,
{
    pub fn new<T: AsRef<[u8]>>(
        sender: S,
        receiver: I,
        container: PeerSessionCrypto<R>,
        psks: &[T],
    ) -> Self {
        let cid = container.toolset.cid;
        let is_initiator = container.local_is_initiator;

        let this = Self {
            sender: Arc::new(TokioMutex::new(sender)),
            receiver: Arc::new(Mutex::new(Some(receiver))),
            container: Arc::new(RwLock::new(container)),
            cid,
            is_initiator,
            constructor: Arc::new(Mutex::new(None)),
            psks: Arc::new(psks.iter().map(|psk| psk.as_ref().to_vec()).collect()),
            role: Arc::new(Atomic::new(RekeyRole::Idle)),
            state: Arc::new(Atomic::new(RekeyState::Idle)),
            local_listener: Arc::new(Mutex::new(None)),
        };

        this.clone().spawn_rekey_process();
        this
    }

    /// Returns true if the re-key was a success, false if no re-key was needed
    pub async fn trigger_rekey(&self) -> Result<bool, CryptError> {
        log::info!(target: "citadel", "Client {} manually triggering rekey", self.cid);
        let state = self.state();
        if state == RekeyState::Halted {
            return Err(CryptError::RekeyUpdateError(
                "Rekey process is halted".to_string(),
            ));
        }

        if self.role() != RekeyRole::Idle {
            // We are already in a rekey process
            return Ok(false);
        }

        let (constructor, earliest_ratchet_version, latest_ratchet_version) = {
            let mut container = self.container.write();
            let constructor = container.get_next_constructor();
            let earliest_ratchet_version = container.toolset.get_oldest_stacked_ratchet_version();
            let latest_ratchet_version = container.latest_usable_version;
            (
                constructor,
                earliest_ratchet_version,
                latest_ratchet_version,
            )
        };

        if let Some(constructor) = constructor {
            let transfer = constructor.stage0_alice().ok_or_else(|| {
                CryptError::RekeyUpdateError("Failed to get initial transfer".to_string())
            })?;

            let payload = bincode::serialize(&transfer)
                .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;

            self.sender
                .lock()
                .await
                .send(RatchetMessage::AliceToBob {
                    payload,
                    earliest_ratchet_version,
                    latest_ratchet_version,
                })
                .await
                .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;
            log::debug!(target: "citadel", "Client {} sent initial AliceToBob transfer", self.cid);

            *self.constructor.lock() = Some(constructor);
            let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();

            *self.local_listener.lock() = Some(tx);
            let err = rx.await.map_err(|_| {
                CryptError::RekeyUpdateError("Failed to wait for local listener".to_string())
            })?;

            if let Some(err) = err {
                return Err(err);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn spawn_rekey_process(self) {
        struct DropWrapper {
            state: Arc<Atomic<RekeyState>>,
        }

        impl Drop for DropWrapper {
            fn drop(&mut self) {
                self.state.store(RekeyState::Halted, Ordering::Relaxed);
            }
        }

        let task = async move {
            let _drop_wrapper = DropWrapper {
                state: self.state.clone(),
            };
            let mut listener = { self.receiver.lock().take().unwrap() };
            loop {
                self.set_state(RekeyState::Running);
                let result = self.rekey(&mut listener).await;
                self.set_state(RekeyState::Idle);
                self.set_role(RekeyRole::Idle);

                let err = result.err();

                if let Some(notifier) = self.local_listener.lock().take() {
                    let _ = notifier.send(err.clone());
                }

                if let Some(err) = err {
                    log::error!("cid {} rekey error: {err:?}", self.cid);
                    continue;
                }
            }
        };

        drop(citadel_io::tokio::task::spawn(task));
    }

    /// Runs a single round of re-keying, listening to events and returning
    /// once a single re-key occurs. This function is intended to be used in a loop
    /// to continuously be ready for re-keying.
    async fn rekey(&self, receiver: &mut I) -> Result<(), CryptError> {
        log::trace!(target: "citadel", "Client {} starting rekey with initial role {:?}", self.cid, self.role());
        let is_initiator = self.is_initiator;
        let mut completed_as_leader = false;
        let mut completed_as_loser = false;

        loop {
            let msg = receiver.next().await;
            // log::debug!(target: "citadel", "Client {} received message {msg:?}", self.cid);
            match msg {
                Some(RatchetMessage::AliceToBob {
                    payload,
                    earliest_ratchet_version,
                    latest_ratchet_version,
                }) => {
                    let status = {
                        log::debug!(target: "citadel", "Client {} received AliceToBob", self.cid);
                        let mut container = self.container.write();

                        // Process the AliceToBob message as Bob
                        let transfer = bincode::deserialize(&payload)
                            .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))?;

                        let cid = container.toolset.cid;
                        let local_earliest_ratchet_version =
                            container.toolset.get_oldest_stacked_ratchet_version();
                        let local_latest_ratchet_version = container.latest_usable_version;

                        if earliest_ratchet_version != local_earliest_ratchet_version {
                            log::warn!(target: "citadel", "Client {cid}: Earliest declared ratchet versions do not match. Local: {local_earliest_ratchet_version}, Peer: {earliest_ratchet_version}");
                            continue;
                        }

                        if latest_ratchet_version != local_latest_ratchet_version {
                            log::warn!(target: "citadel", "Client {cid}: Latest usable ratchet versions do not match. Local: {local_latest_ratchet_version}, Peer: {latest_ratchet_version}");
                            continue;
                        }

                        // Get next_opts from the container
                        let next_opts = container
                            .get_ratchet(None)
                            .ok_or_else(|| {
                                CryptError::RekeyUpdateError(
                                    "Failed to get stacked ratchet".to_string(),
                                )
                            })?
                            .get_next_constructor_opts();

                        // Create Bob constructor
                        let bob_constructor =
                            <R::Constructor as EndpointRatchetConstructor<R>>::new_bob(
                                self.cid, next_opts, transfer, &self.psks,
                            )
                            .ok_or_else(|| {
                                CryptError::RekeyUpdateError(
                                    "Failed to create bob constructor".to_string(),
                                )
                            })?;

                        container.update_sync_safe(bob_constructor, false)?
                    };

                    match status {
                        KemTransferStatus::Some(transfer, _) => {
                            let serialized = bincode::serialize(&transfer)
                                .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;

                            log::trace!(target: "citadel", "Client {} must send BobToAlice", self.cid);

                            {
                                let container = self.container.write();
                                let _ = container.update_in_progress.toggle_on_if_untoggled();
                                self.set_role(RekeyRole::Loser);
                                drop(container);
                            }

                            self.sender
                                .lock()
                                .await
                                .send(RatchetMessage::BobToAlice(serialized, RekeyRole::Loser))
                                .await
                                .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;
                            log::debug!(
                                target: "citadel",
                                "Client {} is {:?}. Sent BobToAlice",
                                self.cid,
                                self.role(),
                            );
                        }
                        KemTransferStatus::Contended => {
                            // The package that we received did not result in a re-key. OUR package will result in a re-key.
                            // Therefore, we will wait for the adjacent node to drive us to completion so we both have the same ratchet
                            self.set_role(RekeyRole::Leader);
                            log::debug!(target: "citadel", "[Contention] Client {} is {:?}. contention detected. We will wait for the adjacent node to drive us to completion", self.cid, RekeyRole::Leader);
                        }
                        _ => {
                            log::warn!(
                                target: "citadel",
                                "cid {} unexpected status for AliceToBob Transfer: {status:?}",
                                self.cid
                            );
                        }
                    }
                }

                Some(RatchetMessage::BobToAlice(transfer_data, sender_role)) => {
                    log::debug!(target: "citadel", "Client {} received BobToAlice", self.cid);
                    // If the sender became a Loser, they expect us to be Leader
                    let initial_role = self.role();
                    if sender_role == RekeyRole::Loser && initial_role != RekeyRole::Leader {
                        self.set_role(RekeyRole::Leader);
                        log::trace!(target: "citadel", "cid {} changing role from {:?} to {:?}", self.cid, initial_role, RekeyRole::Leader);
                        log::debug!(
                            target: "citadel",
                            "Client {} transitioning from {initial_role:?} to Leader as peer became Loser before we were able to transition",
                            self.cid
                        );
                    }

                    // Now verify we're in a valid state to process the message
                    if self.role() == RekeyRole::Loser {
                        return Err(CryptError::RekeyUpdateError(format!(
                            "Unexpected BobToAlice message since our role is not Leader, but {:?}",
                            self.role()
                        )));
                    }

                    if initial_role == RekeyRole::Idle {
                        log::warn!(target: "citadel", "Initial role was idle. Their role: {sender_role:?}");
                    }

                    let mut constructor = { self.constructor.lock().take() };

                    if let Some(mut alice_constructor) = constructor.take() {
                        let transfer = bincode::deserialize(&transfer_data).map_err(|e| {
                            CryptError::RekeyUpdateError(format!(
                                "Failed to deserialize transfer: {e}"
                            ))
                        })?;

                        alice_constructor.stage1_alice(transfer, &self.psks)?;
                        let status = {
                            self.container
                                .write()
                                .update_sync_safe(alice_constructor, true)?
                        };

                        let truncation_required = status.requires_truncation();

                        let expected_status = matches!(
                            status,
                            KemTransferStatus::StatusNoTransfer(..) | KemTransferStatus::Contended
                        );

                        if expected_status {
                            if let Some(version_to_truncate) = truncation_required {
                                {
                                    self.container
                                        .write()
                                        .deregister_oldest_stacked_ratchet(version_to_truncate)?;
                                }

                                self.sender
                                    .lock()
                                    .await
                                    .send(RatchetMessage::Truncate(version_to_truncate))
                                    .await
                                    .map_err(|err| {
                                        CryptError::RekeyUpdateError(format!("{err:?}"))
                                    })?;
                                // We need to wait to be marked as complete
                            } else {
                                // Send LoserCanFinish to Bob so he can finish
                                self.sender
                                    .lock()
                                    .await
                                    .send(RatchetMessage::LoserCanFinish)
                                    .await
                                    .map_err(|err| {
                                        CryptError::RekeyUpdateError(format!("{err:?}"))
                                    })?;
                            }
                        } else {
                            log::warn!(target:"citadel", "Client {} unexpected status as Leader: {status:?}", self.cid);
                        }
                    } else {
                        return Err(CryptError::RekeyUpdateError(
                            "Unexpected BobToAlice message with no loaded local constructor"
                                .to_string(),
                        ));
                    }
                }

                Some(RatchetMessage::Truncate(version_to_truncate)) => {
                    let role = self.role();
                    // Allow Loser if contention, or Idle if no contention
                    log::debug!(target: "citadel", "Client {} received Truncate", self.cid);
                    if role != RekeyRole::Loser {
                        return Err(CryptError::RekeyUpdateError(format!(
                            "Unexpected Truncate message since our role is not Loser, but {:?}",
                            role
                        )));
                    }

                    let latest_version = {
                        let mut container = self.container.write();
                        container.deregister_oldest_stacked_ratchet(version_to_truncate)?;
                        container.post_alice_stage1_or_post_stage1_bob();
                        let latest_actual_ratchet_version = container
                            .maybe_unlock()
                            .expect("Failed to fetch ratchet")
                            .version();
                        let latest_version = container.latest_usable_version;
                        if latest_actual_ratchet_version != latest_version {
                            log::warn!(target:"citadel", "Client {} received Truncate, but, update failed. Actual: {latest_actual_ratchet_version}, Expected: {latest_version} ", self.cid);
                        }
                        latest_version
                    };

                    completed_as_loser = true;

                    self.sender
                        .lock()
                        .await
                        .send(RatchetMessage::LeaderCanFinish { latest_version })
                        .await
                        .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;
                    break;
                }

                Some(RatchetMessage::LoserCanFinish) => {
                    // Allow Loser if contention, or Idle if no contention
                    let role = self.role();
                    if role != RekeyRole::Loser {
                        return Err(CryptError::RekeyUpdateError(
                            format!("Unexpected LoserCanFinish message since our role is not Loser, but {:?}", role)
                        ));
                    }

                    log::debug!(target: "citadel", "Client {} received LoserCanFinish", self.cid);

                    let latest_version = {
                        let mut container = self.container.write();
                        container.post_alice_stage1_or_post_stage1_bob();
                        let latest_actual_ratchet_version = container
                            .maybe_unlock()
                            .expect("Failed to fetch ratchet")
                            .version();
                        let latest_version = container.latest_usable_version;
                        if latest_actual_ratchet_version != latest_version {
                            log::warn!(target:"citadel", "Client {} received LoserCanFinish but, update failed. Actual: {latest_actual_ratchet_version}, Expected: {latest_version} ", self.cid);
                        }
                        latest_version
                    };

                    completed_as_loser = true;

                    // Send a LeaderCanFinish to unlock them
                    self.sender
                        .lock()
                        .await
                        .send(RatchetMessage::LeaderCanFinish { latest_version })
                        .await
                        .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;
                    break;
                }

                Some(RatchetMessage::LeaderCanFinish { latest_version }) => {
                    let our_latest_version = {
                        let container = self.container.read();
                        container.latest_usable_version
                    };

                    log::debug!("Client {} received LeaderCanFinish w/ latest_version = {latest_version} | our latest version: {our_latest_version}", self.cid);
                    // Allow Leader if contention, or Idle if no contention
                    let role = self.role();
                    if role != RekeyRole::Leader {
                        return Err(CryptError::RekeyUpdateError(format!(
                            "Unexpected AliceCanFinish message since our role is not Leader, but {:?}",
                            role
                        )));
                    }

                    {
                        let mut container = self.container.write();
                        container.post_alice_stage1_or_post_stage1_bob();
                        let latest_actual_ratchet_version = container
                            .maybe_unlock()
                            .expect("Failed to fetch ratchet")
                            .version();
                        let latest_declared_version = container.latest_usable_version;
                        if latest_actual_ratchet_version != latest_declared_version {
                            log::warn!(target:"citadel", "Client {} received Truncate, desynced. Actual: {latest_actual_ratchet_version}, Expected: {latest_declared_version} ", self.cid);
                        }
                    }

                    completed_as_leader = true;
                    break;
                }

                None => {
                    return Err(CryptError::RekeyUpdateError(
                        "Unexpected end of stream".to_string(),
                    ));
                }
            }
        }

        log::debug!(
            target: "citadel",
            "Client {} completed re-key. Alice: {}, Bob: {}. Final version: {}. Final Declared Version: {}. Is initiator: {}",
            self.cid,
            completed_as_leader,
            completed_as_loser,
            self.get_ratchet(None).unwrap().version(),
            self.container.read().latest_usable_version,
            is_initiator
        );

        log::debug!(target: "citadel", "*** cid {} rekey completed", self.cid);

        Ok(())
    }

    pub fn get_ratchet(&self, version: Option<u32>) -> Option<R> {
        self.container.read().get_ratchet(version).cloned()
    }

    pub fn role(&self) -> RekeyRole {
        self.role.load(Ordering::Relaxed)
    }

    fn set_role(&self, role: RekeyRole) {
        log::trace!(target: "citadel", "Client {} changing role from {:?} to {:?}", self.cid, self.role(), role);
        self.role.store(role, Ordering::SeqCst);
    }

    pub fn state(&self) -> RekeyState {
        self.state.load(Ordering::Relaxed)
    }

    fn set_state(&self, state: RekeyState) {
        self.state.store(state, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use crate::endpoint_crypto_container::{EndpointRatchetConstructor, PeerSessionCrypto};
    use crate::prelude::Toolset;
    use crate::ratchet_manager::{RatchetManager, RatchetMessage};
    use crate::ratchets::stacked::stacked_ratchet::StackedRatchet;
    use crate::ratchets::Ratchet;
    use citadel_io::tokio;
    use citadel_pqcrypto::constructor_opts::ConstructorOpts;
    use citadel_types::prelude::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
    use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
    use futures::{Sink, Stream};
    use rstest::rstest;
    use std::time::Duration;

    const ALICE_CID: u64 = 10;
    const BOB_CID: u64 = 20;
    pub const TEST_PSKS: &[&[u8]] = &[b"test_psk_1", b"test_psk_2"];
    const START_VERSION: u32 = 0;

    fn gen<R: Ratchet, T: AsRef<[u8]>>(
        version: u32,
        opts: Vec<ConstructorOpts>,
        psks: &[T],
    ) -> (R, R) {
        let mut cx_alice = R::Constructor::new_alice(opts.clone(), ALICE_CID, version).unwrap();
        let mut cx_bob =
            R::Constructor::new_bob(BOB_CID, opts, cx_alice.stage0_alice().unwrap(), psks).unwrap();
        cx_alice
            .stage1_alice(cx_bob.stage0_bob().unwrap(), psks)
            .unwrap();

        (cx_alice.finish().unwrap(), cx_bob.finish().unwrap())
    }

    pub(crate) fn setup_endpoint_containers<R: Ratchet>(
        security_level: SecurityLevel,
        enx: EncryptionAlgorithm,
        kem: KemAlgorithm,
    ) -> (PeerSessionCrypto<R>, PeerSessionCrypto<R>) {
        let opts = ConstructorOpts::new_vec_init(Some(enx + kem), security_level);
        let (hr_alice, hr_bob) = gen::<R, _>(START_VERSION, opts, TEST_PSKS);
        assert_eq!(hr_alice.version(), START_VERSION);
        assert_eq!(hr_bob.version(), START_VERSION);
        assert_eq!(hr_alice.get_cid(), ALICE_CID);
        assert_eq!(hr_bob.get_cid(), BOB_CID);
        let alice_container = PeerSessionCrypto::new(Toolset::new(ALICE_CID, hr_alice), true);
        let bob_container = PeerSessionCrypto::new(Toolset::new(BOB_CID, hr_bob), false);
        (alice_container, bob_container)
    }

    type TestRatchetManager<R> =
        RatchetManager<UnboundedSender<RatchetMessage>, UnboundedReceiver<RatchetMessage>, R>;

    fn create_ratchet_managers<R: Ratchet>() -> (TestRatchetManager<R>, TestRatchetManager<R>) {
        let security_level = SecurityLevel::Standard;

        let (alice_container, bob_container) = setup_endpoint_containers::<R>(
            security_level,
            EncryptionAlgorithm::AES_GCM_256,
            KemAlgorithm::Kyber,
        );

        let (tx_alice, rx_bob) = futures::channel::mpsc::unbounded();
        let (tx_bob, rx_alice) = futures::channel::mpsc::unbounded();

        let alice_manager = RatchetManager::new(tx_alice, rx_alice, alice_container, TEST_PSKS);
        let bob_manager = RatchetManager::new(tx_bob, rx_bob, bob_container, TEST_PSKS);
        (alice_manager, bob_manager)
    }

    pub(crate) fn pre_round_assertions<R: Ratchet>(
        alice_container: &PeerSessionCrypto<R>,
        alice_cid: u64,
        bob_container: &PeerSessionCrypto<R>,
        bob_cid: u64,
    ) -> (u32, u32) {
        assert_eq!(
            alice_container.get_ratchet(None).unwrap().get_cid(),
            alice_cid
        );
        assert_eq!(bob_container.get_ratchet(None).unwrap().get_cid(), bob_cid);

        let start_version = alice_container
            .toolset
            .get_most_recent_stacked_ratchet_version();
        let new_version = start_version + 1;
        let new_version_bob = bob_container
            .toolset
            .get_most_recent_stacked_ratchet_version()
            + 1;
        assert_eq!(new_version, new_version_bob);
        (start_version, new_version)
    }

    async fn run_round_racy<
        S: Sink<RatchetMessage> + Unpin + Send + 'static,
        I: Stream<Item = RatchetMessage> + Unpin + Send + 'static,
        R: Ratchet,
    >(
        container_0: RatchetManager<S, I, R>,
        container_1: RatchetManager<S, I, R>,
        container_0_delay: Option<Duration>,
    ) where
        <S as futures::Sink<RatchetMessage>>::Error: std::fmt::Debug,
    {
        let cid_0 = container_0.cid;
        let cid_1 = container_1.cid;

        let (_start_version, _next_version) = pre_round_assertions(
            &*container_0.container.read(),
            cid_0,
            &*container_1.container.read(),
            cid_1,
        );

        let task = |container: RatchetManager<S, I, R>, delay: Option<Duration>| async move {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            let res = container.trigger_rekey().await;
            log::debug!(target: "citadel", "*** [FINISHED] Client {} rekey result: {res:?}", container.cid);
            res
        };

        // Randomly assign a delay to Alice or Bob, if applicable
        let (delay_0, delay_1) = if let Some(delay) = container_0_delay {
            if delay.as_millis() % 2 == 0 {
                (Some(delay), None)
            } else {
                (None, Some(delay))
            }
        } else {
            (None, None)
        };

        log::info!(target: "citadel", "~~~~ Beginning next round! ~~~~");
        // Spawn Alice's task
        let alice_handle = tokio::spawn(task(container_0.clone(), delay_0));

        // Spawn Bob's task
        let bob_handle = tokio::spawn(task(container_1.clone(), delay_1));

        // Wait for both tasks to complete
        let (alice_result, bob_result) = tokio::join!(alice_handle, bob_handle);

        // Update original containers with final state
        let _rekey_0_res = alice_result.unwrap().unwrap();
        let _rekey_1_res = bob_result.unwrap().unwrap();

        post_checks(&container_0, &container_1);
        log::info!(target: "citadel", "~~~~ Round ended! ~~~~");
    }

    async fn run_round_one_node_only<
        S: Sink<RatchetMessage> + Unpin + Send + 'static,
        I: Stream<Item = RatchetMessage> + Unpin + Send + 'static,
        R: Ratchet,
    >(
        container_0: RatchetManager<S, I, R>,
        container_1: RatchetManager<S, I, R>,
    ) where
        <S as futures::Sink<RatchetMessage>>::Error: std::fmt::Debug,
    {
        let cid_0 = container_0.cid;
        let cid_1 = container_1.cid;

        let (_start_version, _next_version) = pre_round_assertions(
            &*container_0.container.read(),
            cid_0,
            &*container_1.container.read(),
            cid_1,
        );

        let task = |container: RatchetManager<S, I, R>, skip: bool| async move {
            if skip {
                return Ok(false);
            }
            let res = container.trigger_rekey().await;
            log::debug!(target: "citadel", "*** [FINISHED] Client {} rekey result: {res:?}", container.cid);
            res
        };

        // Randomly assign a delay to Alice or Bob, if applicable
        let (alice_skips, bob_skips) = {
            if rand::random::<usize>() % 2 == 0 {
                (true, false)
            } else {
                (false, true)
            }
        };

        // Spawn Alice's task
        let alice_handle = tokio::spawn(task(container_0.clone(), alice_skips));

        // Spawn Bob's task
        let bob_handle = tokio::spawn(task(container_1.clone(), bob_skips));

        // Wait for both tasks to complete
        let (alice_result, bob_result) = tokio::join!(alice_handle, bob_handle);

        // Update original containers with final state
        let rekey_0_res = alice_result.unwrap().unwrap();
        let rekey_1_res = bob_result.unwrap().unwrap();
        assert_eq!(rekey_0_res, !alice_skips);
        assert_eq!(rekey_1_res, !bob_skips);

        post_checks(&container_0, &container_1);
    }

    pub(crate) fn ratchet_encrypt_decrypt_test<R: Ratchet>(
        container_0: &PeerSessionCrypto<R>,
        cid_0: u64,
        container_1: &PeerSessionCrypto<R>,
        cid_1: u64,
        expected_version: u32,
    ) {
        let test_message = b"Hello, World!";
        let alice_ratchet = container_0.get_ratchet(None).unwrap();
        assert_eq!(alice_ratchet.version(), expected_version);
        assert_eq!(alice_ratchet.get_cid(), cid_0);
        let encrypted = alice_ratchet.encrypt(test_message).unwrap();

        let bob_ratchet = container_1.get_ratchet(None).unwrap();
        assert_eq!(bob_ratchet.version(), expected_version);
        assert_eq!(bob_ratchet.get_cid(), cid_1);
        let decrypted = bob_ratchet.decrypt(&encrypted).unwrap();
        assert_eq!(test_message.to_vec(), decrypted);
    }

    fn post_checks<
        S: Sink<RatchetMessage> + Unpin + Send + 'static,
        I: Stream<Item = RatchetMessage> + Unpin + Send + 'static,
        R: Ratchet,
    >(
        container_0: &RatchetManager<S, I, R>,
        container_1: &RatchetManager<S, I, R>,
    ) where
        <S as futures::Sink<RatchetMessage>>::Error: std::fmt::Debug,
    {
        // Verify final state
        let cid_0 = container_0.cid;
        let cid_1 = container_1.cid;
        let alice_declared_latest_version = container_0.container.read().latest_usable_version;
        let bob_declared_latest_version = container_1.container.read().latest_usable_version;
        assert_eq!(alice_declared_latest_version, bob_declared_latest_version);
        let alice_ratchet = container_0.get_ratchet(None).unwrap();
        let bob_ratchet = container_1.get_ratchet(None).unwrap();
        assert_eq!(alice_ratchet.version(), bob_ratchet.version());

        let alice_ratchet_version = alice_ratchet.version();

        ratchet_encrypt_decrypt_test(
            &*container_0.container.read(),
            cid_0,
            &*container_1.container.read(),
            cid_1,
            alice_ratchet_version,
        );
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(60))]
    #[tokio::test]
    async fn test_ratchet_manager_racy_contentious() {
        citadel_logging::setup_log();
        let (alice_manager, bob_manager) = create_ratchet_managers::<StackedRatchet>();
        const ROUNDS: usize = 100;
        for _ in 0..ROUNDS {
            run_round_racy(alice_manager.clone(), bob_manager.clone(), None).await;
        }

        assert_eq!(
            alice_manager.container.read().latest_usable_version,
            ROUNDS as u32
        );
        assert_eq!(
            bob_manager.container.read().latest_usable_version,
            ROUNDS as u32
        );
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(360))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ratchet_manager_racy_with_random_start_lag(
        #[values(0, 1, 10, 100, 500)] min_delay: u64,
    ) {
        citadel_logging::setup_log();
        let (alice_manager, bob_manager) = create_ratchet_managers::<StackedRatchet>();
        const ROUNDS: usize = 100;
        for _ in 0..ROUNDS {
            let delay = rand::random::<u64>() % 5;
            let delay = Duration::from_millis(min_delay + delay);
            run_round_racy(alice_manager.clone(), bob_manager.clone(), Some(delay)).await;
        }
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(60))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ratchet_manager_one_at_a_time() {
        citadel_logging::setup_log();
        let (alice_manager, bob_manager) = create_ratchet_managers::<StackedRatchet>();
        const ROUNDS: usize = 100;
        for _ in 0..ROUNDS {
            run_round_one_node_only(alice_manager.clone(), bob_manager.clone()).await;
        }

        assert_eq!(
            alice_manager.container.read().latest_usable_version,
            ROUNDS as u32
        );
        assert_eq!(
            bob_manager.container.read().latest_usable_version,
            ROUNDS as u32
        );
    }
}
