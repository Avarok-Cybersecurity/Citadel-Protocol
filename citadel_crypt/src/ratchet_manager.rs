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
use crate::stacked_ratchet::Ratchet;
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
    AliceToBob(Vec<u8>),            // Serialized transfer
    BobToAlice(Vec<u8>, RekeyRole), // Serialized transfer + sender's role
    Truncate(u32),                  // Version to truncate
    LeaderCanFinish,
    LoserCanFinish,
}

impl Debug for RatchetMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetMessage::AliceToBob(_) => write!(f, "AliceToBob"),
            RatchetMessage::BobToAlice(_, role) => write!(f, "BobToAlice(sender_role: {:?})", role),
            RatchetMessage::Truncate(_) => write!(f, "Truncate"),
            RatchetMessage::LeaderCanFinish => write!(f, "LeaderCanFinish"),
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
    pub async fn trigger_rekey(&mut self) -> Result<bool, CryptError> {
        if self.state() == RekeyState::Halted {
            return Err(CryptError::RekeyUpdateError(
                "Rekey process is halted".to_string(),
            ));
        }

        let constructor = { self.container.write().get_next_constructor(false) };

        if let Some(constructor) = constructor {
            let transfer = constructor.stage0_alice().ok_or_else(|| {
                CryptError::RekeyUpdateError("Failed to get initial transfer".to_string())
            })?;

            let serialized = bincode::serialize(&transfer)
                .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;

            self.sender
                .lock()
                .await
                .send(RatchetMessage::AliceToBob(serialized))
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

                let err = result.err();

                if let Some(notifier) = self.local_listener.lock().take() {
                    let _ = notifier.send(err.clone());
                }

                if let Some(err) = err {
                    log::error!("cid {} rekey error: {err:?}", self.cid);
                    break;
                }
            }
        };

        drop(citadel_io::tokio::task::spawn(task));
    }

    /// Runs a single round of re-keying, listening to events and returning
    /// once a single re-key occurs. This function is intended to be used in a loop
    /// to continuously be ready for re-keying.
    async fn rekey(&self, receiver: &mut I) -> Result<(), CryptError> {
        let is_initiator = self.is_initiator;
        let mut completed_as_leader = false;
        let mut completed_as_loser = false;

        loop {
            let msg = receiver.next().await;
            log::debug!(target: "citadel", "Client {} received message {msg:?}", self.cid);
            match msg {
                Some(RatchetMessage::AliceToBob(transfer_data)) => {
                    log::debug!("cid {} received AliceToBob", self.cid);

                    // Process the AliceToBob message as Bob
                    let transfer = bincode::deserialize(&transfer_data)
                        .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))?;

                    let status = {
                        let mut container = self.container.write();
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

                        container.update_sync_safe(
                            bob_constructor,
                            self.role() != RekeyRole::Loser,
                            self.cid,
                            false,
                        )?
                    };

                    match status {
                        KemTransferStatus::Some(transfer, _) => {
                            let serialized = bincode::serialize(&transfer)
                                .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;

                            {
                                let container = self.container.write();
                                let _ = container.update_in_progress.toggle_on_if_untoggled();
                                drop(container);
                            }

                            self.set_role(RekeyRole::Loser);
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
                                RekeyRole::Loser
                            );
                        }
                        KemTransferStatus::Contended => {
                            // The package that we received did not result in a re-key. OUR package will result in a re-key.
                            // Therefore, we will wait for the adjacent node to drive us to completion so we both have the same ratchet
                            self.set_role(RekeyRole::Leader);
                            log::debug!("cid {} is {:?}. contention detected. We will wait for the adjacent node to drive us to completion", self.cid, RekeyRole::Leader);
                        }
                        _ => {
                            log::warn!(
                                "cid {} unexpected status for AliceToBob Transfer: {status:?}",
                                self.cid
                            );
                        }
                    }
                }
                Some(RatchetMessage::BobToAlice(transfer_data, sender_role)) => {
                    // If the sender became a Loser, they expect us to be Leader
                    if sender_role == RekeyRole::Loser && self.role() != RekeyRole::Leader {
                        log::debug!(
                            target: "citadel",
                            "Client {} transitioning to Leader as peer became Loser before we were able to transition",
                            self.cid
                        );
                        self.set_role(RekeyRole::Leader);
                    }

                    // Now verify we're in a valid state to process the message
                    if self.role() == RekeyRole::Loser {
                        return Err(CryptError::RekeyUpdateError(format!(
                            "Unexpected BobToAlice message since our role is not Leader, but {:?}",
                            self.role()
                        )));
                    }

                    let mut constructor = { self.constructor.lock().take() };

                    log::debug!(target: "citadel", "Client {} received BobToAlice", self.cid);
                    if let Some(mut alice_constructor) = constructor.take() {
                        let transfer = bincode::deserialize(&transfer_data).map_err(|e| {
                            CryptError::RekeyUpdateError(format!(
                                "Failed to deserialize transfer: {e}"
                            ))
                        })?;

                        alice_constructor.stage1_alice(transfer, &self.psks)?;
                        let status = {
                            self.container.write().update_sync_safe(
                                alice_constructor,
                                false,
                                self.cid,
                                true,
                            )?
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
                                // Send TruncateAck to Bob so he can finish
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
                    // Allow Loser if contention, or Idle if no contention
                    if self.role() == RekeyRole::Leader {
                        return Err(CryptError::RekeyUpdateError(format!(
                            "Unexpected Truncate message since our role is not Bob, but {:?}",
                            self.role()
                        )));
                    }

                    log::debug!(target: "citadel", "Client {} received Truncate", self.cid);

                    {
                        let mut container = self.container.write();
                        container.deregister_oldest_stacked_ratchet(version_to_truncate)?;

                        container.post_alice_stage1_or_post_stage1_bob();
                        let _ = container.maybe_unlock(false);
                    }

                    completed_as_loser = true;

                    self.sender
                        .lock()
                        .await
                        .send(RatchetMessage::LeaderCanFinish)
                        .await
                        .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;
                    break;
                }
                Some(RatchetMessage::LeaderCanFinish) => {
                    // Allow Leader if contention, or Idle if no contention
                    if self.role() == RekeyRole::Loser {
                        return Err(CryptError::RekeyUpdateError(format!(
                            "Unexpected AliceCanFinish message since our role is not Bob, but {:?}",
                            self.role()
                        )));
                    }
                    log::debug!(target: "citadel", "Client {} received LeaderCanFinish", self.cid);

                    {
                        let mut container = self.container.write();
                        container.post_alice_stage1_or_post_stage1_bob();
                        let _ = container.maybe_unlock(false);
                    }

                    completed_as_leader = true;
                    break;
                }

                Some(RatchetMessage::LoserCanFinish) => {
                    // Allow Loser if contention, or Idle if no contention
                    if self.role() == RekeyRole::Leader {
                        return Err(CryptError::RekeyUpdateError(
                            format!("Unexpected LoserCanFinish message since our role is not Loser, but {:?}", self.role())
                        ));
                    }

                    log::debug!(target: "citadel", "Client {} received LoserCanFinish", self.cid);

                    {
                        let mut container = self.container.write();
                        container.post_alice_stage1_or_post_stage1_bob();
                        let _ = container.maybe_unlock(false);
                    }
                    completed_as_loser = true;

                    // Send a LeaderCanFinish to unlock them
                    self.sender
                        .lock()
                        .await
                        .send(RatchetMessage::LeaderCanFinish)
                        .await
                        .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;
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
            "Client {} completed re-key. Alice: {}, Bob: {}. Final version: {}. Is initiator: {}",
            self.cid,
            completed_as_leader,
            completed_as_loser,
            self.get_ratchet(None).unwrap().version(),
            is_initiator
        );

        debug_assert_eq!(
            completed_as_leader, !is_initiator,
            "Client {} completed wrong role. Is initiator: {is_initiator}, Completed as Leader: {completed_as_leader}",
            self.cid
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
        self.role.store(role, Ordering::Relaxed);
    }

    pub fn state(&self) -> RekeyState {
        self.state.load(Ordering::Relaxed)
    }

    fn set_state(&self, state: RekeyState) {
        self.state.store(state, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod racy {
    use crate::endpoint_crypto_container::no_race::TEST_PSKS;
    use crate::ratchet_manager::{RatchetManager, RatchetMessage, RekeyRole};
    use crate::stacked_ratchet::Ratchet;
    use citadel_io::tokio;
    use citadel_types::prelude::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
    use futures::{Sink, Stream};
    use rstest::rstest;
    use std::time::Duration;

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

        let (_start_version, _next_version) =
            crate::endpoint_crypto_container::no_race::pre_round_assertions(
                &*container_0.container.read(),
                cid_0,
                &*container_1.container.read(),
                cid_1,
            );

        let task = |mut container: RatchetManager<S, I, R>, delay: Option<Duration>| async move {
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

        // Spawn Alice's task
        let alice_handle = tokio::spawn(task(container_0.clone(), delay_0));

        // Spawn Bob's task
        let bob_handle = tokio::spawn(task(container_1.clone(), delay_1));

        // Wait for both tasks to complete
        let (alice_result, bob_result) = tokio::join!(alice_handle, bob_handle);

        // Update original containers with final state
        let rekey_0_res = alice_result.unwrap().unwrap();
        let rekey_1_res = bob_result.unwrap().unwrap();

        assert!(rekey_0_res, "Alice failed to rekey");
        assert!(rekey_1_res, "Bob failed to rekey");

        // Verify final state
        let alice_ratchet = container_0.get_ratchet(None).unwrap();
        let bob_ratchet = container_1.get_ratchet(None).unwrap();
        assert_eq!(alice_ratchet.version(), bob_ratchet.version());

        let alice_ratchet_version = alice_ratchet.version();

        crate::endpoint_crypto_container::no_race::ratchet_encrypt_decrypt_test(
            &*container_0.container.read(),
            cid_0,
            &*container_1.container.read(),
            cid_1,
            alice_ratchet_version,
        );
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(30))]
    #[tokio::test]
    async fn test_endpoint_container_racy_basic() {
        citadel_logging::setup_log();
        let security_level = SecurityLevel::Standard;

        let (alice_container, bob_container) =
            crate::endpoint_crypto_container::no_race::setup_endpoint_containers(
                security_level,
                EncryptionAlgorithm::AES_GCM_256,
                KemAlgorithm::Kyber,
            );

        let (tx_alice, rx_bob) = futures::channel::mpsc::unbounded();
        let (tx_bob, rx_alice) = futures::channel::mpsc::unbounded();

        let alice_manager = RatchetManager::new(tx_alice, rx_alice, alice_container, TEST_PSKS);
        let bob_manager = RatchetManager::new(tx_bob, rx_bob, bob_container, TEST_PSKS);

        const ROUNDS: usize = 100;
        for _ in 0..ROUNDS {
            run_round_racy(alice_manager.clone(), bob_manager.clone(), None).await;
        }
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(30))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_endpoint_container_racy_with_random_start_lag() {
        citadel_logging::setup_log();
        let security_level = SecurityLevel::Standard;

        let (alice_container, bob_container) =
            crate::endpoint_crypto_container::no_race::setup_endpoint_containers(
                security_level,
                EncryptionAlgorithm::AES_GCM_256,
                KemAlgorithm::Kyber,
            );

        let (tx_alice, rx_bob) = futures::channel::mpsc::unbounded();
        let (tx_bob, rx_alice) = futures::channel::mpsc::unbounded();

        let alice_manager = RatchetManager::new(tx_alice, rx_alice, alice_container, TEST_PSKS);
        let bob_manager = RatchetManager::new(tx_bob, rx_bob, bob_container, TEST_PSKS);

        let mut initiator_leader_count = 0;
        let mut non_initiator_leader_count = 0;

        const ROUNDS: usize = 100;
        for _ in 0..ROUNDS {
            let delay = rand::random::<u8>() % 100;
            let delay = Duration::from_millis(delay as u64);
            run_round_racy(alice_manager.clone(), bob_manager.clone(), Some(delay)).await;

            if alice_manager.role() == RekeyRole::Leader {
                if alice_manager.is_initiator {
                    initiator_leader_count += 1;
                } else {
                    non_initiator_leader_count += 1;
                }
            }

            if bob_manager.role() == RekeyRole::Leader {
                if bob_manager.is_initiator {
                    initiator_leader_count += 1;
                } else {
                    non_initiator_leader_count += 1;
                }
            }
        }

        log::info!("initiator_leader_count: {initiator_leader_count}, non_initiator_leader_count: {non_initiator_leader_count}");
    }
}
