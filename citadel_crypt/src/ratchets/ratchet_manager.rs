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
//! use citadel_crypt::ratchets::ratchet_manager::{RatchetManager, RatchetMessage, RatchetManagerSink, RatchetManagerStream};
//! use citadel_crypt::ratchets::Ratchet;
//!
//! async fn example<S, I, R>(
//!     sender: S,
//!     receiver: I,
//!     container: PeerSessionCrypto<R>,
//!     psks: &[Vec<u8>]
//! ) -> Result<(), Box<dyn std::error::Error>>
//! where
//!     S: RatchetManagerSink<RatchetMessage<()>>,
//!     I: RatchetManagerStream<RatchetMessage<()>>,
//!     R: Ratchet,
//! {
//!     let mut manager = RatchetManager::new(sender, receiver, container, psks);
//!     // Trigger a ratchet update
//!     manager.trigger_rekey().await?;
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
use crate::prelude::Toolset;
use crate::ratchets::Ratchet;
use atomic::Atomic;
use bytemuck::NoUninit;
use citadel_io::tokio::sync::Mutex as TokioMutex;
use citadel_io::tokio_stream::Stream;
use citadel_io::{tokio, Mutex};
use futures::{Sink, SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub struct RatchetManager<S, I, R, P: AttachedPayload = ()>
where
    R: Ratchet,
{
    pub(crate) sender: Arc<TokioMutex<S>>,
    receiver: Arc<Mutex<Option<I>>>,
    pub(crate) session_crypto_state: PeerSessionCrypto<R>,
    attached_payload_tx: UnboundedSender<P>,
    attached_payload_rx: Arc<Mutex<Option<UnboundedReceiver<P>>>>,
    rekey_done_notifier: Arc<Mutex<Option<UnboundedReceiver<R>>>>,
    cid: u64,
    psks: Arc<Vec<Vec<u8>>>,
    role: Arc<Atomic<RekeyRole>>,
    constructor: Arc<Mutex<Option<R::Constructor>>>,
    is_initiator: bool,
    state: Arc<Atomic<RekeyState>>,
    local_listener: LocalListener<R>,
    shutdown_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

pub(crate) type LocalListener<R> = Arc<Mutex<Option<citadel_io::tokio::sync::oneshot::Sender<R>>>>;

impl<S, I, R: Ratchet, P: AttachedPayload> Clone for RatchetManager<S, I, R, P> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            receiver: self.receiver.clone(),
            session_crypto_state: self.session_crypto_state.clone(),
            cid: self.cid,
            psks: self.psks.clone(),
            role: self.role.clone(),
            attached_payload_tx: self.attached_payload_tx.clone(),
            attached_payload_rx: self.attached_payload_rx.clone(),
            rekey_done_notifier: self.rekey_done_notifier.clone(),
            constructor: self.constructor.clone(),
            is_initiator: self.is_initiator,
            state: self.state.clone(),
            local_listener: self.local_listener.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum RoleTransition {
    IdleToLeader,
    IdleToLoser,
    LeaderToIdle,
    LoserToIdle,
    Invalid,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyMetadata {
    current_version: u32,
    next_version: u32,
}

#[derive(Serialize, Deserialize)]
pub enum RatchetMessage<P> {
    AliceToBob {
        payload: Vec<u8>,
        earliest_ratchet_version: u32,
        latest_ratchet_version: u32,
        attached_payload: Option<P>,
        metadata: RekeyMetadata,
    },
    BobToAlice(Vec<u8>, RekeyRole, RekeyMetadata),
    Truncate(u32),
    LeaderCanFinish {
        version: u32,
    },
    LoserCanFinish,
    #[serde(bound = "")]
    JustMessage(P),
}

impl<P> Debug for RatchetMessage<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetMessage::AliceToBob { .. } => write!(f, "AliceToBob"),
            RatchetMessage::BobToAlice(_, role, _) => {
                write!(f, "BobToAlice(sender_role: {:?})", role)
            }
            RatchetMessage::Truncate(_) => write!(f, "Truncate"),
            RatchetMessage::LeaderCanFinish { .. } => write!(f, "LeaderCanFinish"),
            RatchetMessage::LoserCanFinish => write!(f, "LoserCanFinish"),
            RatchetMessage::JustMessage(_) => write!(f, "JustMessage"),
        }
    }
}

pub trait RatchetManagerSink<P: AttachedPayload>:
    Sink<RatchetMessage<P>> + Send + Sync + Unpin + 'static
{
}

impl<S, P: AttachedPayload> RatchetManagerSink<P> for S where
    S: Sink<RatchetMessage<P>> + Send + Sync + Unpin + 'static
{
}

pub trait RatchetManagerStream<P: AttachedPayload>:
    Stream<Item = RatchetMessage<P>> + Send + Sync + Unpin + 'static
{
}
impl<I, P: AttachedPayload> RatchetManagerStream<P> for I where
    I: Stream<Item = RatchetMessage<P>> + Send + Sync + Unpin + 'static
{
}

pub trait AttachedPayload: Send + Sync + 'static + Serialize + DeserializeOwned {}
impl<T: Send + Sync + 'static + Serialize + DeserializeOwned> AttachedPayload for T {}

pub type DefaultRatchetManager<E, R, P> = RatchetManager<
    Box<dyn RatchetManagerSink<P, Error = E>>,
    Box<dyn RatchetManagerStream<P>>,
    R,
    P,
>;

impl<S, I, R, P> RatchetManager<S, I, R, P>
where
    S: RatchetManagerSink<P>,
    I: RatchetManagerStream<P>,
    R: Ratchet,
    P: AttachedPayload,
{
    pub fn new<T: AsRef<[u8]>>(
        sender: S,
        receiver: I,
        container: PeerSessionCrypto<R>,
        psks: &[T],
    ) -> Self {
        let cid = container.cid();
        let is_initiator = container.local_is_initiator();
        let (attached_payload_tx, attached_payload_rx) = tokio::sync::mpsc::unbounded_channel();
        let (rekey_done_notifier_tx, rekey_done_notifier) = tokio::sync::mpsc::unbounded_channel();
        let rekey_done_notifier = Arc::new(Mutex::new(Some(rekey_done_notifier)));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let this = Self {
            sender: Arc::new(TokioMutex::new(sender)),
            receiver: Arc::new(Mutex::new(Some(receiver))),
            session_crypto_state: container,
            cid,
            is_initiator,
            constructor: Arc::new(Mutex::new(None)),
            attached_payload_tx,
            attached_payload_rx: Arc::new(Mutex::new(Some(attached_payload_rx))),
            rekey_done_notifier,
            psks: Arc::new(psks.iter().map(|psk| psk.as_ref().to_vec()).collect()),
            role: Arc::new(Atomic::new(RekeyRole::Idle)),
            state: Arc::new(Atomic::new(RekeyState::Idle)),
            local_listener: Arc::new(Mutex::new(None)),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
        };

        this.clone()
            .spawn_rekey_process(rekey_done_notifier_tx, shutdown_rx);
        this
    }

    pub fn new_from_components<T: AsRef<[u8]>>(
        toolset: Toolset<R>,
        local_is_initiator: bool,
        sender: S,
        receiver: I,
        psks: &[T],
    ) -> Self {
        let container = PeerSessionCrypto::new(toolset, local_is_initiator);
        Self::new(sender, receiver, container, psks)
    }

    pub fn is_rekeying(&self) -> bool {
        self.role() != RekeyRole::Idle
    }

    /// Triggers a rekey without sending an attached payload
    pub async fn trigger_rekey(&self) -> Result<(), CryptError> {
        self.trigger_rekey_with_payload(None).await.map(|_| ())
    }

    /// Supposing the payload is Some: Returns Ok(None) if the payload was sent along with the rekey bundle,
    /// otherwise, returns the attached payload for later use.
    pub async fn trigger_rekey_with_payload(
        &self,
        attached_payload: Option<P>,
    ) -> Result<Option<P>, CryptError> {
        log::info!(target: "citadel", "Client {} manually triggering rekey", self.cid);
        let state = self.state();
        if state == RekeyState::Halted {
            return Err(CryptError::RekeyUpdateError(
                "Rekey process is halted".to_string(),
            ));
        }

        if self.is_rekeying() {
            // We are already in a rekey process
            return Ok(attached_payload);
        }

        let (constructor, earliest_ratchet_version, latest_ratchet_version) = {
            let constructor = self.session_crypto_state.get_next_constructor();
            let earliest_ratchet_version = self
                .session_crypto_state
                .toolset()
                .read()
                .get_oldest_ratchet_version();
            let latest_ratchet_version = self.session_crypto_state.latest_usable_version();
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

            let metadata = self.get_rekey_metadata();

            self.sender
                .lock()
                .await
                .send(RatchetMessage::AliceToBob {
                    payload,
                    earliest_ratchet_version,
                    latest_ratchet_version,
                    attached_payload,
                    metadata,
                })
                .await
                .map_err(|_err| CryptError::RekeyUpdateError("Sink send error".into()))?;
            log::debug!(target: "citadel", "Client {} sent initial AliceToBob transfer", self.cid);

            *self.constructor.lock() = Some(constructor);
            let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();

            *self.local_listener.lock() = Some(tx);
            let _res = rx.await.map_err(|_| {
                CryptError::RekeyUpdateError("Failed to wait for local listener".to_string())
            })?;

            Ok(None)
        } else {
            Ok(attached_payload)
        }
    }

    fn spawn_rekey_process(
        self,
        rekey_done_notifier_tx: tokio::sync::mpsc::UnboundedSender<R>,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) {
        struct DropWrapper {
            state: Arc<Atomic<RekeyState>>,
            role: Arc<Atomic<RekeyRole>>,
        }

        impl Drop for DropWrapper {
            fn drop(&mut self) {
                self.state.store(RekeyState::Halted, Ordering::Relaxed);
                self.role.store(RekeyRole::Idle, Ordering::Relaxed);
            }
        }

        let cid = self.cid;

        let task = async move {
            let _drop_wrapper = DropWrapper {
                state: self.state.clone(),
                role: self.role.clone(),
            };

            let mut listener = { self.receiver.lock().take().unwrap() };
            loop {
                self.set_state(RekeyState::Running);
                let result = self.rekey(&mut listener).await;
                self.set_state(RekeyState::Idle);
                self.set_role(RekeyRole::Idle);

                match result {
                    Ok(latest_ratchet) => {
                        // Alert any local callers waiting for rekeying to finish
                        if let Err(_err) = rekey_done_notifier_tx.send(latest_ratchet.clone()) {
                            log::warn!(target: "citadel", "Failed to send rekey done notification");
                        }

                        // Alert any passive background listeners wanting to keep track of each
                        // time a rekey finishes, independent of who initiated the rekey
                        if let Some(notifier) = self.local_listener.lock().take() {
                            let _ = notifier.send(latest_ratchet);
                        }
                    }

                    Err(err) => {
                        if matches!(err, CryptError::FatalError(..)) {
                            if self.shutdown().is_some() {
                                log::error!(target: "citadel", "Client {} fatal rekey error: {err:?}", self.cid);
                            }
                            break;
                        } else {
                            log::warn!(target: "citadel", "Client {} rekey error: {err:?}", self.cid);
                        }
                    }
                }
            }
        };

        let combined = async move {
            tokio::select! {
                _ = shutdown_rx => {
                    log::warn!(target: "citadel", "Client {cid} rekey process shutting down due to shutdown signal");
                },
                _ = task => {
                    log::warn!(target: "citadel", "Client {cid} rekey process shutting down");
                }
            }
        };

        drop(citadel_io::tokio::task::spawn(combined));
    }

    /// Runs a single round of re-keying, listening to events and returning
    /// once a single re-key occurs. This function is intended to be used in a loop
    /// to continuously be ready for re-keying.
    async fn rekey(&self, receiver: &mut I) -> Result<R, CryptError> {
        log::trace!(target: "citadel", "Client {} starting rekey with initial role {:?}", self.cid, self.role());

        // First synchronize state with peer
        let metadata = self.get_rekey_metadata();

        let is_initiator = self.is_initiator;
        let mut completed_as_leader = false;
        let mut completed_as_loser = false;

        loop {
            let msg = receiver.next().await;
            match msg {
                Some(RatchetMessage::AliceToBob {
                    payload,
                    earliest_ratchet_version,
                    latest_ratchet_version,
                    attached_payload,
                    metadata: peer_metadata,
                }) => {
                    if let Some(attached_payload) = attached_payload {
                        let _ = self.attached_payload_tx.send(attached_payload);
                    }

                    let status = {
                        log::debug!(target: "citadel", "Client {} received AliceToBob", self.cid);

                        // Process the AliceToBob message as Bob
                        let transfer = bincode::deserialize(&payload)
                            .map_err(|err| CryptError::RekeyUpdateError(err.to_string()))?;

                        let _cid = self.session_crypto_state.cid();
                        let local_earliest_ratchet_version = self
                            .session_crypto_state
                            .toolset()
                            .read()
                            .get_oldest_ratchet_version();
                        let local_latest_ratchet_version =
                            self.session_crypto_state.latest_usable_version();

                        // Validate against our barrier. We only care abou the latest version, since the
                        // earliest version may still be syncing
                        if latest_ratchet_version != local_latest_ratchet_version {
                            // Request resynchronization
                            return Err(CryptError::RekeyUpdateError(
                                format!(
                                    "Rekey barrier mismatch (earliest/latest). Peer: ({}-{}) != Local: ({}-{})",
                                    earliest_ratchet_version,
                                    latest_ratchet_version,
                                    local_earliest_ratchet_version,
                                    local_latest_ratchet_version
                                ),
                            ));
                        }

                        // Validate metadata
                        if peer_metadata != metadata {
                            return Err(CryptError::RekeyUpdateError(
                                format!("Metadata mismatch (AliceToBob). Peer: {peer_metadata:?} != Local: {metadata:?}"),
                            ));
                        }

                        // Get next_opts from the container
                        let next_opts = self
                            .session_crypto_state
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

                        self.session_crypto_state
                            .update_sync_safe(bob_constructor, false)?
                    };

                    match status {
                        KemTransferStatus::Some(transfer, _) => {
                            let serialized = bincode::serialize(&transfer)
                                .map_err(|err| CryptError::RekeyUpdateError(format!("{err:?}")))?;

                            log::trace!(target: "citadel", "Client {} must send BobToAlice", self.cid);

                            {
                                let container = &self.session_crypto_state;
                                let _ = container.update_in_progress.toggle_on_if_untoggled();
                                self.set_role(RekeyRole::Loser);
                            }

                            self.sender
                                .lock()
                                .await
                                .send(RatchetMessage::BobToAlice(
                                    serialized,
                                    RekeyRole::Loser,
                                    metadata,
                                ))
                                .await
                                .map_err(|_err| {
                                    CryptError::RekeyUpdateError("Sink send error".into())
                                })?;
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
                            log::warn!(target:"citadel", "Client {} unexpected status for AliceToBob Transfer: {status:?}", self.cid);
                        }
                    }
                }

                Some(RatchetMessage::BobToAlice(transfer_data, sender_role, peer_metadata)) => {
                    log::debug!(target: "citadel", "Client {} received BobToAlice", self.cid);

                    // First validate metadata
                    let local_metadata = self.get_rekey_metadata();

                    // Validate metadata
                    if peer_metadata != local_metadata {
                        return Err(CryptError::RekeyUpdateError(
                            format!("Metadata mismatch (AliceToBob). Peer: {peer_metadata:?} != Local: {metadata:?}"),
                        ));
                    }

                    // Only validate role transition if we're not already in the correct role
                    let initial_role = self.role();
                    if sender_role == RekeyRole::Loser && initial_role != RekeyRole::Leader {
                        let transition = self.validate_role_transition(RekeyRole::Leader);
                        match transition {
                            RoleTransition::IdleToLeader => {
                                self.set_role(RekeyRole::Leader);
                                log::debug!(target: "citadel", "Client {} transitioning from Idle to Leader", self.cid);
                            }
                            RoleTransition::Invalid => {
                                log::warn!(target: "citadel", "Invalid role transition from {:?} to Leader", initial_role);
                                return Err(CryptError::RekeyUpdateError(format!(
                                    "Invalid role transition from {:?} to Leader",
                                    initial_role
                                )));
                            }
                            _ => {}
                        }
                    }

                    // Verify we're in a valid state to process the message
                    if self.role() == RekeyRole::Loser {
                        return Err(CryptError::RekeyUpdateError(format!(
                            "Unexpected BobToAlice message since our role is not Leader, but {:?}",
                            self.role()
                        )));
                    }

                    // Now process the transfer data
                    let mut constructor = { self.constructor.lock().take() };
                    if let Some(mut alice_constructor) = constructor.take() {
                        let transfer = bincode::deserialize(&transfer_data).map_err(|e| {
                            CryptError::RekeyUpdateError(format!(
                                "Failed to deserialize transfer: {e}"
                            ))
                        })?;

                        alice_constructor.stage1_alice(transfer, &self.psks)?;
                        let status = {
                            self.session_crypto_state
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
                                    self.session_crypto_state
                                        .deregister_oldest_ratchet(version_to_truncate)?;
                                }

                                self.sender
                                    .lock()
                                    .await
                                    .send(RatchetMessage::Truncate(version_to_truncate))
                                    .await
                                    .map_err(|_err| {
                                        CryptError::RekeyUpdateError("Sink send error".into())
                                    })?;
                                // We need to wait to be marked as complete
                            } else {
                                // Send LoserCanFinish to Bob so he can finish
                                self.sender
                                    .lock()
                                    .await
                                    .send(RatchetMessage::LoserCanFinish)
                                    .await
                                    .map_err(|_err| {
                                        CryptError::RekeyUpdateError("Sink send error".into())
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
                        let container = &self.session_crypto_state;
                        container.deregister_oldest_ratchet(version_to_truncate)?;
                        container.post_alice_stage1_or_post_stage1_bob();
                        let latest_actual_ratchet_version = container
                            .maybe_unlock()
                            .expect("Failed to fetch ratchet")
                            .version();
                        let latest_version = container.latest_usable_version();
                        if latest_actual_ratchet_version != latest_version {
                            log::warn!(target:"citadel", "Client {} received Truncate, but, update failed. Actual: {latest_actual_ratchet_version}, Expected: {latest_version} ", self.cid);
                        }
                        latest_version
                    };

                    completed_as_loser = true;

                    self.sender
                        .lock()
                        .await
                        .send(RatchetMessage::LeaderCanFinish {
                            version: latest_version,
                        })
                        .await
                        .map_err(|_err| CryptError::RekeyUpdateError("Sink send error".into()))?;
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
                        let container = &self.session_crypto_state;
                        container.post_alice_stage1_or_post_stage1_bob();
                        let latest_actual_ratchet_version = container
                            .maybe_unlock()
                            .expect("Failed to unlock container")
                            .version();
                        let latest_version = container.latest_usable_version();
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
                        .send(RatchetMessage::LeaderCanFinish {
                            version: latest_version,
                        })
                        .await
                        .map_err(|_err| CryptError::RekeyUpdateError("Sink send error".into()))?;
                    break;
                }

                Some(RatchetMessage::LeaderCanFinish { version }) => {
                    log::debug!(
                        "Client {} received LeaderCanFinish w/ version = {version}",
                        self.cid
                    );

                    // First handle role transition if needed
                    let initial_role = self.role();
                    if initial_role == RekeyRole::Idle {
                        let transition = self.validate_role_transition(RekeyRole::Leader);
                        match transition {
                            RoleTransition::IdleToLeader => {
                                self.set_role(RekeyRole::Leader);
                                log::debug!(target: "citadel", "Client {} transitioning from Idle to Leader", self.cid);
                            }
                            RoleTransition::Invalid => {
                                log::warn!(target: "citadel", "Invalid role transition from {:?} to Leader", initial_role);
                                return Err(CryptError::RekeyUpdateError(format!(
                                    "Invalid role transition from {:?} to Leader",
                                    initial_role
                                )));
                            }
                            _ => {}
                        }
                    }

                    // Verify we're in a valid role
                    let role = self.role();
                    if role != RekeyRole::Leader {
                        return Err(CryptError::RekeyUpdateError(format!(
                            "Unexpected LeaderCanFinish message since our role is not Leader, but {:?}",
                            role
                        )));
                    }

                    // Apply the update
                    let container = &self.session_crypto_state;
                    container.post_alice_stage1_or_post_stage1_bob();
                    let latest_actual_ratchet_version = container
                        .maybe_unlock()
                        .expect("Failed to fetch ratchet")
                        .version();
                    let latest_declared_version = container.latest_usable_version();

                    // Now validate the version after applying the update
                    if latest_declared_version != version {
                        log::warn!(target: "citadel", "Client {} version mismatch after LeaderCanFinish. Local: {}, Peer: {}", 
                            self.cid, latest_declared_version, version);
                        return Err(CryptError::RekeyUpdateError(format!(
                            "Version mismatch after LeaderCanFinish update. Local: {}, Peer: {}",
                            latest_declared_version, version
                        )));
                    }

                    if latest_actual_ratchet_version != latest_declared_version {
                        log::warn!(target: "citadel", "Client {} received LeaderCanFinish, desynced. Actual: {latest_actual_ratchet_version}, Expected: {latest_declared_version} ", self.cid);
                    }

                    completed_as_leader = true;
                    break;
                }

                Some(RatchetMessage::JustMessage(message)) => {
                    // If we receive a message, just forward it to the attached payload stream
                    if self.attached_payload_tx.send(message).is_err() {
                        log::warn!(target:"citadel", "Attached payload send error");
                    }
                }

                None => {
                    return Err(CryptError::FatalError(
                        "Unexpected end of stream".to_string(),
                    ));
                }
            }
        }

        let latest_ratchet = self.get_ratchet(None).unwrap();
        log::debug!(
            target: "citadel",
            "Client {} completed re-key. Alice: {}, Bob: {}. Final version: {}. Final Declared Version: {}. Is initiator: {}",
            self.cid,
            completed_as_leader,
            completed_as_loser,
            latest_ratchet.version(),
            self.session_crypto_state.latest_usable_version(),
            is_initiator
        );

        log::debug!(target: "citadel", "*** Client {} rekey completed ***", self.cid);

        Ok(latest_ratchet)
    }

    pub fn take_payload_rx(&self) -> Option<UnboundedReceiver<P>> {
        self.attached_payload_rx.lock().take()
    }

    pub fn take_on_rekey_finished_event_listener(&self) -> Option<UnboundedReceiver<R>> {
        self.rekey_done_notifier.lock().take()
    }

    pub fn session_crypto_state(&self) -> &PeerSessionCrypto<R> {
        &self.session_crypto_state
    }

    pub fn get_ratchet(&self, version: Option<u32>) -> Option<R> {
        self.session_crypto_state.get_ratchet(version)
    }

    pub fn local_is_initiator(&self) -> bool {
        self.session_crypto_state.local_is_initiator()
    }

    pub fn role(&self) -> RekeyRole {
        self.role.load(Ordering::Relaxed)
    }

    fn set_role(&self, role: RekeyRole) {
        log::trace!(target: "citadel", "Client {} changing role from {:?} to {:?}", self.cid, self.role(), role);
        self.role.store(role, Ordering::SeqCst);
    }

    /// Shuts down the rekey
    pub fn shutdown(&self) -> Option<()> {
        let _ = self.shutdown_tx.lock().take()?.send(());
        Some(())
    }

    pub fn state(&self) -> RekeyState {
        self.state.load(Ordering::Relaxed)
    }

    fn set_state(&self, state: RekeyState) {
        self.state.store(state, Ordering::Relaxed);
    }

    fn validate_role_transition(&self, new_role: RekeyRole) -> RoleTransition {
        match (self.role(), new_role) {
            (RekeyRole::Idle, RekeyRole::Leader) => RoleTransition::IdleToLeader,
            (RekeyRole::Idle, RekeyRole::Loser) => RoleTransition::IdleToLoser,
            (RekeyRole::Leader, RekeyRole::Idle) => RoleTransition::LeaderToIdle,
            (RekeyRole::Loser, RekeyRole::Idle) => RoleTransition::LoserToIdle,
            _ => RoleTransition::Invalid,
        }
    }

    fn get_rekey_metadata(&self) -> RekeyMetadata {
        let latest_usable_version = self.session_crypto_state.latest_usable_version();
        RekeyMetadata {
            current_version: latest_usable_version,
            next_version: latest_usable_version + 1,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub use crate::endpoint_crypto_container::{EndpointRatchetConstructor, PeerSessionCrypto};
    pub use crate::prelude::Toolset;
    pub use crate::ratchets::ratchet_manager::{
        RatchetManager, RatchetManagerSink, RatchetManagerStream,
    };
    pub use crate::ratchets::stacked::ratchet::StackedRatchet;
    pub use crate::ratchets::Ratchet;
    pub use citadel_io::tokio;
    pub use citadel_pqcrypto::constructor_opts::ConstructorOpts;
    pub use citadel_types::prelude::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
    pub use rstest::rstest;
    pub use std::time::Duration;

    use super::AttachedPayload;

    pub const ALICE_CID: u64 = 10;
    pub const BOB_CID: u64 = 20;
    pub const TEST_PSKS: &[&[u8]] = &[b"test_psk_1", b"test_psk_2"];
    pub const START_VERSION: u32 = 0;

    pub fn gen<R: Ratchet, T: AsRef<[u8]>>(
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

    pub fn setup_endpoint_containers<R: Ratchet>(
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

    pub type TestRatchetManager<R, P> = RatchetManager<
        Box<dyn RatchetManagerSink<P, Error = futures::channel::mpsc::SendError>>,
        Box<dyn RatchetManagerStream<P>>,
        R,
        P,
    >;

    pub fn create_ratchet_managers<R: Ratchet, P: AttachedPayload>(
    ) -> (TestRatchetManager<R, P>, TestRatchetManager<R, P>) {
        let security_level = SecurityLevel::Standard;

        let (alice_container, bob_container) = setup_endpoint_containers::<R>(
            security_level,
            EncryptionAlgorithm::AES_GCM_256,
            KemAlgorithm::Kyber,
        );

        let (tx_alice, rx_bob) = futures::channel::mpsc::unbounded();
        let (tx_bob, rx_alice) = futures::channel::mpsc::unbounded();

        let alice_manager = RatchetManager::new(
            Box::new(tx_alice)
                as Box<dyn RatchetManagerSink<P, Error = futures::channel::mpsc::SendError>>,
            Box::new(rx_alice) as Box<dyn RatchetManagerStream<P>>,
            alice_container,
            TEST_PSKS,
        );
        let bob_manager = RatchetManager::new(
            Box::new(tx_bob)
                as Box<dyn RatchetManagerSink<P, Error = futures::channel::mpsc::SendError>>,
            Box::new(rx_bob) as Box<dyn RatchetManagerStream<P>>,
            bob_container,
            TEST_PSKS,
        );
        (alice_manager, bob_manager)
    }

    pub fn pre_round_assertions<R: Ratchet>(
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
            .toolset()
            .read()
            .get_most_recent_ratchet_version();
        let new_version = start_version + 1;
        let new_version_bob = bob_container
            .toolset()
            .read()
            .get_most_recent_ratchet_version()
            + 1;
        assert_eq!(new_version, new_version_bob);
        (start_version, new_version)
    }

    pub async fn run_round_racy<
        S: RatchetManagerSink<P>,
        I: RatchetManagerStream<P>,
        R: Ratchet,
        P: AttachedPayload,
    >(
        container_0: RatchetManager<S, I, R, P>,
        container_1: RatchetManager<S, I, R, P>,
        container_0_delay: Option<Duration>,
    ) {
        let cid_0 = container_0.cid;
        let cid_1 = container_1.cid;

        let (start_version, _) = pre_round_assertions(
            &container_0.session_crypto_state,
            cid_0,
            &container_1.session_crypto_state,
            cid_1,
        );

        let task = |container: RatchetManager<S, I, R, P>, delay: Option<Duration>| async move {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            let res = container.trigger_rekey().await;
            log::debug!(target: "citadel", "*** [FINISHED] Client {} rekey result: {res:?}", container.cid);
            res
        };

        let container_0_task = task(container_0.clone(), container_0_delay);
        let container_1_task = task(container_1.clone(), None);

        // Add timeout to catch deadlocks
        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        tokio::select! {
            _ = &mut timeout => {
                log::error!(target: "citadel", "Rekey round timed out after 5 seconds");
                let _ = container_0.shutdown();
                let _ = container_1.shutdown();
                panic!("Rekey round timed out - possible deadlock");
            }
            res = async { tokio::join!(container_0_task, container_1_task) } => {
                match res {
                    (Ok(_), Ok(_)) => {
                        // Both succeeded, verify final state
                        let latest_0 = container_0.session_crypto_state.latest_usable_version();
                        let latest_1 = container_1.session_crypto_state.latest_usable_version();

                        assert_eq!(latest_0, latest_1, "Version mismatch after rekey. Container 0: {}, Container 1: {}", latest_0, latest_1);
                        assert!(latest_0 > start_version, "Version did not increase. Start: {}, Current: {}", start_version, latest_0);

                        // Reset roles to idle
                        container_0.set_role(super::RekeyRole::Idle);
                        container_1.set_role(super::RekeyRole::Idle);
                    }
                    (Err(e1), Err(e2)) => {
                        panic!("Both containers failed. Error 1: {:?}, Error 2: {:?}", e1, e2);
                    }
                    (Err(e), Ok(_)) => {
                        panic!("Container 0 failed: {:?}", e);
                    }
                    (Ok(_), Err(e)) => {
                        panic!("Container 1 failed: {:?}", e);
                    }
                }
            }
        }
    }

    pub async fn run_round_one_node_only<
        S: RatchetManagerSink<P>,
        I: RatchetManagerStream<P>,
        R: Ratchet,
        P: AttachedPayload,
    >(
        container_0: RatchetManager<S, I, R, P>,
        container_1: RatchetManager<S, I, R, P>,
    ) {
        let cid_0 = container_0.cid;
        let cid_1 = container_1.cid;

        let (_start_version, _next_version) = pre_round_assertions(
            &container_0.session_crypto_state,
            cid_0,
            &container_1.session_crypto_state,
            cid_1,
        );

        let task = |container: RatchetManager<S, I, R, P>, skip: bool| async move {
            if skip {
                return Ok(());
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
        alice_result.unwrap().unwrap();
        bob_result.unwrap().unwrap();

        post_checks(&container_0, &container_1);
    }

    pub fn ratchet_encrypt_decrypt_test<R: Ratchet>(
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

    pub fn post_checks<
        S: RatchetManagerSink<P>,
        I: RatchetManagerStream<P>,
        R: Ratchet,
        P: AttachedPayload,
    >(
        container_0: &RatchetManager<S, I, R, P>,
        container_1: &RatchetManager<S, I, R, P>,
    ) {
        // Verify final state
        let cid_0 = container_0.cid;
        let cid_1 = container_1.cid;
        let alice_declared_latest_version =
            container_0.session_crypto_state.latest_usable_version();
        let bob_declared_latest_version = container_1.session_crypto_state.latest_usable_version();
        assert_eq!(alice_declared_latest_version, bob_declared_latest_version);
        let alice_ratchet = container_0.get_ratchet(None).unwrap();
        let bob_ratchet = container_1.get_ratchet(None).unwrap();
        assert_eq!(alice_ratchet.version(), bob_ratchet.version());

        let alice_ratchet_version = alice_ratchet.version();

        ratchet_encrypt_decrypt_test(
            &container_0.session_crypto_state,
            cid_0,
            &container_1.session_crypto_state,
            cid_1,
            alice_ratchet_version,
        );
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(60))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ratchet_manager_racy_contentious() {
        citadel_logging::setup_log();
        let (alice_manager, bob_manager) = create_ratchet_managers::<StackedRatchet, ()>();
        const ROUNDS: usize = 100;
        for _ in 0..ROUNDS {
            run_round_racy(alice_manager.clone(), bob_manager.clone(), None).await;
        }

        assert_eq!(
            alice_manager.session_crypto_state.latest_usable_version(),
            ROUNDS as u32
        );
        assert_eq!(
            bob_manager.session_crypto_state.latest_usable_version(),
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
        let (alice_manager, bob_manager) = create_ratchet_managers::<StackedRatchet, ()>();
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
        let (alice_manager, bob_manager) = create_ratchet_managers::<StackedRatchet, ()>();
        const ROUNDS: usize = 100;
        for _ in 0..ROUNDS {
            run_round_one_node_only(alice_manager.clone(), bob_manager.clone()).await;
        }

        assert_eq!(
            alice_manager.session_crypto_state.latest_usable_version(),
            ROUNDS as u32
        );
        assert_eq!(
            bob_manager.session_crypto_state.latest_usable_version(),
            ROUNDS as u32
        );
    }
}
