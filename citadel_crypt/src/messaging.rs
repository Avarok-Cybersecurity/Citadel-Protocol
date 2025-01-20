use crate::misc::CryptError;
use crate::ratchets::ratchet_manager::{AttachedPayload, DefaultRatchetManager, RatchetMessage};
use crate::ratchets::Ratchet;
use citadel_io::tokio;
use citadel_types::prelude::SecrecyMode;
use futures::{SinkExt, Stream};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::mpsc::UnboundedReceiver;

/// A messenger intended for use by the citadel_proto package for two nodes to use
/// for messaging. It enforces the secrecy mode such that:
/// [*] True Perfect Forward Secrecy: C message can only be sent if a new key is
/// ready for use. This uses head-of-line blocking, placing any messages into the queue
/// until a rekey is complete. This is best for pure messaging applications.
/// [*] Best effort mode: Messages will attempt to use an unused key, but, will re-use the
/// same key in order to not block. This is best for high-throughput applications.
///
/// This pattern bypasses the kernel executor for direct writing and reading from the
/// underlying stream at the application-layer
pub struct RatchetManagerMessengerLayer<E: Send + Sync + 'static, R: Ratchet, P: AttachedPayload> {
    sink: RatchetManagerMessengerLayerTx<E, R, P>,
    stream: RatchetManagerMessengerLayerRx<E, R, P>,
}

pub struct RatchetManagerMessengerLayerTx<E: Send + Sync + 'static, R: Ratchet, P: AttachedPayload>
{
    manager: DefaultRatchetManager<E, R, P>,
    enqueued_messages: Arc<tokio::sync::Mutex<VecDeque<P>>>,
    is_active: Arc<AtomicBool>,
    secrecy_mode: SecrecyMode,
}

pub struct RatchetManagerMessengerLayerRx<E: Send + Sync + 'static, R: Ratchet, P: AttachedPayload>
{
    manager: DefaultRatchetManager<E, R, P>,
    rx: UnboundedReceiver<P>,
    is_active: Arc<AtomicBool>,
}

const ORDERING: std::sync::atomic::Ordering = std::sync::atomic::Ordering::Relaxed;

impl<E, R, P> RatchetManagerMessengerLayer<E, R, P>
where
    E: Send + Sync + 'static,
    R: Ratchet,
    P: AttachedPayload,
{
    pub fn new(
        manager: DefaultRatchetManager<E, R, P>,
        secrecy_mode: SecrecyMode,
        rekey_finished_tx: Option<tokio::sync::mpsc::UnboundedSender<R>>,
        is_active: Arc<AtomicBool>,
    ) -> Self {
        // The rx below will receive all messages that get sent via the ratchet manager layer
        // Some messages will "catch a ride" alongside a re-keying packet, others will be
        // standalone. This is not Pandora.
        let rx = manager
            .take_payload_rx()
            .expect("Cannot pass a RatchetManager that has no payload receiver!");
        let mut on_rekey_finish_listener = manager
            .take_on_rekey_finished_event_listener()
            .expect("Cannot pass a RatchetManager that has no on_rekey listener!");
        let enqueued_messages = Arc::new(tokio::sync::Mutex::new(VecDeque::new()));
        let enqueued_messages_clone = enqueued_messages.clone();
        let manager_clone = manager.clone();
        let is_active_bg = is_active.clone();

        let background_task = async move {
            // Each time a rekey finishes, we should check the local queue for any enqueued messages
            // to poll and send
            while let Some(next_ratchet) = on_rekey_finish_listener.recv().await {
                if let Some(notify_on_finish_tx) = rekey_finished_tx.as_ref() {
                    if let Err(err) = notify_on_finish_tx.send(next_ratchet) {
                        log::warn!(target: "citadel", "Failed to notify on rekey finish: {err}");
                    }
                }
                // Check the latest item in the queue. Hold the lock to prevent race conditions locally
                let mut lock = enqueued_messages_clone.lock().await;
                if let Some(last_item) = lock.pop_front() {
                    match manager_clone
                        .trigger_rekey_with_payload(Some(last_item))
                        .await
                    {
                        Ok(Some(message_not_sent)) => {
                            lock.insert(0, message_not_sent);
                        }

                        Ok(None) => {
                            // Successfully sent
                        }

                        Err(err) => {
                            log::error!(target: "citadel", "RatchetManager failed to trigger rekey: {:?}", err);
                        }
                    }
                }

                if !is_active_bg.load(ORDERING) {
                    break;
                }
            }

            is_active_bg.store(false, ORDERING);

            log::warn!(target: "citadel", "RatchetManagerMessengerLayer: background task ending")
        };

        drop(tokio::task::spawn(background_task));

        Self {
            sink: RatchetManagerMessengerLayerTx {
                manager: manager.clone(),
                enqueued_messages,
                secrecy_mode,
                is_active: is_active.clone(),
            },
            stream: RatchetManagerMessengerLayerRx {
                rx,
                is_active,
                manager,
            },
        }
    }

    pub fn split(
        self,
    ) -> (
        RatchetManagerMessengerLayerTx<E, R, P>,
        RatchetManagerMessengerLayerRx<E, R, P>,
    ) {
        (self.sink, self.stream)
    }
}

impl<E, R, P> RatchetManagerMessengerLayerTx<E, R, P>
where
    E: Send + Sync + 'static,
    R: Ratchet,
    P: AttachedPayload,
{
    pub async fn send(&self, message: impl Into<P>) -> Result<(), CryptError> {
        if !self.is_active.load(ORDERING) {
            return Err(CryptError::Encrypt(
                "Cannot send encrypted messages (stream died)".to_string(),
            ));
        }

        match self.secrecy_mode {
            SecrecyMode::BestEffort => {
                if let Some(message_not_sent) = self
                    .manager
                    .trigger_rekey_with_payload(Some(message.into()))
                    .await?
                {
                    // Just send through channel
                    self.manager
                        .sender
                        .lock()
                        .await
                        .send(RatchetMessage::JustMessage(message_not_sent))
                        .await
                        .map_err(|_| {
                            CryptError::FatalError("Ratchet Manager's outbound stream died".into())
                        })?;
                } else {
                    // Success; this message will trigger a simultaneous rekey
                }

                Ok(())
            }

            SecrecyMode::Perfect => {
                if let Some(message_not_sent) = self
                    .manager
                    .trigger_rekey_with_payload(Some(message.into()))
                    .await?
                {
                    // We need to enqueue
                    self.enqueued_messages
                        .lock()
                        .await
                        .push_back(message_not_sent);
                } else {
                    // Success; this message will trigger a simultaneous rekey w/o enqueuing
                }

                Ok(())
            }
        }
    }
}

impl<E, R, P> Stream for RatchetManagerMessengerLayerRx<E, R, P>
where
    E: Send + Sync + 'static,
    R: Ratchet,
    P: AttachedPayload,
{
    type Item = P;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if !this.is_active.load(ORDERING) {
            return Poll::Ready(None);
        }

        this.rx.poll_recv(cx)
    }
}

impl<E, R, P> Drop for RatchetManagerMessengerLayerTx<E, R, P>
where
    E: Send + Sync + 'static,
    R: Ratchet,
    P: AttachedPayload,
{
    fn drop(&mut self) {
        self.is_active.store(false, ORDERING);
        let _ = self.manager.shutdown();
    }
}

impl<E, R, P> Drop for RatchetManagerMessengerLayerRx<E, R, P>
where
    E: Send + Sync + 'static,
    R: Ratchet,
    P: AttachedPayload,
{
    fn drop(&mut self) {
        self.is_active.store(false, ORDERING);
        let _ = self.manager.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{atomic::AtomicBool, Arc};

    use citadel_io::tokio_stream::StreamExt;
    use citadel_types::crypto::SecrecyMode;

    pub use crate::ratchets::ratchet_manager::tests::*;
    use crate::ratchets::ratchet_manager::AttachedPayload;

    use super::{
        RatchetManagerMessengerLayer, RatchetManagerMessengerLayerRx,
        RatchetManagerMessengerLayerTx,
    };

    pub type TestRatchetManagerMessenger<R, P> =
        RatchetManagerMessengerLayer<futures::channel::mpsc::SendError, R, P>;
    pub type TestRatchetManagerMessengerRx<R, P> =
        RatchetManagerMessengerLayerRx<futures::channel::mpsc::SendError, R, P>;
    pub type TestRatchetManagerMessengerTx<R, P> =
        RatchetManagerMessengerLayerTx<futures::channel::mpsc::SendError, R, P>;

    fn create_messengers<R, P>(
        secrecy_mode: SecrecyMode,
    ) -> (
        TestRatchetManagerMessenger<R, P>,
        TestRatchetManagerMessenger<R, P>,
    )
    where
        R: Ratchet,
        P: AttachedPayload,
    {
        let (alice_manager, bob_manager) = create_ratchet_managers::<R, P>();

        let alice_messenger = RatchetManagerMessengerLayer::new(
            alice_manager,
            secrecy_mode,
            None,
            Arc::new(AtomicBool::new(true)),
        );

        let bob_messenger = RatchetManagerMessengerLayer::new(
            bob_manager,
            secrecy_mode,
            None,
            Arc::new(AtomicBool::new(true)),
        );

        (alice_messenger, bob_messenger)
    }

    async fn run_messenger_round_racy<
        R: Ratchet,
        P: AttachedPayload + From<u64> + std::fmt::Debug + Eq + Clone,
    >(
        alice_messenger_tx: &mut TestRatchetManagerMessengerTx<R, P>,
        alice_messenger_rx: &mut TestRatchetManagerMessengerRx<R, P>,
        bob_messenger_tx: &mut TestRatchetManagerMessengerTx<R, P>,
        bob_messenger_rx: &mut TestRatchetManagerMessengerRx<R, P>,
        delay: Option<Duration>,
    ) {
        let (delay_alice, delay_bob) = if let Some(delay) = delay {
            if rand::random::<u8>() % 2 == 0 {
                (Some(delay), None)
            } else {
                (None, Some(delay))
            }
        } else {
            (None, None)
        };

        let alice_task = async move {
            for x in 0..100u64 {
                if let Some(delay) = delay_alice {
                    tokio::time::sleep(delay).await;
                }

                let payload = P::from(x);
                alice_messenger_tx.send(payload.clone()).await.unwrap();

                let recv_payload = alice_messenger_rx.next().await.unwrap();
                assert_eq!(recv_payload, payload);
            }
        };

        let bob_task = async move {
            for x in 0..100u64 {
                if let Some(delay) = delay_bob {
                    tokio::time::sleep(delay).await;
                }

                let payload = P::from(x);
                bob_messenger_tx.send(payload.clone()).await.unwrap();

                let recv_payload = bob_messenger_rx.next().await.unwrap();
                assert_eq!(recv_payload, payload);
            }
        };

        tokio::join!(alice_task, bob_task);
    }

    async fn run_messenger_one_round_one_at_a_time<
        R: Ratchet,
        P: AttachedPayload + Clone + std::fmt::Debug + Eq,
    >(
        alice_messenger_tx: &mut TestRatchetManagerMessengerTx<R, P>,
        alice_messenger_rx: &mut TestRatchetManagerMessengerRx<R, P>,
        bob_messenger_tx: &mut TestRatchetManagerMessengerTx<R, P>,
        bob_messenger_rx: &mut TestRatchetManagerMessengerRx<R, P>,
        payload: P,
    ) {
        alice_messenger_tx.send(payload.clone()).await.unwrap();
        bob_messenger_tx.send(payload.clone()).await.unwrap();
        let alice_message_from_bob = alice_messenger_rx.next().await.unwrap();
        let bob_message_from_alice = bob_messenger_rx.next().await.unwrap();
        assert_eq!(alice_message_from_bob, payload.clone());
        assert_eq!(bob_message_from_alice, payload);
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(60))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_messenger_racy_contentious(
        #[values(SecrecyMode::BestEffort, SecrecyMode::Perfect)] secrecy_mode: SecrecyMode,
    ) {
        citadel_logging::setup_log();
        let (alice_manager, bob_manager) = create_messengers::<StackedRatchet, _>(secrecy_mode);
        let (mut alice_messenger_tx, mut alice_messenger_rx) = alice_manager.split();
        let (mut bob_messenger_tx, mut bob_messenger_rx) = bob_manager.split();

        run_messenger_round_racy::<_, u64>(
            &mut alice_messenger_tx,
            &mut alice_messenger_rx,
            &mut bob_messenger_tx,
            &mut bob_messenger_rx,
            None,
        )
        .await;
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(360))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_messenger_racy_with_random_start_lag_pfs(
        #[values(0, 1, 10, 100, 500)] min_delay: u64,
    ) {
        citadel_logging::setup_log();
        let (alice_manager, bob_manager) =
            create_messengers::<StackedRatchet, _>(SecrecyMode::Perfect);
        let (mut alice_messenger_tx, mut alice_messenger_rx) = alice_manager.split();
        let (mut bob_messenger_tx, mut bob_messenger_rx) = bob_manager.split();

        run_messenger_round_racy::<_, u64>(
            &mut alice_messenger_tx,
            &mut alice_messenger_rx,
            &mut bob_messenger_tx,
            &mut bob_messenger_rx,
            Some(Duration::from_millis(min_delay)),
        )
        .await;
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(360))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_messenger_racy_with_random_start_lag_best_effort(
        #[values(0, 1, 10, 100, 500)] min_delay: u64,
    ) {
        citadel_logging::setup_log();
        let (alice_manager, bob_manager) =
            create_messengers::<StackedRatchet, _>(SecrecyMode::BestEffort);
        let (mut alice_messenger_tx, mut alice_messenger_rx) = alice_manager.split();
        let (mut bob_messenger_tx, mut bob_messenger_rx) = bob_manager.split();

        run_messenger_round_racy::<_, u64>(
            &mut alice_messenger_tx,
            &mut alice_messenger_rx,
            &mut bob_messenger_tx,
            &mut bob_messenger_rx,
            Some(Duration::from_millis(min_delay)),
        )
        .await;
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(60))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_messenger_one_at_a_time() {
        citadel_logging::setup_log();
        let (alice_manager, bob_manager) =
            create_messengers::<StackedRatchet, _>(SecrecyMode::BestEffort);
        let (mut alice_messenger_tx, mut alice_messenger_rx) = alice_manager.split();
        let (mut bob_messenger_tx, mut bob_messenger_rx) = bob_manager.split();
        const ROUNDS: usize = 100;

        for x in 0..ROUNDS {
            run_messenger_one_round_one_at_a_time::<_, u64>(
                &mut alice_messenger_tx,
                &mut alice_messenger_rx,
                &mut bob_messenger_tx,
                &mut bob_messenger_rx,
                x as u64,
            )
            .await;
        }
    }
}
