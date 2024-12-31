use crate::misc::CryptError;
use crate::ratchets::ratchet_manager::{AttachedPayload, DefaultRatchetManager, RatchetMessage};
use crate::ratchets::Ratchet;
use citadel_io::tokio;
use citadel_types::prelude::SecrecyMode;
use futures::{SinkExt, Stream};
use std::collections::VecDeque;
use std::pin::Pin;
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
    stream: RatchetManagerMessengerLayerRx<P>,
}

pub struct RatchetManagerMessengerLayerTx<E: Send + Sync + 'static, R: Ratchet, P: AttachedPayload>
{
    manager: DefaultRatchetManager<E, R, P>,
    enqueued_messages: Arc<tokio::sync::Mutex<VecDeque<P>>>,
    secrecy_mode: SecrecyMode,
}

impl<E: Send + Sync + 'static, R: Ratchet, P: AttachedPayload> Clone
    for RatchetManagerMessengerLayerTx<E, R, P>
{
    fn clone(&self) -> Self {
        Self {
            manager: self.manager.clone(),
            enqueued_messages: self.enqueued_messages.clone(),
            secrecy_mode: self.secrecy_mode,
        }
    }
}

pub struct RatchetManagerMessengerLayerRx<P: AttachedPayload> {
    rx: UnboundedReceiver<P>,
}

impl<E, R, P> RatchetManagerMessengerLayer<E, R, P>
where
    E: Send + Sync + 'static,
    R: Ratchet,
    P: AttachedPayload,
{
    pub fn new(manager: DefaultRatchetManager<E, R, P>, secrecy_mode: SecrecyMode) -> Self {
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

        drop(tokio::task::spawn(async move {
            // Each time a rekey finishes, we should check the local queue for any enqueued messages
            // to poll and send
            while let Some(_next_ratchet) = on_rekey_finish_listener.recv().await {
                // TODO: Send notifications to kernel, if applicable, with the latest ratchet
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
            }

            log::warn!(target: "citadel", "on_rekey_finish_listener died")
        }));

        Self {
            sink: RatchetManagerMessengerLayerTx {
                manager,
                enqueued_messages,
                secrecy_mode,
            },
            stream: RatchetManagerMessengerLayerRx { rx },
        }
    }

    pub fn split(
        self,
    ) -> (
        RatchetManagerMessengerLayerTx<E, R, P>,
        RatchetManagerMessengerLayerRx<P>,
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
    /// Triggers a re key on a separate task
    pub fn trigger_rekey(&self) {
        let this = self.manager.clone();
        drop(tokio::task::spawn(async move {
            match this.trigger_rekey().await {
                Ok(_new_vers) => (),
                Err(err) => log::error!(target: "citadel", "{:?}", err),
            }
        }));
    }

    pub async fn send(&mut self, message: impl Into<P>) -> Result<(), CryptError> {
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

impl<P> Stream for RatchetManagerMessengerLayerRx<P>
where
    P: AttachedPayload,
{
    type Item = P;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().rx.poll_recv(cx)
    }
}
