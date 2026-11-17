//! A test shell around the pure negotiator, for the SDK's key-epoch tests.
//!
//! The production shell is the agent's (lane A1). This one is the least that drives N0's
//! `Negotiator<KeyProfile>` over a real `PeerChannel`: negotiation envelopes travel on the
//! channel's own ordered lane, sealed for the connection (C7), beside the application messages;
//! the SDK's `KeyEpochPort` carries `ApplyKeyEpoch` out and gates the peer's steered rounds.

pub use crate::shell_parts::is_accept;
use crate::shell_parts::{policy, spawn, Admit};
use citadel_io::tokio;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::{watch, Notify};
use citadel_negotiation::ports::KeyExchange;
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{
    Command, Envelope, Epoch, Input, KeyExchangeOutcome, Millis, NegotiationEvent,
    NegotiationState, Negotiator, NegotiatorConfig, PeerSupport,
};
use citadel_sdk::prelude::negotiation::key_epoch::{KeyEpochHandle, KeyEpochPort};
use citadel_sdk::prelude::*;
use futures::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type R = StackedRatchet;
type Send = Arc<tokio::sync::Mutex<PeerChannelSendHalf<R>>>;

const APP: u8 = 0;
const NEGOTIATION: u8 = 1;

enum ShellInput {
    Request(KeyProfile),
    Frame(Envelope),
    Outcome(Epoch, KeyExchangeOutcome),
    Tick,
}

/// Called with every inbound envelope before the negotiator sees it.
pub type FrameHook = Box<dyn Fn(&Envelope) + core::marker::Send + Sync>;

pub struct Shell {
    inputs: UnboundedSender<ShellInput>,
    pub events: UnboundedReceiver<NegotiationEvent<KeyProfile>>,
    pub app: UnboundedReceiver<Vec<u8>>,
    pub handle: KeyEpochHandle<R>,
    tx: Send,
    release: watch::Sender<bool>,
    /// Steered rounds this side triggered (only the Leader may, D2) and deliberate drops.
    pub applies: Arc<AtomicUsize>,
    pub drops: Arc<AtomicUsize>,
    pub unopened: Arc<AtomicUsize>,
    pub floors: watch::Receiver<Option<Epoch>>,
}

impl Shell {
    pub fn start(channel: PeerChannel<R>, minimum: KeyProfile, hook: Option<FrameHook>) -> Self {
        let handle = channel
            .key_epoch()
            .expect("a P2P channel has a key-epoch handle");
        let initial = KeyProfile::of(&channel.session_security_settings());
        let config = NegotiatorConfig {
            local: channel.get_session_cid(),
            peer: channel.get_peer_cid(),
            initial,
            minimum,
            support: PeerSupport::InBand,
            policy: policy(),
        };
        let neg = Arc::new(Mutex::new(Negotiator::new(config).expect("valid config")));
        let port = Arc::new(KeyEpochPort::new(handle.clone(), &policy()));
        let stepped = Arc::new(Notify::new());
        let mut rounds = port.install_gate(Arc::new(Admit(neg.clone())), stepped.clone());
        let (tx, mut rx) = channel.split();
        let tx: Send = Arc::new(tokio::sync::Mutex::new(tx));
        let (inputs, mut input_rx) = unbounded_channel();
        let (events_tx, events) = unbounded_channel();
        let (app_tx, app) = unbounded_channel();
        let (release, mut released) = watch::channel(true);
        let (floors_tx, floors) = watch::channel(None);
        let (applies, drops, unopened) = Default::default();
        let shell = Shell {
            inputs: inputs.clone(),
            events,
            app,
            handle: handle.clone(),
            tx: tx.clone(),
            release,
            applies,
            drops,
            unopened,
            floors,
        };

        let (round_inputs, round_port) = (inputs.clone(), port.clone());
        spawn(async move {
            while let Some(round) = rounds.recv().await {
                let outcome = round_port.round_outcome(round);
                let inputs = round_inputs.clone();
                spawn(async move {
                    let _ = inputs.send(ShellInput::Outcome(round.tag.epoch, outcome.await));
                });
            }
        });

        let (reader_inputs, reader_handle, unopened) =
            (inputs.clone(), handle.clone(), shell.unopened.clone());
        spawn(async move {
            while let Some(message) = rx.next().await {
                let bytes = message.as_ref();
                match bytes.split_first() {
                    Some((&APP, body)) => drop(app_tx.send(body.to_vec())),
                    Some((&NEGOTIATION, sealed)) => match reader_handle.open_frame(sealed) {
                        Ok(envelope) => {
                            if let Some(hook) = &hook {
                                hook(&envelope);
                            }
                            if released.wait_for(|open| *open).await.is_err() {
                                return;
                            }
                            let _ = reader_inputs.send(ShellInput::Frame(envelope));
                        }
                        Err(err) => {
                            log::error!(target: "citadel", "negotiation frame not opened: {err:?}");
                            unopened.fetch_add(1, Ordering::SeqCst);
                        }
                    },
                    _ => panic!("an untagged message on the test channel"),
                }
            }
        });

        let (applies, drops) = (shell.applies.clone(), shell.drops.clone());
        let conn = handle.connection_id();
        let start = Instant::now();
        spawn(async move {
            while let Some(input) = input_rx.recv().await {
                let now = Millis(start.elapsed().as_millis() as u64);
                let input = match input {
                    ShellInput::Request(value) => Input::Request(value),
                    ShellInput::Frame(envelope) => Input::Recv(envelope),
                    ShellInput::Outcome(epoch, outcome) => Input::KeyOutcome { epoch, outcome },
                    ShellInput::Tick => Input::Tick,
                };
                let (commands, wake) = {
                    let mut neg = neg.lock().unwrap();
                    (neg.step(now, input), neg.next_wake())
                };
                // C1: the agreed level applies before the Retire that follows it goes out.
                for command in &commands {
                    if let Command::Report(NegotiationEvent {
                        state: NegotiationState::Applied { agreed, .. },
                        ..
                    }) = command
                    {
                        tx.lock().await.set_security_level(agreed.level());
                    }
                }
                for command in commands {
                    match command {
                        Command::Send(envelope) => {
                            let sealed = handle.seal_frame(&envelope).expect("seal");
                            let framed = [&[NEGOTIATION][..], &sealed].concat();
                            tx.lock().await.send(framed).await.expect("frame sent");
                        }
                        Command::ApplyKeyEpoch { epoch, value } => {
                            applies.fetch_add(1, Ordering::SeqCst);
                            let (port, inputs) = (port.clone(), inputs.clone());
                            spawn(async move {
                                let outcome = port.apply(conn, epoch, value).await;
                                let _ = inputs.send(ShellInput::Outcome(epoch, outcome));
                            });
                        }
                        Command::RaiseFloor { epoch } => {
                            assert!(
                                port.raise_floor(epoch),
                                "the retired epoch's version is known"
                            );
                            let _ = floors_tx.send(Some(epoch));
                        }
                        Command::Drop { reason, .. } => {
                            log::error!(target: "citadel", "the negotiator dropped the link: {reason:?}");
                            drops.fetch_add(1, Ordering::SeqCst);
                        }
                        Command::ApplyLocal { .. } => {
                            unreachable!("the key profile applies by a key round")
                        }
                        Command::Report(event) => drop(events_tx.send(event)),
                    }
                }
                stepped.notify_waiters();
                if let Some(at) = wake {
                    let inputs = inputs.clone();
                    let after = Duration::from_millis(at.0.saturating_sub(now.0));
                    spawn(async move {
                        tokio::time::sleep(after).await;
                        let _ = inputs.send(ShellInput::Tick);
                    });
                }
            }
        });
        shell
    }

    pub fn request(&self, value: KeyProfile) {
        let _ = self.inputs.send(ShellInput::Request(value));
    }

    /// Holds inbound negotiation frames back until [`Self::release_inbound`].
    pub fn hold_inbound(&self) {
        let _ = self.release.send_replace(false);
    }

    pub fn release_inbound(&self) {
        let _ = self.release.send_replace(true);
    }

    pub async fn send_app(&self, body: &[u8]) {
        let framed = [&[APP][..], body].concat();
        self.tx
            .lock()
            .await
            .send(framed)
            .await
            .expect("app message sent");
    }

    pub async fn set_level(&self, level: SecurityLevel) {
        self.tx.lock().await.set_security_level(level);
    }

    /// Waits for the first reported event that `pick` accepts, keeping everything seen.
    pub async fn until<T>(
        &mut self,
        seen: &mut Vec<NegotiationState<KeyProfile>>,
        mut pick: impl FnMut(&NegotiationState<KeyProfile>) -> Option<T>,
    ) -> T {
        loop {
            let event = self.events.recv().await.expect("the shell is running");
            let picked = pick(&event.state);
            seen.push(event.state);
            if let Some(value) = picked {
                return value;
            }
        }
    }
}
