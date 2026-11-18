//! Subscription pairing under [`WireRevision::Exchanged`](crate::sync::wire::WireRevision).
//!
//! The receiver proposes each id (`Open { topic, id }`) and the initiator answers with the id it
//! took (`OpenAck { id }`), so the id is the receiver's choice and both ends hold the same one by
//! construction. Opens wait in a queue per topic, so a subscription pairs only with the peer's
//! subscription on the same topic: a call the peer never matched waits for its own match instead
//! of taking the peer's next one.
//!
//! Cancellation is part of the protocol, since every caller runs under a timeout:
//! - a receiver whose proposal the peer has seen leaves it as an orphan, and its next open on the
//!   same topic adopts it, because the peer will (or did) answer that id;
//! - an initiator cancelled before its answer went out puts the proposal back for its next open.
//!
//! The connection's reader never waits on this state, so a burst of opens cannot stall the data
//! of established subscriptions; the queue of unanswered proposals is bounded instead.

use crate::multiplex::MultiplexedConnKey;
use crate::sync::subscription::Subscribable;
use crate::sync::wire::Topic;
use citadel_io::tokio::sync::Notify;
use std::collections::{HashMap, HashSet, VecDeque};

/// Proposals unanswered at once, across all topics. A receiver waits for an answer before it
/// proposes past this, so an initiator holding more is facing a peer that ignores the bound, and
/// refuses the excess instead of queueing it.
pub(crate) const MAX_UNANSWERED_PROPOSALS: usize = 64;

pub struct Pairing<K: MultiplexedConnKey> {
    state: citadel_io::Mutex<State<K>>,
    changed: Notify,
}

struct State<K> {
    closed: bool,
    next_seq: u64,
    /// Receiver: proposals with an opener waiting on them.
    live: HashSet<K>,
    /// Receiver: proposals the peer has seen whose opener was cancelled, oldest first by seq.
    orphans: HashMap<Topic, Vec<(u64, K)>>,
    /// Receiver: answered proposals not yet taken by their opener.
    answered: HashSet<K>,
    /// Receiver: proposals sent (live or orphaned) and not yet answered.
    outstanding: usize,
    /// Initiator: the peer's proposals not yet answered, in arrival order.
    proposals: HashMap<Topic, VecDeque<K>>,
    unanswered: usize,
}

impl<K: MultiplexedConnKey> Pairing<K> {
    pub(crate) fn new() -> Self {
        Self {
            state: citadel_io::Mutex::new(State {
                closed: false,
                next_seq: 0,
                live: HashSet::new(),
                orphans: HashMap::new(),
                answered: HashSet::new(),
                outstanding: 0,
                proposals: HashMap::new(),
                unanswered: 0,
            }),
            changed: Notify::new(),
        }
    }

    /// Initiator side: the peer proposed `id` for `topic`.
    pub(crate) fn proposed(&self, topic: Topic, id: K) -> Result<(), anyhow::Error> {
        let mut state = self.state.lock();
        if state.unanswered >= MAX_UNANSWERED_PROPOSALS {
            return Err(anyhow::Error::msg(format!(
                "refused proposal {id:?}: {MAX_UNANSWERED_PROPOSALS} already unanswered"
            )));
        }
        state.unanswered += 1;
        state.proposals.entry(topic).or_default().push_back(id);
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Receiver side: the peer took `id`. An answer to no proposal of ours is dropped.
    pub(crate) fn answered(&self, id: K) -> Result<(), anyhow::Error> {
        let mut state = self.state.lock();
        let ours = state.live.contains(&id)
            || state
                .orphans
                .values()
                .any(|o| o.iter().any(|(_, k)| *k == id));
        if !ours {
            return Err(anyhow::Error::msg(format!("answer to no proposal: {id:?}")));
        }
        if state.answered.insert(id) {
            state.outstanding -= 1;
        }
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Nothing more can arrive: every waiting open fails.
    pub(crate) fn close(&self) {
        self.state.lock().closed = true;
        self.changed.notify_waiters();
    }

    /// Waits until `ready` yields a value, re-checking after every change.
    async fn wait_for<T>(
        &self,
        mut ready: impl FnMut(&mut State<K>) -> Option<T>,
    ) -> Result<T, anyhow::Error> {
        loop {
            let notified = self.changed.notified();
            citadel_io::tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.state.lock();
                if let Some(value) = ready(&mut state) {
                    return Ok(value);
                }
                if state.closed {
                    return Err(anyhow::Error::msg("the connection ended before pairing"));
                }
            }
            notified.await;
        }
    }
}

/// Undoes a half-done open when its caller is cancelled.
enum Undo<'a, S: Subscribable<ID = K>, K: MultiplexedConnKey> {
    /// Receiver: forget a proposal the peer never saw.
    Unsent(&'a S, K),
    /// Receiver: keep a proposal the peer saw for the next open on its topic.
    Orphan(&'a S, Topic, u64, K),
    /// Initiator: return a proposal whose answer did not go out.
    Unanswered(&'a S, Topic, K),
    Done,
}

impl<S: Subscribable<ID = K>, K: MultiplexedConnKey> Undo<'_, S, K> {
    fn disarm(&mut self) {
        // Only references and ids: forgetting the replaced value skips its undo and leaks nothing.
        std::mem::forget(std::mem::replace(self, Undo::Done));
    }
}

impl<S: Subscribable<ID = K>, K: MultiplexedConnKey> Drop for Undo<'_, S, K> {
    fn drop(&mut self) {
        // By copy: every field is a reference or an id.
        match *self {
            Undo::Unsent(ptr, id) => {
                {
                    let mut state = ptr.pairing().state.lock();
                    state.live.remove(&id);
                    state.outstanding -= 1;
                }
                let _ = ptr.subscriptions().write().remove(&id);
                ptr.pairing().changed.notify_waiters();
            }
            Undo::Orphan(ptr, topic, seq, id) => {
                let mut state = ptr.pairing().state.lock();
                state.live.remove(&id);
                state.orphans.entry(topic).or_default().push((seq, id));
            }
            Undo::Unanswered(ptr, topic, id) => {
                {
                    let mut state = ptr.pairing().state.lock();
                    state.unanswered += 1;
                    state.proposals.entry(topic).or_default().push_front(id);
                }
                ptr.pairing().changed.notify_waiters();
            }
            Undo::Done => {}
        }
    }
}

fn adopt_orphan<K: MultiplexedConnKey>(state: &mut State<K>, topic: Topic) -> Option<(u64, K)> {
    let orphans = state.orphans.get_mut(&topic)?;
    let oldest = (0..orphans.len()).min_by_key(|&i| orphans[i].0)?;
    let adopted = orphans.swap_remove(oldest);
    state.live.insert(adopted.1);
    Some(adopted)
}

pub(crate) async fn open_as_receiver<S: Subscribable<ID = K>, K: MultiplexedConnKey>(
    ptr: &S,
    topic: Topic,
) -> Result<S::BorrowedSubscriptionType, anyhow::Error> {
    let pairing = ptr.pairing();
    let adopted = adopt_orphan(&mut pairing.state.lock(), topic);
    let (id, mut undo) = match adopted {
        Some((seq, id)) => (id, Undo::Orphan(ptr, topic, seq, id)),
        None => {
            let (seq, id) = pairing
                .wait_for(|state| {
                    if state.outstanding >= MAX_UNANSWERED_PROPOSALS {
                        return None;
                    }
                    state.outstanding += 1;
                    state.next_seq += 1;
                    let id = ptr.get_next_id();
                    state.live.insert(id);
                    Some((state.next_seq, id))
                })
                .await?;
            let mut unsent = Undo::Unsent(ptr, id);
            // Reserved before the peer learns the id, so what it sends after answering is kept.
            ptr.reserve(id);
            ptr.post_close_container().setup_channel(id).await;
            ptr.send_open(topic, id).await?;
            unsent.disarm();
            (id, Undo::Orphan(ptr, topic, seq, id))
        }
    };
    pairing
        .wait_for(|state| state.answered.remove(&id).then_some(()))
        .await?;
    // No await from here on: both ends hold the id.
    pairing.state.lock().live.remove(&id);
    undo.disarm();
    claim(ptr, id)
}

pub(crate) async fn open_as_initiator<S: Subscribable<ID = K>, K: MultiplexedConnKey>(
    ptr: &S,
    topic: Topic,
) -> Result<S::BorrowedSubscriptionType, anyhow::Error> {
    let pairing = ptr.pairing();
    let id = pairing
        .wait_for(|state| {
            let id = state.proposals.get_mut(&topic)?.pop_front()?;
            state.unanswered -= 1;
            Some(id)
        })
        .await?;
    let mut undo = Undo::Unanswered(ptr, topic, id);
    ptr.reserve(id);
    ptr.post_close_container().setup_channel(id).await;
    ptr.send_open_ack(id).await?;
    // No await from here on: the peer holds the answer.
    undo.disarm();
    claim(ptr, id)
}

fn claim<S: Subscribable<ID = K>, K: MultiplexedConnKey>(
    ptr: &S,
    id: K,
) -> Result<S::BorrowedSubscriptionType, anyhow::Error> {
    ptr.claim_reserved(id).ok_or_else(|| {
        anyhow::Error::msg(format!(
            "subscription {id:?} is no longer reserved (claimed, or refused for buffering too much)"
        ))
    })
}
