//! Finding a peer connection's counters from a packet header without a lock per packet.
//!
//! A client's P2P packets that the server relays share its client-server stream, so that
//! stream's meter learns which connection each belongs to from the header's peer CID. The index
//! maps a peer CID to the counters of its current connection. Each thread caches what it looked
//! up, tagged with the index's generation; registering a connection advances the generation, so a
//! cached entry is used only while no connection has been created since. A lookup takes the
//! index's lock only on a cache miss.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use super::PathBytes;

#[derive(Clone, Debug)]
pub(crate) struct RelayIndex(Arc<Inner>);

struct Inner {
    id: u64,
    generation: AtomicU64,
    peers: citadel_io::RwLock<HashMap<u64, Weak<PathBytes>>>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayIndex")
            .field("id", &self.id)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

type CacheKey = (u64, u64);
type CacheEntry = (u64, Weak<PathBytes>);

/// Entries kept per thread before the cache is cleared: a bound, not a tuning knob. Each live
/// connection needs one; a full cache only costs a re-lookup.
const MAX_CACHED: usize = 4096;

thread_local! {
    static CACHE: RefCell<HashMap<CacheKey, CacheEntry>> = RefCell::new(HashMap::new());
}

impl RelayIndex {
    pub(crate) fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self(Arc::new(Inner {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            generation: AtomicU64::new(0),
            peers: citadel_io::RwLock::new(HashMap::new()),
        }))
    }

    /// `peer_cid`'s current connection counts on `bytes` from now on.
    pub(crate) fn register(&self, peer_cid: u64, bytes: &Arc<PathBytes>) {
        let mut peers = self.0.peers.write();
        peers.retain(|_, counters| counters.strong_count() > 0);
        peers.insert(peer_cid, Arc::downgrade(bytes));
        self.0.generation.fetch_add(1, Ordering::Release);
    }

    /// The counters of `peer_cid`'s current connection, if one exists.
    pub(crate) fn lookup(&self, peer_cid: u64) -> Option<Arc<PathBytes>> {
        let generation = self.0.generation.load(Ordering::Acquire);
        let key = (self.0.id, peer_cid);
        let cached = CACHE.with(|cache| {
            let cache = cache.borrow();
            let (seen, counters) = cache.get(&key)?;
            (*seen == generation).then(|| counters.upgrade())
        });
        if let Some(found) = cached {
            return found;
        }
        let counters = self.0.peers.read().get(&peer_cid).cloned();
        let entry = counters.clone().unwrap_or_default();
        CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache.len() >= MAX_CACHED {
                cache.clear();
            }
            cache.insert(key, (generation, entry));
        });
        counters.and_then(|weak| weak.upgrade())
    }
}
