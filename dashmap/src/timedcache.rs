//! Threadsafe concurrent timed cache.
//!
//! Acts as a overlay on top of whatever persistent storage you are using and handles
//! loading and saving of data behind the scenes.

use crate::dashmap::DashMap;
use parking_lot::Mutex;
use std::hash::Hash;
use std::time;

pub const VALID_DURATION: time::Duration = time::Duration::from_secs(3 * 60 * 60);
pub const VALID_CHECK_INTERVAL: time::Duration = time::Duration::from_secs(30 * 60);
pub const SAVE_INTERVAL: time::Duration = time::Duration::from_secs(3 * 60);

/// Threadsafe concurrent timed cache.
/// Handles loading and potential saving behind the scenes with user supplied functions.
/// Intended for use in high concurrency applications.
///
/// The `do_check` method has to be called periodically to do maintenance.
/// The supplied durations ensure that maintenance is done independently of how often `do_check` is called.
pub struct TimedCache<K, V>
where
    K: Hash + Eq + Clone,
{
    storage: DashMap<K, (V, time::Instant, bool)>,
    load_item_fn: fn(&K) -> Option<V>,
    save_item_fn: fn(&K, &V) -> bool,
    last_saved: Mutex<time::Instant>,
    last_purged: Mutex<time::Instant>,
    valid_duration: time::Duration,
    valid_check_interval: time::Duration,
    save_interval: time::Duration,
}

impl<'a, K: Hash + Eq + Clone, V> TimedCache<K, V> {
    /// Creates a new TimedCache. Saving function may be empty if no custom saving functionality is needed.
    /// Takes three duration arguments. Supply `None` to use the defaults.
    ///
    /// The `valid_duration` argument specifies how long a entry is valid before scheduling it for eviction.
    ///
    /// The `valid_check_interval` argument specifies how often expiry checking is done.
    ///
    /// The `save_interval` argument specifies how often to call the save function on unsaved entries.
    pub fn new(
        load_item: fn(&K) -> Option<V>,
        save_item: fn(&K, &V) -> bool,
        valid_duration: Option<time::Duration>,
        valid_check_interval: Option<time::Duration>,
        save_interval: Option<time::Duration>,
    ) -> Self {
        Self {
            storage: DashMap::default(),
            load_item_fn: load_item,
            save_item_fn: save_item,
            last_saved: Mutex::new(time::Instant::now()),
            last_purged: Mutex::new(time::Instant::now()),
            valid_duration: valid_duration.unwrap_or(VALID_DURATION),
            valid_check_interval: valid_check_interval.unwrap_or(VALID_CHECK_INTERVAL),
            save_interval: save_interval.unwrap_or(SAVE_INTERVAL),
        }
    }

    /// Load an item with a specified key. Intended to mainly be called from `map` and `map_mut`
    pub fn load_item(&self, k: &K) {
        if !self.storage.contains_key(k) {
            if let Some(v) = (self.load_item_fn)(k) {
                let v = (v, time::Instant::now(), true);
                self.storage.insert(k.clone(), v);
            }
        }
    }

    /// Takes a closure with a normal reference as an argument and executes it.
    /// The function will return the same value as the closure which means the function can be used to extract data.
    pub fn map<T, F: FnOnce(&V) -> T>(&self, k: &K, f: F) -> T {
        self.load_item(k);
        let data = self.storage.get(k).unwrap();
        f(&data.0)
    }

    /// Takes a closure with a mutable reference as an argument and executes it.
    /// The function will return the same value as the closure which means the function can be used to extract data.
    pub fn map_mut<T, F: FnOnce(&mut V) -> T>(&self, k: &K, f: F) -> T {
        self.load_item(k);
        let mut data = self.storage.get_mut(k).unwrap();
        data.2 = false;
        f(&mut data.0)
    }

    /// Saves all entries. Useful to run before shutting down gracefully.
    pub fn save_all(&self) {
        let check_save_item = |k: &K, v: &mut (V, time::Instant, bool)| {
            if !v.2 && (self.save_item_fn)(k, &v.0) {
                v.2 = true;
            }
        };

        self.storage.chunks_write().for_each(|mut submap| {
            submap
                .iter_mut()
                .for_each(|(k, mut v)| check_save_item(&k, &mut v))
        });
    }

    /// Performs maintenance tasks like saving and evicting invalid entries.
    /// May take significant time depending on amount of entries and the time complexity of saving each.
    /// This is intended to be improved in a future iteration of TimedCache.
    pub fn do_check(&self) {
        let now = time::Instant::now();
        let mut last_saved = self.last_saved.lock();
        let mut last_purged = self.last_purged.lock();

        let check_save_item = |k: &K, v: &mut (V, time::Instant, bool)| {
            if !v.2 && (self.save_item_fn)(k, &v.0) {
                v.2 = true;
            }
        };

        let check_to_evict = |_k: &K, v: &mut (V, time::Instant, bool)| -> bool {
            now.duration_since(v.1) > self.valid_duration && v.2
        };

        if now.duration_since(*last_saved) > self.save_interval {
            *last_saved = now;

            self.storage.chunks_write().for_each(|mut submap| {
                submap
                    .iter_mut()
                    .for_each(|(k, mut v)| check_save_item(&k, &mut v))
            });
        }

        if now.duration_since(*last_purged) > self.valid_check_interval {
            *last_purged = now;

            self.storage.retain(|k, v| !check_to_evict(k, v));
        }
    }
}
