//! See struct level documentation.

mod raw;

#[cfg(test)]
mod tests;

use crate::uniform_allocator::UniformAllocator;
use crate::util::UniformAllocExt;
use ccl_crossbeam_epoch::{self as epoch, Guard, Owned};
use rand::prelude::*;
use raw::{Bucket, Entry as RawEntry, Table};
pub use raw::{TableIter, TableRef};
use std::fmt;
use std::hash::Hash;
use std::rc::Rc;
use std::sync::Arc;

pub struct OccupiedEntry<'a, K: Hash + Eq, V> {
    map: &'a NestedMap<K, V>,
    guard: Guard,
    r: TableRef<'a, K, V>,
    key: K,
}

impl<'a, K: Hash + Eq, V> OccupiedEntry<'a, K, V> {
    #[inline(always)]
    pub fn new(guard: Guard, map: &'a NestedMap<K, V>, r: TableRef<'a, K, V>, key: K) -> Self {
        Self { map, guard, r, key }
    }

    #[inline(always)]
    pub fn key(&self) -> &K {
        self.r.key()
    }

    #[inline(always)]
    pub fn remove(self) {
        self.map.remove_with_guard(self.r.key(), &self.guard);
    }

    #[inline(always)]
    pub fn get(&self) -> &V {
        self.r.value()
    }

    #[inline(always)]
    pub fn insert(self, value: V) {
        self.map.insert_with_guard(self.key, value, &self.guard);
    }

    #[inline(always)]
    pub fn into_ref(self) -> TableRef<'a, K, V> {
        self.r
    }
}

pub struct VacantEntry<'a, K: Hash + Eq, V> {
    map: &'a NestedMap<K, V>,
    guard: Guard,
    key: K,
}

impl<'a, K: Hash + Eq, V> VacantEntry<'a, K, V> {
    #[inline(always)]
    pub fn new(guard: Guard, map: &'a NestedMap<K, V>, key: K) -> Self {
        Self { map, guard, key }
    }

    #[inline(always)]
    pub fn insert(self, value: V) {
        self.map.insert_with_guard(self.key, value, &self.guard);
    }

    #[inline(always)]
    pub fn into_key(self) -> K {
        self.key
    }

    #[inline(always)]
    pub fn key(&self) -> &K {
        &self.key
    }
}

impl<'a, K: Hash + Eq + Clone, V> VacantEntry<'a, K, V> {
    #[inline(always)]
    pub fn insert_with_ret(self, value: V) -> (&'a NestedMap<K, V>, Guard, K) {
        self.map
            .insert_with_guard(self.key.clone(), value, &self.guard);
        (self.map, self.guard, self.key)
    }
}

pub enum Entry<'a, K: Hash + Eq, V> {
    Occupied(OccupiedEntry<'a, K, V>),
    Vacant(VacantEntry<'a, K, V>),
}

impl<'a, K: Hash + Eq, V> Entry<'a, K, V> {
    #[inline(always)]
    pub fn is_occupied(&self) -> bool {
        if let Entry::Occupied(_) = self {
            true
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn into_occupied(self) -> Option<OccupiedEntry<'a, K, V>> {
        if let Entry::Occupied(v) = self {
            Some(v)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn is_vacant(&self) -> bool {
        if let Entry::Vacant(_) = self {
            true
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn into_vacant(self) -> Option<VacantEntry<'a, K, V>> {
        if let Entry::Vacant(v) = self {
            Some(v)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn key(&self) -> &K {
        match self {
            Entry::Occupied(v) => v.key(),
            Entry::Vacant(v) => v.key(),
        }
    }

    #[inline(always)]
    pub fn and_inspect<F: FnOnce(&V)>(self, f: F) -> Self {
        if let Entry::Occupied(occupied) = &self {
            f(occupied.get());
        }

        self
    }
}

impl<'a, K: Hash + Eq + Clone, V> Entry<'a, K, V> {
    pub fn or_insert(self, default: V) -> TableRef<'a, K, V> {
        match self {
            Entry::Occupied(occupied) => occupied.into_ref(),
            Entry::Vacant(vacant) => {
                let (map, guard, key) = vacant.insert_with_ret(default);
                map.get_with_guard(&key, guard)
                    .expect("this should never happen; nestedmap entry or_insert")
            }
        }
    }

    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> TableRef<'a, K, V> {
        match self {
            Entry::Occupied(occupied) => occupied.into_ref(),
            Entry::Vacant(vacant) => {
                let (map, guard, key) = vacant.insert_with_ret(default());
                map.get_with_guard(&key, guard)
                    .expect("this should never happen; nestedmap entry or_insert")
            }
        }
    }
}

#[inline(always)]
pub fn aquire_guard() -> Guard {
    epoch::pin()
}

/// NestedMap is a threadsafe concurrent hashmap with generally good performance.
///
///
/// The primary difference compared to DashMap is that NestedMap is lockfree and non-blocking which
/// makes it more appealing for latency critical things. It also has faster reads that DHashMap.
pub struct NestedMap<K: Hash + Eq, V> {
    root: Table<K, V>,
}

impl<'a, K: 'a + Hash + Eq, V: 'a> NestedMap<K, V> {
    /// Create a new completely empty map.
    pub fn new() -> Self {
        Self {
            root: Table::layer_pregen(Arc::new(UniformAllocator::default()), 1),
        }
    }

    /// Create a new map but the root table is prefilled. This may make rapid initial growth more efficient.
    /// Now does the same as Self::new().
    #[deprecated]
    pub fn new_layer_prefill() -> Self {
        Self {
            root: Table::layer_pregen(Arc::new(UniformAllocator::default()), 1),
        }
    }

    /// Insert a value into the map.
    #[inline(always)]
    pub fn insert(&self, key: K, value: V) {
        let guard = &epoch::pin();
        self.insert_with_guard(key, value, guard);
    }

    /// Insert a value into the map with an existing guard, saving on guard creation.
    #[inline(always)]
    pub fn insert_with_guard(&self, key: K, value: V, guard: &Guard) {
        let tag: u8 = rand::thread_rng().gen();

        let bucket = Owned::uniform_alloc(
            self.root.allocator(),
            tag as usize,
            Bucket::Leaf(tag, RawEntry { key, value }),
        );
        self.root.insert(bucket, guard);
    }

    /// Get a reference to a value in the map.
    #[inline(always)]
    pub fn get(&'a self, key: &K) -> Option<TableRef<'a, K, V>> {
        let guard = epoch::pin();
        self.get_with_guard(key, guard)
    }

    /// Get a value from the map with an existing guard, saving on guard cration.
    #[inline(always)]
    pub fn get_with_guard(&'a self, key: &K, guard: Guard) -> Option<TableRef<'a, K, V>> {
        self.root.get(key, guard)
    }

    /// Remove an item from the map.
    #[inline(always)]
    pub fn remove(&self, key: &K) {
        let guard = &epoch::pin();
        self.remove_with_guard(key, guard);
    }

    /// Remove an item from the map with an existing guard, saving on guard creation.
    #[inline(always)]
    pub fn remove_with_guard(&self, key: &K, guard: &Guard) {
        self.root.remove(key, guard);
    }

    /// Check if the map contains a given key.
    #[inline(always)]
    pub fn contains_key(&self, key: &K) -> bool {
        let guard = epoch::pin();
        self.root.contains_key(key, guard)
    }

    /// Iterate over all items in a map.
    #[inline(always)]
    pub fn iter(&'a self) -> TableIter<'a, K, V> {
        let guard = Rc::new(epoch::pin());
        self.root.iter(guard)
    }

    /// Get the amount of elements in the map.
    #[inline(always)]
    pub fn len(&self) -> usize {
        let guard = &epoch::pin();
        self.root.len(guard)
    }

    /// Check if the map is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get an entry from the map.
    #[inline]
    pub fn entry(&'a self, key: K) -> Entry<'a, K, V> {
        let guard = epoch::pin();

        match self.get(&key) {
            None => Entry::Vacant(VacantEntry::new(guard, self, key)),
            Some(r) => Entry::Occupied(OccupiedEntry::new(guard, self, r, key)),
        }
    }

    /// Extend the map with an iterator.
    #[inline]
    pub fn extend<I: IntoIterator<Item = (K, V)>>(&self, iter: I) {
        let guard = &epoch::pin();

        for pair in iter {
            self.insert_with_guard(pair.0, pair.1, guard);
        }
    }
}

impl<'a, K: 'a + Hash + Eq, V: 'a> Default for NestedMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K: 'a + Hash + Eq, V: 'a> fmt::Debug for NestedMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NestedMap {{}}")
    }
}

impl<'a, K: 'a + Hash + Eq, V: 'a> IntoIterator for &'a NestedMap<K, V> {
    type Item = TableRef<'a, K, V>;
    type IntoIter = TableIter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
