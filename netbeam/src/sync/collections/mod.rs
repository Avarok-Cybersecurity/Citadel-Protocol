use std::collections::HashMap;
use anyhow::Error;
use std::hash::Hash;
use crate::sync::collections::net_abstract_collection::NetAbstractCollection;

pub mod net_abstract_collection;

pub type NetVec<T, S> = NetAbstractCollection<T, usize, Vec<T>, S>;
pub type NetHashMap<K, T, S> = NetAbstractCollection<T, K, HashMap<K, T>, S>;

pub trait AbstractCollection<K, V>: Default {
    fn insert(&mut self, k: K, v: V) -> Result<Option<V>, anyhow::Error>;
    fn remove(&mut self, k: &K) -> Option<V>;
    fn get(&self, k: &K) -> Option<&V>;
    fn get_mut(&mut self, k: &K) -> Option<&mut V>;
    fn clear(&mut self);
    fn len(&self) -> usize;
}

impl<V> AbstractCollection<usize, V> for Vec<V> {
    fn insert(&mut self, k: usize, v: V) -> Result<Option<V>, anyhow::Error> {
        if k > self.len() {
            return Err(anyhow::Error::msg("index > len"))
        }

        Vec::insert(self, k, v);
        Ok(None)
    }

    fn remove(&mut self, k: &usize) -> Option<V> {
        if *k < self.len() {
            Some(Vec::remove(self, *k))
        } else {
            None
        }
    }

    fn get(&self, k: &usize) -> Option<&V> {
        self.as_slice().get(*k)
    }

    fn get_mut(&mut self, k: &usize) -> Option<&mut V> {
        self.as_mut_slice().get_mut(*k)
    }

    fn clear(&mut self) {
        Vec::clear(self)
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }
}

impl<K: Eq + Hash, V> AbstractCollection<K, V> for HashMap<K, V> {
    fn insert(&mut self, k: K, v: V) -> Result<Option<V>, Error> {
        Ok(HashMap::insert(self, k, v))
    }

    fn remove(&mut self, k: &K) -> Option<V> {
        HashMap::remove(self, k)
    }

    fn get(&self, k: &K) -> Option<&V> {
        HashMap::get(self, k)
    }

    fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        HashMap::get_mut(self, k)
    }

    fn clear(&mut self) {
        HashMap::clear(self)
    }

    fn len(&self) -> usize {
        HashMap::len(self)
    }
}