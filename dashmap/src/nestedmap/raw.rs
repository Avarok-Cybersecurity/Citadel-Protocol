use crate::uniform_allocator::UniformAllocator;
use crate::util;
use crate::util::sharedptr_null;
use crate::util::UniformAllocExt;
use crate::util::UniformDeallocExt;
use crate::util::UnsafeOption;
use ccl_crossbeam_epoch::{self as epoch, Atomic, Guard, Owned, Pointer, Shared};
use rand::prelude::*;
use std::hash::Hash;
use std::mem;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::Arc;

const TABLE_SIZE: usize = 96;

pub struct Entry<K: Hash + Eq, V> {
    pub key: K,
    pub value: V,
}

pub enum Bucket<K: Hash + Eq, V> {
    Leaf(u8, Entry<K, V>),
    Branch(u8, Table<K, V>),
}

impl<K: Hash + Eq, V> Bucket<K, V> {
    #[inline(always)]
    fn key_ref(&self) -> &K {
        if let Bucket::Leaf(_, entry) = self {
            &entry.key
        } else {
            panic!("bucket unvalid key get")
        }
    }

    #[inline(always)]
    fn tag(&self) -> u8 {
        match self {
            Bucket::Leaf(tag, _) => *tag,
            Bucket::Branch(tag, _) => *tag,
        }
    }
}

pub struct Table<K: Hash + Eq, V> {
    nonce: u8,
    buckets: Box<[Atomic<Bucket<K, V>>; TABLE_SIZE]>,
    allocator: Arc<UniformAllocator<Bucket<K, V>>>,
}

pub struct TableRef<'a, K: Hash + Eq, V> {
    guard: Option<epoch::Guard>,
    ptr: &'a Entry<K, V>,
}

impl<'a, K: Hash + Eq, V> Drop for TableRef<'a, K, V> {
    #[inline(always)]
    fn drop(&mut self) {
        let guard = self.guard.take();
        mem::drop(guard);
    }
}

impl<'a, K: Hash + Eq, V> TableRef<'a, K, V> {
    #[inline(always)]
    pub fn key(&self) -> &K {
        &self.ptr.key
    }

    #[inline(always)]
    pub fn value(&self) -> &V {
        &self.ptr.value
    }
}

impl<'a, K: Hash + Eq, V> Deref for TableRef<'a, K, V> {
    type Target = V;

    #[inline(always)]
    fn deref(&self) -> &V {
        &self.value()
    }
}

impl<K: Hash + Eq, V> Drop for Table<K, V> {
    fn drop(&mut self) {
        self.buckets.iter().for_each(|ptr| {
            let ptr = unsafe { ptr.load(Ordering::Acquire, epoch::unprotected()) };
            if !ptr.is_null() {
                unsafe {
                    ptr.uniform_dealloc(&self.allocator, ptr.deref().tag() as usize);
                }
            }
        });
    }
}

impl<'a, K: 'a + Hash + Eq, V: 'a> Table<K, V> {
    #[inline(always)]
    pub fn allocator(&self) -> &UniformAllocator<Bucket<K, V>> {
        &self.allocator
    }

    #[inline]
    fn with_two_entries(
        allocator: Arc<UniformAllocator<Bucket<K, V>>>,
        entry_1: Shared<'a, Bucket<K, V>>,
        entry_2: Shared<'a, Bucket<K, V>>,
    ) -> Self {
        let mut table = Self::empty(allocator);
        let entry_1_pos = unsafe {
            util::hash_with_nonce(entry_1.as_ref().unsafe_unwrap().key_ref(), table.nonce) as usize
                % TABLE_SIZE
        };
        let entry_2_pos = unsafe {
            util::hash_with_nonce(entry_2.as_ref().unsafe_unwrap().key_ref(), table.nonce) as usize
                % TABLE_SIZE
        };

        if entry_1_pos != entry_2_pos {
            table.buckets[entry_1_pos].store(entry_1, Ordering::Release);
            table.buckets[entry_2_pos].store(entry_2, Ordering::Release);
        } else {
            let tag: u8 = rand::thread_rng().gen();
            table.buckets[entry_1_pos] = Atomic::uniform_alloc(
                &table.allocator,
                tag as usize,
                Bucket::Branch(
                    tag,
                    Table::with_two_entries(table.allocator.clone(), entry_1, entry_2),
                ),
            );
        }

        table
    }

    #[inline]
    pub fn empty(allocator: Arc<UniformAllocator<Bucket<K, V>>>) -> Self {
        Self {
            nonce: rand::thread_rng().gen(),
            buckets: unsafe { Box::new(mem::zeroed()) },
            allocator,
        }
    }

    pub fn layer_pregen(allocator: Arc<UniformAllocator<Bucket<K, V>>>, layers: u8) -> Self {
        let mut table = Self::empty(allocator.clone());
        if layers == 0 {
            return table;
        }
        for slot in table.buckets.iter_mut() {
            let tag: u8 = rand::thread_rng().gen();
            *slot = Atomic::uniform_alloc(
                &table.allocator,
                tag as usize,
                Bucket::Branch(tag, Table::layer_pregen(allocator.clone(), layers - 1)),
            );
        }
        table
    }

    #[inline]
    pub fn get(&'a self, key: &K, guard: Guard) -> Option<TableRef<'a, K, V>> {
        let fake_guard = unsafe { epoch::unprotected() };
        let key_pos = util::hash_with_nonce(key, self.nonce) as usize % TABLE_SIZE;

        let bucket_shared: Shared<'a, Bucket<K, V>> =
            self.buckets[key_pos].load(Ordering::Acquire, fake_guard);

        if bucket_shared.is_null() {
            None
        } else {
            let bucket_ref = unsafe { bucket_shared.deref() };

            match bucket_ref {
                Bucket::Leaf(_, entry) => {
                    if &entry.key == key {
                        Some(TableRef {
                            guard: Some(guard),
                            ptr: entry,
                        })
                    } else {
                        None
                    }
                }

                Bucket::Branch(_, table) => table.get(key, guard),
            }
        }
    }

    #[inline(always)]
    pub fn contains_key(&'a self, key: &K, guard: Guard) -> bool {
        self.get(key, guard).is_some()
    }

    #[inline]
    pub fn insert(&self, entry: Owned<Bucket<K, V>>, guard: &Guard) {
        let key_pos = util::hash_with_nonce(entry.key_ref(), self.nonce) as usize % TABLE_SIZE;
        let bucket = &self.buckets[key_pos];

        let mut entry = Some(entry);

        match bucket.compare_and_set(
            sharedptr_null(),
            unsafe { entry.unsafe_take().unsafe_unwrap() },
            Ordering::Acquire,
            guard,
        ) {
            Ok(_) => {}

            Err(err) => {
                entry = Some(err.new);
                let actual = err.current;
                let actual_ref = unsafe { actual.as_ref().expect("insert1 null") };

                let entry = unsafe { entry.unsafe_take().unsafe_unwrap() };
                match actual_ref {
                    Bucket::Branch(_, ref table) => table.insert(entry, guard),
                    Bucket::Leaf(actual_tag, ref old_entry) => {
                        if entry.key_ref() == &old_entry.key {
                            bucket.store(entry, Ordering::Release);
                            unsafe {
                                guard.defer_unchecked(|| {
                                    actual.uniform_dealloc(&self.allocator, *actual_tag as usize);
                                })
                            }
                        } else {
                            let tag: u8 = rand::thread_rng().gen();
                            let uz = unsafe { mem::transmute_copy::<Owned<_>, usize>(&entry) };

                            let new_table = Owned::uniform_alloc(
                                &self.allocator,
                                tag as usize,
                                Bucket::Branch(
                                    tag,
                                    Table::with_two_entries(
                                        self.allocator.clone(),
                                        actual,
                                        entry.into_shared(guard),
                                    ),
                                ),
                            );
                            //bucket.store(new_table, Ordering::Release);
                            match bucket.compare_and_set(actual, new_table, Ordering::SeqCst, guard)
                            {
                                Ok(_) => {}
                                Err(_) => self.insert(unsafe { Owned::from_usize(uz) }, guard),
                            }
                        }
                    }
                }
            }
        }
    }

    #[inline]
    pub fn remove(&self, key: &K, guard: &Guard) {
        let key_pos = util::hash_with_nonce(key, self.nonce) as usize % TABLE_SIZE;

        let bucket_sharedptr = self.buckets[key_pos].load(Ordering::Acquire, guard);

        if let Some(bucket_ref) = unsafe { bucket_sharedptr.as_ref() } {
            match bucket_ref {
                Bucket::Branch(_, table) => table.remove(key, guard),
                Bucket::Leaf(tag, _) => {
                    let res = self.buckets[key_pos].compare_and_set(
                        bucket_sharedptr,
                        sharedptr_null(),
                        Ordering::SeqCst,
                        guard,
                    );

                    if res.is_ok() {
                        let allocator = self.allocator.clone();

                        unsafe {
                            guard.defer_unchecked(move || {
                                bucket_sharedptr.uniform_dealloc(&allocator, *tag as usize);
                            })
                        };
                    }
                }
            }
        }
    }

    #[inline]
    pub fn iter(&'a self, guard: Rc<Guard>) -> TableIter<'a, K, V> {
        TableIter {
            table: self,
            idx: 0,
            guard,
            current_subiter: Box::new(None),
        }
    }

    #[inline]
    pub fn len(&self, guard: &'a Guard) -> usize {
        let mut l = 0;
        let mut idx = 0;

        while idx < TABLE_SIZE {
            let bucket_shared: Shared<'a, Bucket<K, V>> =
                self.buckets[idx].load(Ordering::Acquire, guard);

            if let Some(r) = unsafe { bucket_shared.as_ref() } {
                match r {
                    Bucket::Leaf(_, _) => l += 1,
                    Bucket::Branch(_, table) => l += table.len(guard),
                }
            }

            idx += 1;
        }

        l
    }
}

pub struct TableIter<'a, K: Hash + Eq, V> {
    table: &'a Table<K, V>,
    idx: usize,
    guard: Rc<Guard>,
    current_subiter: Box<Option<TableIter<'a, K, V>>>,
}

impl<'a, K: Hash + Eq, V> Iterator for TableIter<'a, K, V> {
    type Item = TableRef<'a, K, V>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        // Check if we contains a iterator to a subtable.
        if let Some(subiter) = &mut *self.current_subiter {
            // Fetch element from subiter. If it's Some we return it.
            // If it isn't we discard the iterator.
            if let Some(v) = subiter.next() {
                return Some(v);
            } else {
                // Discard iterator.
                *self.current_subiter = None;
            }
        }

        loop {
            // We have checked every entry in the table and none is left.
            if self.idx == TABLE_SIZE {
                return None;
            }

            if let Some(bucket_ref) = unsafe {
                self.table.buckets[self.idx]
                    .load(Ordering::Acquire, epoch::unprotected())
                    .as_ref()
            } {
                self.idx += 1;

                match bucket_ref {
                    Bucket::Leaf(_, entry) => {
                        return Some(TableRef {
                            guard: Some(epoch::pin()),
                            ptr: entry,
                        });
                    }

                    Bucket::Branch(_, table) => {
                        *self.current_subiter = Some(table.iter(self.guard.clone()));
                        return self.next();
                    }
                }
            } else {
                self.idx += 1;
            }
        }
    }
}
