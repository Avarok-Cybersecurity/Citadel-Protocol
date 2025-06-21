//! Concurrency improvements and utilities for the Citadel Protocol
//!
//! This module provides improved concurrency primitives and patterns to replace
//! problematic usage patterns that can lead to deadlocks, race conditions, or
//! performance issues.

use std::sync::Arc;
use tokio::sync::{RwLock, Mutex, OwnedRwLockReadGuard, OwnedRwLockWriteGuard};
use std::hash::Hash;
use std::collections::HashMap;
use futures::future::BoxFuture;

/// A read-write lock optimized for frequently read, infrequently written data
/// 
/// This is better than Arc<Mutex<_>> for cases where reads are much more common
/// than writes, as it allows multiple concurrent readers.
pub type SharedReadWrite<T> = Arc<RwLock<T>>;

/// A mutex that's guaranteed to be used correctly in async contexts
/// 
/// This wrapper provides additional safety guarantees and deadlock detection
/// capabilities in debug builds.
#[derive(Debug)]
pub struct SafeAsyncMutex<T> {
    inner: Arc<Mutex<T>>,
    #[cfg(debug_assertions)]
    name: &'static str,
}

impl<T> SafeAsyncMutex<T> {
    /// Create a new SafeAsyncMutex
    pub fn new(value: T) -> Self {
        Self {
            inner: Arc::new(Mutex::new(value)),
            #[cfg(debug_assertions)]
            name: "unnamed",
        }
    }

    /// Create a new SafeAsyncMutex with a debug name
    #[cfg(debug_assertions)]
    pub fn new_named(value: T, name: &'static str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(value)),
            name,
        }
    }

    /// Lock the mutex, with timeout to prevent deadlocks
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, T> {
        #[cfg(debug_assertions)]
        {
            let timeout = tokio::time::Duration::from_secs(30);
            match tokio::time::timeout(timeout, self.inner.lock()).await {
                Ok(guard) => guard,
                Err(_) => {
                    panic!("Potential deadlock detected in SafeAsyncMutex '{}' - lock held for over 30 seconds", self.name);
                }
            }
        }
        #[cfg(not(debug_assertions))]
        {
            self.inner.lock().await
        }
    }

    /// Try to lock the mutex without blocking
    pub fn try_lock(&self) -> Result<tokio::sync::MutexGuard<'_, T>, tokio::sync::TryLockError> {
        self.inner.try_lock()
    }
}

impl<T> Clone for SafeAsyncMutex<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            #[cfg(debug_assertions)]
            name: self.name,
        }
    }
}

/// A specialized container for managing collections with concurrent access
/// 
/// This provides optimized patterns for common collection operations that
/// often cause contention in the original codebase.
#[derive(Debug)]
pub struct ConcurrentMap<K, V> 
where 
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    inner: Arc<RwLock<HashMap<K, V>>>,
    #[cfg(debug_assertions)]
    name: &'static str,
}

impl<K, V> ConcurrentMap<K, V>
where 
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    /// Create a new ConcurrentMap
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(debug_assertions)]
            name: "unnamed",
        }
    }

    /// Create a new ConcurrentMap with a debug name
    #[cfg(debug_assertions)]
    pub fn new_named(name: &'static str) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            name,
        }
    }

    /// Get a value by key (read operation)
    pub async fn get<Q>(&self, key: &Q) -> Option<V> 
    where 
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized + Send + Sync,
        V: Clone,
    {
        let read_guard = self.inner.read().await;
        read_guard.get(key).cloned()
    }

    /// Insert a value (write operation)
    pub async fn insert(&self, key: K, value: V) -> Option<V> {
        let mut write_guard = self.inner.write().await;
        write_guard.insert(key, value)
    }

    /// Remove a value (write operation)
    pub async fn remove<Q>(&self, key: &Q) -> Option<V>
    where 
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized + Send + Sync,
    {
        let mut write_guard = self.inner.write().await;
        write_guard.remove(key)
    }

    /// Check if key exists (read operation)
    pub async fn contains_key<Q>(&self, key: &Q) -> bool
    where 
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized + Send + Sync,
    {
        let read_guard = self.inner.read().await;
        read_guard.contains_key(key)
    }

    /// Get the number of items (read operation)
    pub async fn len(&self) -> usize {
        let read_guard = self.inner.read().await;
        read_guard.len()
    }

    /// Check if empty (read operation)
    pub async fn is_empty(&self) -> bool {
        let read_guard = self.inner.read().await;
        read_guard.is_empty()
    }

    /// Execute a closure with read access to the entire map
    pub async fn with_read<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&HashMap<K, V>) -> R + Send + 'static,
        R: Send + 'static,
    {
        let read_guard = self.inner.read().await;
        f(&*read_guard)
    }

    /// Execute a closure with write access to the entire map
    pub async fn with_write<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<K, V>) -> R + Send + 'static,
        R: Send + 'static,
    {
        let mut write_guard = self.inner.write().await;
        f(&mut *write_guard)
    }
}

impl<K, V> Clone for ConcurrentMap<K, V>
where 
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            #[cfg(debug_assertions)]
            name: self.name,
        }
    }
}

impl<K, V> Default for ConcurrentMap<K, V>
where 
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// A utility for preventing race conditions in initialization patterns
/// 
/// This helps avoid the double-checked locking antipattern and provides
/// safe lazy initialization with proper synchronization.
#[derive(Debug)]
pub struct AsyncOnce<T> {
    inner: Arc<tokio::sync::OnceCell<T>>,
}

impl<T> AsyncOnce<T> {
    /// Create a new AsyncOnce
    pub fn new() -> Self {
        Self {
            inner: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Get the value, initializing it if necessary
    pub async fn get_or_init<F, Fut>(&self, init: F) -> &T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        self.inner.get_or_init(init).await
    }

    /// Get the value if it's already initialized
    pub fn get(&self) -> Option<&T> {
        self.inner.get()
    }

    /// Try to initialize the value, returning an error if already initialized
    pub fn set(&self, value: T) -> Result<(), T> {
        self.inner.set(value)
    }
}

impl<T> Clone for AsyncOnce<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Default for AsyncOnce<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Timeout wrapper for async operations to prevent indefinite blocking
/// 
/// This helps prevent operations from hanging indefinitely, which can
/// cause the entire system to become unresponsive.
pub struct TimeoutGuard;

impl TimeoutGuard {
    /// Execute an async operation with a timeout
    pub async fn with_timeout<F, T>(
        operation: F,
        timeout: std::time::Duration,
        operation_name: &str,
    ) -> Result<T, TimeoutError>
    where
        F: std::future::Future<Output = T>,
    {
        match tokio::time::timeout(timeout, operation).await {
            Ok(result) => Ok(result),
            Err(_) => {
                log::error!(target: "citadel", "Operation '{}' timed out after {:?}", operation_name, timeout);
                Err(TimeoutError::Timeout {
                    operation: operation_name.to_string(),
                    duration: timeout,
                })
            }
        }
    }

    /// Execute an async operation with a default timeout of 30 seconds
    pub async fn with_default_timeout<F, T>(
        operation: F,
        operation_name: &str,
    ) -> Result<T, TimeoutError>
    where
        F: std::future::Future<Output = T>,
    {
        Self::with_timeout(operation, std::time::Duration::from_secs(30), operation_name).await
    }
}

/// Errors that can occur when using timeout guards
#[derive(Debug, thiserror::Error)]
pub enum TimeoutError {
    #[error("Operation '{operation}' timed out after {duration:?}")]
    Timeout {
        operation: String,
        duration: std::time::Duration,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_concurrent_map_basic_operations() {
        let map = ConcurrentMap::new();
        
        // Test insert and get
        assert_eq!(map.insert("key1".to_string(), 42).await, None);
        assert_eq!(map.get("key1").await, Some(42));
        
        // Test contains_key
        assert!(map.contains_key("key1").await);
        assert!(!map.contains_key("key2").await);
        
        // Test len and is_empty
        assert_eq!(map.len().await, 1);
        assert!(!map.is_empty().await);
        
        // Test remove
        assert_eq!(map.remove("key1").await, Some(42));
        assert!(map.is_empty().await);
    }

    #[tokio::test]
    async fn test_async_once() {
        let once = AsyncOnce::new();
        
        // Test initialization
        let value = once.get_or_init(|| async { 42 }).await;
        assert_eq!(*value, 42);
        
        // Test that it returns the same value
        let value2 = once.get_or_init(|| async { 99 }).await;
        assert_eq!(*value2, 42); // Should still be 42, not 99
        
        // Test get
        assert_eq!(once.get(), Some(&42));
    }

    #[tokio::test]
    async fn test_timeout_guard() {
        // Test successful operation
        let result = TimeoutGuard::with_timeout(
            async { 42 },
            Duration::from_secs(1),
            "test_op"
        ).await;
        assert_eq!(result.unwrap(), 42);

        // Test timeout
        let result = TimeoutGuard::with_timeout(
            async { 
                tokio::time::sleep(Duration::from_secs(2)).await;
                42
            },
            Duration::from_millis(10),
            "slow_op"
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_safe_async_mutex() {
        let mutex = SafeAsyncMutex::new(42);
        
        // Test basic lock
        {
            let guard = mutex.lock().await;
            assert_eq!(*guard, 42);
        }
        
        // Test try_lock
        let guard = mutex.try_lock().unwrap();
        assert_eq!(*guard, 42);
        drop(guard);
        
        // Test concurrent access
        let mutex_clone = mutex.clone();
        let handle = tokio::spawn(async move {
            let _guard = mutex_clone.lock().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        });
        
        handle.await.unwrap();
    }
}