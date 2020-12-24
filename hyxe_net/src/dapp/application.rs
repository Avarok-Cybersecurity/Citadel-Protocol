use crate::dapp::primitives::accessor::{NetworkTransferable, OwnedGuard};
use crate::dapp::primitives::variable::{NetworkVariableInner, VariableType, NetworkVariable};
use crate::hdp::outbound_sender::channel;
use std::sync::Arc;
use crossbeam_utils::sync::ShardedLock;
use std::collections::HashMap;
use std::sync::atomic::{Ordering, AtomicU64};

/// Each application that gets run spawns in its own task associated with a session
#[derive(Clone)]
pub struct Application {
    map: Arc<ShardedLock<HashMap<u64, NetworkVariableInner>>>,
    id_generator: Arc<AtomicU64>
}

impl Application {
    pub fn create_mutex_variable<T: NetworkTransferable>(&self, value: T) -> NetworkVariable<T> {
        self.create_variable(value, VariableType::MutualExclusion)
    }

    pub fn create_rwlock_variable<T: NetworkTransferable>(&self, value: T) -> NetworkVariable<T> {
        self.create_variable(value, VariableType::ReadWriteLock)
    }

    #[allow(unused_variables, unused_results)]
    fn create_variable<T: NetworkTransferable>(&self, value: T, var_type: VariableType) -> NetworkVariable<T> {
        let (notifier_tx, notifier_rx) = channel::<()>(1);
        let (updater_tx, updater_rx) = channel::<OwnedGuard<T>>(1);
        let net_var_inner = NetworkVariableInner::new::<T>(value, var_type, notifier_rx, updater_tx);
        let user_net_var = NetworkVariable::<T>::new(net_var_inner.clone());
        let mut lock = self.map.write().unwrap();
        lock.insert(self.get_next_vid(), net_var_inner);
        // register the variable with the internal local mapping
        user_net_var
    }

    fn get_next_vid(&self) -> u64 {
        self.id_generator.fetch_add(1, Ordering::SeqCst) + 1
    }
}