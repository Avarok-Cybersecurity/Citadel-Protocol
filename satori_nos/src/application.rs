use crate::primitives::accessor::{NetworkTransferable, OwnedGuard};
use crate::primitives::variable::{NetworkVariableInner, VariableType, NetworkVariable};
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{Ordering, AtomicU64};
use parking_lot::RwLock;
use tokio::sync::mpsc::{channel, Sender};
use serde::{Serialize, Deserialize};
use crate::primitives::updater::VariableUpdater;

/// Each application that gets run spawns in its own task associated with a session
#[derive(Clone)]
pub struct Application {
    /// These variables maintain a shared-state across the network
    variables: Arc<RwLock<HashMap<u64, (Sender<NetworkUpdateState>, NetworkVariableInner)>>>,
    id_generator: Arc<AtomicU64>
}

#[derive(Serialize, Deserialize)]
pub enum ApplicationState {
    Variable { state: VariableState, vid: u64, value: Vec<u8> }
}

#[derive(Serialize, Deserialize)]
pub enum VariableState {
    Init, Update
}

#[allow(variant_size_differences)]
#[derive(Serialize, Deserialize)]
pub enum NetworkUpdateState {
    AllowRead { vid: u64 },
    AllowWrite { vid: u64 },
    ValueModified { vid: u64, value: Vec<u8> }
}

impl Application {
    pub fn new() -> Self {
        Self {
            variables: Arc::new(RwLock::new(HashMap::new())),
            id_generator: Arc::new(AtomicU64::new(1))
        }
    }

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
        let (state_update_tx, state_update_rx) = channel(3);
        let net_var_inner = NetworkVariableInner::new::<T>(value, var_type, notifier_rx, updater_tx);
        let user_net_var = NetworkVariable::<T>::new(net_var_inner.clone());

        let variable_updater = VariableUpdater::<T>::new(state_update_rx, notifier_tx, net_var_inner.clone());
        // TODO: updater_rx handler
        let mut lock = self.variables.write();
        lock.insert(self.get_next_vid(), (state_update_tx, net_var_inner));
        // spawn the variable updater
        tokio::task::spawn(variable_updater);
        // register the variable with the internal local mapping
        user_net_var
    }

    fn get_next_vid(&self) -> u64 {
        self.id_generator.fetch_add(1, Ordering::SeqCst)
    }
}