use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

pub mod net_mutex;
pub mod net_rwlock;

pub trait NetObject: Debug + Serialize + DeserializeOwned + Send + Sync + Clone + 'static {}
impl<T: Debug + Serialize + DeserializeOwned + Send + Sync + Clone + 'static> NetObject for T {}
