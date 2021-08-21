use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod net_mutex;
pub mod net_rwlock;

pub trait NetObject: Serialize + DeserializeOwned + Send + Sync + Clone + 'static {}
impl<T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static> NetObject for T {}
