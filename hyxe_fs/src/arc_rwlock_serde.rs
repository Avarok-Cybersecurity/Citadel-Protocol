/*use serde::{Deserialize, Serialize};
use serde::de::Deserializer;
use serde::ser::Serializer;
use std::sync::{Arc, RwLock};

/// Serializes an Arc<RwLock<T>> Type. Warning! This drops the inner device
pub fn serialize<S, T>(val: &Arc<RwLock<T>>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
          T: Serialize,
{
    let extract = Arc::try_unwrap(val.clone()).ok().unwrap().into_inner()?;
    T::serialize(&extract, s)
}

/// Deserializes an inner T into an Arc<RwLock<T>> device
pub fn deserialize<'de, D, T>(d: D) -> Result<Arc<RwLock<T>>, D::Error>
    where D: Deserializer<'de>,
          T: Deserialize<'de>,
{
    Ok(Arc::new(RwLock::new(T::deserialize(d)?)))
}*/