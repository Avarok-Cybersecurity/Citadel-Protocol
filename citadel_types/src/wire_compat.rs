//! Reading a field whose value may be one this node cannot use.
//!
//! The wire format is bincode, which has no field names, so every field is read in order and an
//! encoding that stops early is refused. A field marked
//! `#[serde(default, deserialize_with = "ok_or_default")]` reads as its default when its value
//! fails validation or names a variant this node does not know (an admission challenge from a
//! provider it does not support, a path policy it cannot accept). It cannot tell a missing value
//! from an unusable one, so it also reads an encoding that stops before the field: use it only
//! where reading the default is safe, and never to carry an older encoding forward.

use serde::{Deserialize, Deserializer};

/// The field's value, or its default when there is none this node can read.
pub fn ok_or_default<'a, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'a> + Default,
    D: Deserializer<'a>,
{
    Ok(T::deserialize(deserializer).unwrap_or_default())
}
