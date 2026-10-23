//! Reading a message an older or newer node wrote.
//!
//! The wire format is bincode, which has no field names: a field added at the END of a message
//! is simply absent from an older node's bytes, and an older node ignores the trailing bytes of
//! a newer one (`allow_trailing_bytes`). Mark such a field
//! `#[serde(default, deserialize_with = "ok_or_default")]`: it then reads as its default when it
//! is missing, or when it carries a value this node cannot decode (a variant added later).

use serde::{Deserialize, Deserializer};

/// The field's value, or its default when there is none this node can read.
pub fn ok_or_default<'a, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'a> + Default,
    D: Deserializer<'a>,
{
    Ok(T::deserialize(deserializer).unwrap_or_default())
}
