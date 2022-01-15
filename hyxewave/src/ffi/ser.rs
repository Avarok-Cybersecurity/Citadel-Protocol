use serde::{ser::SerializeSeq, Serialize, Serializer};

#[derive(Serialize)]
pub enum Test {
    X1(#[serde(serialize_with = "string")] u64, #[serde(serialize_with = "string")] u64, String, #[serde(serialize_with = "string_vec")] Vec<u64>),
    X2(#[serde(serialize_with = "string")] u64, #[serde(serialize_with = "string")] u32, String)
}

use std::fmt::Display;

pub fn string<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where T: Display,
          S: Serializer
{
    serializer.collect_str(value)
}

pub fn string_vec<T, S>(values: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
    where T: Display,
          S: Serializer
{
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for element in values {
        seq.serialize_element(&format!("{}", element))?;
    }
    seq.end()
}