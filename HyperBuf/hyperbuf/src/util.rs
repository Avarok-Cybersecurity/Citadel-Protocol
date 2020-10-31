/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

/// For efficient packing of data
#[allow(unused)]
pub mod bit_handler {
    /// for shifting
    const EMPTY5: u8 = 0b1111_0000;
    /// for shifting
    const EMPTY6: u8 = 0b0000_1111;

    #[inline]
    /// Packs two values (n,k) such that 0 <= (n,k) <= 2^4 into a single 8-bit byte. There are NO CHECKS IF `first` or `second` are above this for performance reasons! Use wisely!
    pub fn pack4_4(first: u8, second: u8) -> u8 {
        (first << 4) | second
    }

    #[inline]
    /// The inverse of pack4_4. Returns the values in the original order they were packed
    pub fn unpack4_4(byte: u8) -> [u8; 2] { [(byte & EMPTY5) >> 4, byte & EMPTY6] }

    #[repr(align(4))]
    /// Used for storing powers of two
    #[allow(missing_docs)]
    pub enum U4 {
        ONE = 0b0001,
        TWO = 0b0010,
        THREE = 0b0011,
        FOUR = 0b0100,
        FIVE = 0b0101,
        SIX = 0b0110,
        SEVEN = 0b0111,
    }
}

pub(super) mod ser {
    use std::fs::File;
    //use tokio::fs::File;
    //use futures::TryFutureExt;
    //use tokio::io::AsyncWriteExt;
    use std::io::{BufReader, Write};
    use crate::results::{MemError, InformationResult};
    use serde::Serialize;
    use serde::de::DeserializeOwned;

    /// Serializes an entity to the disk
    pub(crate) fn serialize_hypervec_to_disk<'a, T: Serialize + 'a>(full_path: &'a str, entity: T) -> InformationResult<'a, usize, String> {
        //bincode::serialize(entity).unwrap().as_slice()
        File::create(full_path)
            .map_err(|err| MemError::GENERIC(err.to_string()))
            .and_then(|mut file| file.write(bincode::serialize(&entity).unwrap().as_slice()).map_err(|err| MemError::GENERIC(err.to_string())))
            .map_err(|err| err)
    }

    /// Deserializes an entity to the disk
    /// Objects to consider:
    ///             bytes,
    ///             cursor (isize: 8 bytes),
    ///             read_version (usize: 8 bytes),
    ///             write_version (usize: 8 bytes),
    ///             is_be (bool: 1 byte)
    /// Tactic: start from the end, assume the bytes are properly placed in order
    pub(crate) fn deserialize_hypervec_from_disk<'a, T: DeserializeOwned>(full_path: &str) -> InformationResult<'a, T, String> {
        File::open(full_path).map_err(|err| MemError::GENERIC(err.to_string())).and_then(|res| {
            let rx = BufReader::new(res);
            bincode::config().deserialize_from(rx).map_err(|err| MemError::GENERIC(err.to_string()))
        }).map_err(|err| MemError::GENERIC(err.to_string()))
    }

}