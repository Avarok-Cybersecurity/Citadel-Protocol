/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use bytes::{BufMut, ByteOrder};
use byteorder::BigEndian;
use hyxe_crypt::misc::CryptError;


const empty: u8 = 0b00000000;
const empty2: u8 = 0b00000011;
const empty3: u8 = 0b00011100;
const empty4: u8 = 0b11100000;

const empty5: u8 = 0b11110000;
const empty6: u8 = 0b00001111;


#[inline]
/// Packs two values (n,k) such that 0 <= (n,k) <= 2^4 into a single 8-bit byte. There are NO CHECKS IF `first` or `second` are above this for performance reasons! Use wisely!
pub fn pack4_4(first: u8, second: u8) -> u8 {
    (first << 4) | second
}

#[inline]
/// The inverse of pack4_4. Returns the values in the original order they were packed
pub fn unpack4_4(byte: u8) -> [u8; 2] { [(byte & empty5) >> 4, byte & empty6] }

#[inline]
/// Packs 3 values (n,k,z) such that 0 <= (n,k) <= 2^3 and 0 <= z <= 2^2 into a single 8-bit byte. There are NO CHECKS IF `first` or `second` or `two_bit` are above this for performance reasons! Use wisely!
pub fn pack3_3_2(first: u8, second: u8, two_bit: u8) -> u8 {
    ((((first << 3) | second) << 2) | two_bit)
}

#[inline]
/// The inverse of pack3_3_2. Returns the values in the original order they were packed
pub fn unpack3_3_2(byte: u8) -> [u8; 3] {
    [(byte & empty4) >> 5, (byte & empty3) >> 2, byte & empty2]
}

/// Performs a XOR against a supplied nonce. This, unlike the inverse function, is infallible
#[inline]
pub fn apply_nonce<T: AsRef<[u8]>>(input: &T, nonce: u64) -> Vec<u8> {
    let input = input.as_ref();
    let full_len = input.len() * 8;

    let mut output = Vec::with_capacity(full_len); // the nonce is a u64... for each byte input, the output is stretched by 8 times

    for byte in bytes_unnonced {
        let block = (byte as u64) ^ nonce;
        output.put_u64_be(block)
    }

    output
}

/// The inverse of `apply_nonce`
#[inline]
pub fn unapply_nonce<T: AsRef<[u8]>>(input: &T, nonce: u64) -> Result<Vec<u8>, CryptError<String>> {
    let input = input.as_ref();
    
    if input.len() % 8 != 0 {
        return Err(CryptError::OutOfBoundsError)
    }

    let unnonced_len = input.len() / 8;

    let mut output = Vec::with_capacity(unnonced_len);

    for bytes in input.chunks(8) {
        let nonced_u64 = BigEndian::read_u64(bytes);
        let unnonced_value = nonced_u64 ^ nonce;
        if unnonced_value > std::u8::MAX as u64 {
            return Err(CryptError::OutOfBoundsError)
        }
        
        (&mut output).push(unnonced_value as u8);
    }

    Ok(output)
}