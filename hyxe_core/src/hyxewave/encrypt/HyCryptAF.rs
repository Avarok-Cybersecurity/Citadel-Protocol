/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::mem::transmute;
use std::sync::Arc;

use byteorder::{ReadBytesExt, WriteBytesExt};
use bytes::{BigEndian, BufMut, ByteOrder, Bytes, BytesMut};
use parking_lot::{Mutex, RawRwLock, RwLockReadGuard};
//use arrayfire::*;
use serde_derive::{Deserialize, Serialize};
use zerocopy::ByteSliceMut;

use async_mem::hyxeobject::HyxeObject;
use hyxe_util::result::{HyxeError, HyxeResult};

use crate::{HyxeObject, SecurityLevel};
use crate::hyxewave::encrypt::Drill::*;
use crate::hyxewave::misc::*;
use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;
use crate::hyxewave::network::session::SessionHandler::Session;
use async_mem::prelude::MemoryInfo;
use rayon::prelude::{ParallelSliceMut, IndexedParallelIterator, ParallelIterator, ParallelSlice};

/**
    This entire file uses GPU/CPU (if available) acceleration. AF = ArrayFire
*/
#[derive(Serialize, Deserialize, Debug)]
pub struct LinearHycryptor();

impl LinearHycryptor {
    pub fn new() -> Self {
        /*println!("Initializing GPU/CPU acceleration module...");
        set_device(0);
        info();
        print!("Info String:\n{}", info_string(true));
        println!("Arrayfire version: {:?}", get_version());
        let (name, platform, toolkit, compute) = device_info();
        print!(
            "Name: {}\nPlatform: {}\nToolkit: {}\nCompute: {}\n",
            name, platform, toolkit, compute
        );*/
        Self()
    }

    /// Appends data to dst via push. ENSURE `dst` has the reserved amount of bytes needed!
    /// Returns the number of bytes written
    #[inline]
    pub fn encrypt_bytes<Input: AsRef<[u8]>>(&self, unencrypted_bytes: Input, dst: &mut BytesMut, drill: HyxeObject<Drill>, security_level: &SecurityLevel, amplitudal_sum: &u16, session: Option<HyxeObject<Session>>) -> HyxeResult<usize> {
        debug_assert!(dst.len() != 0);

        let start_len = dst.len();

        if let Some(mut sess) = session {
            // We must trigger the SAAQ client via this function to keep it hyperactive
            sess.write().trigger();
        }

        let unencrypted_bytes = unencrypted_bytes.as_ref();
        let drill = drill.read();
        let port_range = drill.get_port_range();
        let max_len = unencrypted_bytes.len();
        let j_rand = {
            match security_level {
                SecurityLevel::LOW => *drill.get_low().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize,
                SecurityLevel::MEDIUM => *drill.get_med().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize,
                SecurityLevel::HIGH => *drill.get_high().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize,
                SecurityLevel::ULTRA => *drill.get_ultra().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize,
                SecurityLevel::DIVINE => *drill.get_divine().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize
            }
        };

        let mut current: usize = 0;

        while current < max_len {
            let mut getval: u16 = 0;
            while getval < port_range && current < max_len {
                //println!("{}, {}", current, getval);
                match security_level {
                    SecurityLevel::LOW => {
                        let c_rand = drill.get_low().get(&C_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let k_rand = drill.get_low().get(&K_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let k = c_rand ^ unencrypted_bytes[current] ^ k_rand ^ (j_rand as u8);
                        dst.put_u8(k);
                    }

                    SecurityLevel::MEDIUM => {
                        let c_rand = *drill.get_med().get(&C_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let k_rand = *drill.get_med().get(&K_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let value = unencrypted_bytes[current] as u16;

                        let k = (c_rand ^ k_rand ^ (j_rand as u16)) ^ value;
                        //let check = (c_rand ^ k_rand ^ (j_rand as u32)) ^ k;
                        //println!("c={}, k={}, input={}, output={}", c_rand, k_rand, value, k);
                        dst.put_u16_be(k);
                    }

                    SecurityLevel::HIGH => {
                        let c_rand = *drill.get_high().get(&C_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let k_rand = *drill.get_high().get(&K_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let value = unencrypted_bytes[current] as u32;

                        let k = (c_rand ^ k_rand ^ (j_rand as u32)) ^ value;
                        //let check = (c_rand ^ k_rand ^ (j_rand as u32)) ^ k;
                        //println!("c={}, k={}, input={}, output={}", c_rand, k_rand, value, k);
                        dst.put_u32_be(k);
                    }

                    SecurityLevel::ULTRA => {
                        let c_rand = *drill.get_ultra().get(&C_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let k_rand = *drill.get_ultra().get(&K_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let value = unencrypted_bytes[current] as u64;

                        let k = (c_rand ^ k_rand ^ (j_rand as u64)) ^ value;
                        //let check = (c_rand ^ k_rand ^ (j_rand as u32)) ^ k;
                        //println!("c={}, k={}, input={}, output={}", c_rand, k_rand, value, k);
                        dst.put_u64_be(k);
                    }

                    SecurityLevel::DIVINE => {
                        let c_rand = *drill.get_divine().get(&C_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let k_rand = *drill.get_divine().get(&K_RAND_INDEX).unwrap().get(&getval).unwrap();
                        let value = unencrypted_bytes[current] as u128;

                        let k = (c_rand ^ k_rand ^ (j_rand as u128)) ^ value;
                        //let check = (c_rand ^ k_rand ^ (j_rand as u32)) ^ k;
                        //println!("c={}, k={}, input={}, output={}", c_rand, k_rand, value, k);
                        dst.put_u128_be(k);
                    }
                }
                getval += 1;
                current += 1;
            }
        }

        Ok(dst.len() - start_len)
    }
}

#[inline]
pub fn par_decrypt<Input: AsRef<[u8]>>(input: Input, dest: &mut BytesMut, drill: HyxeObject<Drill>, security_level: &SecurityLevel, amplitudal_sum: &u16) -> HyxeResult<usize> {
    let encrypted_bytes = input.as_ref();
    let drill = drill.read();
    let port_range = drill.get_port_range() as usize;
    let max_len = encrypted_bytes.len();
    let size_when_decrypted = (max_len / security_level.get_encrypt_byte_multiplier()) as usize;
    let (j_rand, skip) = get_decryption_config(drill, security_level, amplitudal_sum);
    if max_len % skip != 0 {
        return HyxeError::throw("Invalid input! not divisible by zero!");
    }

    let ptr = unsafe { dest.as_mut_ptr().get_memory_address().unwrap() };


    let matrix = drill.get_high();

    encrypted_bytes.as_parallel_slice().par_chunks(skip).enumerate().map( |(idx, arr)| unsafe {
        let current_index = (idx % port_range) as u16;

        let encrypted_value = BigEndian::read_u32(&arr[0..4]);
        let c_rand = matrix.get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
        let k_rand = matrix.get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();
        let real_value = (c_rand ^ k_rand ^ (j_rand as u16)) ^ encrypted_value;
        debug_assert!(real_value < u8::max_value());

        (*ptr.index_mut(idx as isize)) = real_value as u8;
    }).collect::<()>();

    unsafe { dest.advance_mut(size_when_decrypted);}

    Ok(size_when_decrypted)
}

#[inline]
/// Returns the bytes into a newly allocated set of bytes
pub fn decrypt_bytes_alloc<'a, Input: AsRef<[u8]> + 'a>(encrypted_bytes: Input, drill: HyxeObject<Drill>, security_level: &'a SecurityLevel, amplitudal_sum: &'a u16) -> HyxeResult<&'a mut [u8]> {
    let encrypted_bytes = encrypted_bytes.as_ref();

    let drill = drill.read();
    let port_range = drill.get_port_range() as usize;
    let max_len = encrypted_bytes.len();

    let (j_rand, skip) = get_decryption_config(drill, security_level, amplitudal_sum);

    if max_len % skip != 0 {
        return HyxeError::throw("Invalid input! not divisible by zero!");
    }

    let blocks = encrypted_bytes.len() / skip;
    let mut ret_vec = Vec::with_capacity(blocks);
    unsafe { ret_vec.set_len(blocks) };

    //now,decrypt the decoded data and return
    let mut current_index = 0 as u16;
    let mut vec_idx = 0; //Equivalent to the # of bytes written

    //println!("[HyCrypter] skip={}, encrypted_length={}, blocks=unencrypted_length/skip={}", skip, encrypted_bytes.len(), blocks);

    for block_idx in 0..blocks {
        let block_idx = block_idx * skip;
        //println!("GetVal = {}, And going to parse block {} of {}", current_index, block_idx/skip, blocks);
        let encrypted_data_current = &encrypted_bytes[block_idx..(block_idx + skip)];
        match security_level {
            SecurityLevel::LOW => {
                assert_eq!(encrypted_data_current.len(), 1);
                let encrypted_value = &encrypted_data_current[0];
                let c_rand = *drill.get_low().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_low().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u8)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                ret_vec[vec_idx] = true_value;
            }

            SecurityLevel::MEDIUM => {
                assert_eq!(encrypted_data_current.len(), 2);
                let encrypted_value = BigEndian::read_u16(&encrypted_data_current[0..2]);
                let c_rand = *drill.get_med().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_med().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u16)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                ret_vec[vec_idx] = true_value as u8;
            }

            SecurityLevel::HIGH => {
                assert_eq!(encrypted_data_current.len(), 4);
                let encrypted_value = BigEndian::read_u32(&encrypted_data_current[0..4]);
                let c_rand = *drill.get_high().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_high().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u32)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                ret_vec[vec_idx] = true_value as u8;
            }

            SecurityLevel::ULTRA => {
                assert_eq!(encrypted_data_current.len(), 8);
                let encrypted_value = BigEndian::read_u64(&encrypted_data_current[0..8]);
                let c_rand = *drill.get_ultra().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_ultra().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u64)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                ret_vec[vec_idx] = true_value as u8;
            }

            SecurityLevel::DIVINE => {
                assert_eq!(encrypted_data_current.len(), 16);
                let encrypted_value = BigEndian::read_u128(&encrypted_data_current[0..16]);
                let c_rand = *drill.get_divine().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_divine().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u128)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                ret_vec[vec_idx] = true_value as u8;
            }
        }

        if current_index == port_range - 1 {
            current_index = 0;
        } else {
            current_index += 1;
        }
        vec_idx += 1;
    }
    Ok(ret_vec.as_mut_slice())
}

#[inline]
/// Returns the bytes into the input, then trimming the input (hence the input must be mutable)
pub fn decrypt_bytes_slice<Input: ByteSliceMut>(mut encrypted_bytes: Input, drill: HyxeObject<Drill>, security_level: &SecurityLevel, amplitudal_sum: &u16) -> HyxeResult<usize> {
    let drill = drill.read();
    let port_range = drill.get_port_range() as usize;
    let max_len = encrypted_bytes.len();

    let (j_rand, skip) = get_decryption_config(drill, security_level, amplitudal_sum);

    if max_len % skip != 0 {
        return HyxeError::throw("Invalid input! not divisible by zero!");
    }

    let blocks = encrypted_bytes.len() / skip;

    //now,decrypt the decoded data and return
    let mut current_index = 0 as u16;
    let mut vec_idx = 0; //Equivalent to the # of bytes written

    //println!("[HyCrypter] skip={}, encrypted_length={}, blocks=unencrypted_length/skip={}", skip, encrypted_bytes.len(), blocks);

    for block_idx in 0..blocks {
        let block_idx = block_idx * skip;
        //println!("GetVal = {}, And going to parse block {} of {}", current_index, block_idx/skip, blocks);
        let encrypted_data_current = &encrypted_bytes[block_idx..(block_idx + skip)];
        match security_level {
            SecurityLevel::LOW => {
                assert_eq!(encrypted_data_current.len(), 1);
                let encrypted_value = &encrypted_data_current[0];
                let c_rand = *drill.get_low().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_low().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u8)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                encrypted_bytes[vec_idx] = true_value;
            }

            SecurityLevel::MEDIUM => {
                assert_eq!(encrypted_data_current.len(), 2);
                let encrypted_value = BigEndian::read_u16(&encrypted_data_current[0..2]);
                let c_rand = *drill.get_med().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_med().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u16)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                encrypted_bytes[vec_idx] = true_value as u8;
            }

            SecurityLevel::HIGH => {
                assert_eq!(encrypted_data_current.len(), 4);
                let encrypted_value = BigEndian::read_u32(&encrypted_data_current[0..4]);
                let c_rand = *drill.get_high().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_high().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u32)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                encrypted_bytes[vec_idx] = true_value as u8;
            }

            SecurityLevel::ULTRA => {
                assert_eq!(encrypted_data_current.len(), 8);
                let encrypted_value = BigEndian::read_u64(&encrypted_data_current[0..8]);
                let c_rand = *drill.get_ultra().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_ultra().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u64)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                encrypted_bytes[vec_idx] = true_value as u8;
            }

            SecurityLevel::DIVINE => {
                assert_eq!(encrypted_data_current.len(), 16);
                let encrypted_value = BigEndian::read_u128(&encrypted_data_current[0..16]);
                let c_rand = *drill.get_divine().get(&C_RAND_INDEX).unwrap().get(&current_index).unwrap();
                let k_rand = *drill.get_divine().get(&K_RAND_INDEX).unwrap().get(&current_index).unwrap();

                let true_value = (c_rand ^ k_rand ^ (j_rand as u128)) ^ encrypted_value;

                //println!("c={}, k={}, encrypted_value={}, decrypted_value={}", c_rand, k_rand, encrypted_value, true_value);
                encrypted_bytes[vec_idx] = true_value as u8;
            }
        }

        if current_index == port_range - 1 {
            current_index = 0;
        } else {
            current_index += 1;
        }
        vec_idx += 1;
    }

    encrypted_bytes = encrypted_bytes.split_at(vec_idx).0;
    Ok(vec_idx)
}

#[inline]
fn get_decryption_config(drill: RwLockReadGuard<Drill>, security_level: &SecurityLevel, amplitudal_sum: &u16,) -> (usize, usize) {
    match security_level {
        SecurityLevel::LOW => (*drill.get_low().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize, 1),
        SecurityLevel::MEDIUM => (*drill.get_med().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize, 2),
        SecurityLevel::HIGH => (*drill.get_high().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize, 4),
        SecurityLevel::ULTRA => (*drill.get_ultra().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize, 8),
        SecurityLevel::DIVINE => (*drill.get_divine().get(&AMPLITUDE_DIFFERENTIALS_KEY_INDEX).unwrap().get(amplitudal_sum).unwrap() as usize, 16)
    }
}