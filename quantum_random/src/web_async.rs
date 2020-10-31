use std::str;
use std::sync::Arc;

use byteorder::*;
use chrono::{DateTime, Local, Utc};
//use futures::{FutureExt, StreamExt, TryStreamExt, TryFutureExt};
use futures::StreamExt;
use mut_static::MutStatic;
use parking_lot::RwLock;
use rand::prelude::*;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rayon::prelude::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::util::*;

/// There are 1024 x 1024 possible hex values. There are thus 1024 x 1024 x 2 possible bytes
pub static MAX_BLOCK_SIZE: u32 = 1024 * 1024;
/// Toggles debug
pub static ENABLE_DEBUG: bool = true;
///Enable temporarily if you're encountering problems with fetching the data
pub static MAX_RETRY_COUNT: u8 = 10;
///In the case the https stream is interrupted (I've had this happen quite frequently), increase this value. 10 should be more than enough for a stable connection
pub static ENTROPY_BANK_EXPIRE_MS: i64 = 60000;
//every minute, the bank should update
/// #
pub static ENTROPY_BANK_SIZE: u32 = MAX_BLOCK_SIZE - 1;

#[macro_use]
lazy_static! {
    static ref DEFAULT_ENTROPY_BANK: MutStatic<Arc<RwLock<EntropyBank>>> = MutStatic::new();
    pub(crate) static ref REQWEST_CLIENT: MutStatic<Client> = MutStatic::new();
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// The default structure for holding random bytes
pub struct EntropyBank {
    bank: Option<Vec<u8>>,
    timestamp: Option<DateTime<Utc>>,
    name: Option<String>,
}

impl EntropyBank {
    /// Returns an EntropyBank
    fn new(vector: Vec<u8>) -> Arc<RwLock<Self>> {
        let now = DateTime::<Utc>::from_utc(Local::now().naive_utc(), Utc);
        Arc::new(RwLock::new(Self {
            bank: Some(vector),
            timestamp: Some(now),
            name: None,
        }))
    }

    /// Returns an EntropyBank asynchronously
    pub async fn new_async(size: u32) -> Result<Arc<RwLock<Self>>, QuantumError> {
        get_data_async(size).await.and_then(move |data| {
            Ok(EntropyBank::new(data))
        })
    }

    /// Checks if the entropy bank is usable
    pub fn default_entropy_bank_loaded_to_memory_and_is_valid() -> bool {
        if DEFAULT_ENTROPY_BANK.is_set().unwrap() {
            //file is set into memory; check to see if it expired
            return !DEFAULT_ENTROPY_BANK.read().unwrap().read_recursive().did_expire();
        }
        false
    }

    /// Saves the EntropyBank to the hard drive
    pub fn save(&mut self, name: Option<String>) -> Result<(), QuantumError> {
        let name = name.unwrap_or(ENTROPY_BANK_DEFAULT_FILE.to_string());
        self.name = Some(name.to_string());
        let obj = self.clone();
        if let Err(_) = serialize_entity_to_disk(format!("{}cfg/{}.entropy", get_home_dir(), name), obj) {
            return QuantumError::throw("[QuantumRandom] Unable to serialize entity to disk!");
        }
        Ok(())
    }

    /// TODO: Stop deserializing it constantly, this is actually a security risk in the case of a local virus
    pub async fn load(name_opt: Option<String>) -> Result<Arc<RwLock<Self>>, QuantumError> {
        let name_is_none = name_opt.is_none();
        let name = name_opt.unwrap_or(ENTROPY_BANK_DEFAULT_FILE.to_string());
        let fname = sanitize_path(format!("{}cfg/{}.entropy", get_home_dir(), name));

        if !entropy_file_exists() && name_is_none {
            return QuantumError::throw("[QuantumRandom] Unable to get entropy bank (none exist!)");
        }

        println!("[QRandom::EntropyBank] Going to deserialize {}", &fname);
        let res = deserialize_entity_from_disk::<EntropyBank>(fname);

        if res.is_err() {
            return QuantumError::throw("Unable to get entropy bank");
        }

        let l2m = Arc::new(RwLock::new(res.unwrap()));
        let ret = Arc::clone(&l2m);
        // Update the global entropy file
        if name == ENTROPY_BANK_DEFAULT_FILE {
            //load the default file to memory
            if let Err(_) = DEFAULT_ENTROPY_BANK.set(l2m) {
                return QuantumError::throw("[QuantumRandom] Unable to set default entropy bank!");
            }
        }

        Ok(ret)
    }

    /// Performs a deep clone of the EntropyBank
    pub fn replicate(&self) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(self.clone()))
    }

    /// Determines if the EntropyBank expired
    pub fn did_expire(&self) -> bool {
        let now = DateTime::<Utc>::from_utc(Local::now().naive_utc(), Utc).timestamp_millis();
        now - self.timestamp.unwrap().timestamp_millis() >= ENTROPY_BANK_EXPIRE_MS
    }

    /// Shuffles the EntropyBank and returns a reference to the newly allocated array for read access
    pub fn shuffle_and_get(&mut self, len: usize, save: bool) -> Result<Vec<u8>, QuantumError> {
        println!("bank size: {}", self.bank.as_mut().unwrap().len());
        // TODO: Use quantum random rng
        self.bank.as_mut().unwrap().shuffle(&mut thread_rng());
        if save {
            if let Err(err) = self.save(self.name.clone()) {
                return Err(err);
            }
        }
        println!("bank size: {}", self.bank.as_mut().unwrap().len());
        Ok(self.bank.as_ref().unwrap()[0..len].to_vec())
    }
}

/// Returns the raw bytes.
async fn get_raw_data_async(length: usize, mut _retry_count: usize) -> Result<Vec<u8>, QuantumError> {
    if length as u32 > MAX_BLOCK_SIZE {
        return QuantumError::throw_string(format!("[QuantumRandom] Error! You cannot call this function with a parameter greater than {}", MAX_BLOCK_SIZE));
    }

    //We only want 1 reqwest client
    if !REQWEST_CLIENT.is_set().unwrap() {
        if let Err(_) = REQWEST_CLIENT.set(Client::new()) {
            return QuantumError::throw("[QuantumRandom] Unable to interface with Reqwest!");
        }
    }

    providers::anu_edu_download(length).await.and_then(|mut resp| {
        let data = resp.text().unwrap();
        if ENABLE_DEBUG {
            println!("[QuantumRandom] Recv: {}", data);
        }
        Ok(data)
    }).or_else(|err| {
        QuantumError::throw_string(format!("[QuantumRandom] Unable to download data! Reason: {}", err.to_string()))
    }).and_then(move |input| extract_values_anu(length, input))
        .and_then(|vector| Ok(vector))
}

mod providers {
    use reqwest::Error;
    use reqwest::Response;

    use super::REQWEST_CLIENT;

// This one is weird. The max distance between min and max is 10000
    /*pub(crate) async fn random_org_download(_len: usize) -> String {
        let url = format!("https://www.random.org/sequences/?min=[]&max=[]&col=[]&format=plain&rnd=new");
        url
    }*/

    /// Returns the unfiltered string
    pub(crate) async fn anu_edu_download(len_total: usize) -> Result<Response, Error> {
        // size determines the number of hex pairs per item (these are NOT comma-seperated). If size = 2, then you may get 0f1e
        // length determines the number of items. If length = 3 (with size = 2), then you may get: 01fe, 1e22, 12a6
        let (length, size) = {
            if len_total <= 1024 {
                (1, len_total)
            } else {
                //println!("We want {}, and are using {} x 1024 to get it", len_total, len);
                (((len_total as f64) / (1024 as f64)).ceil() as usize, 1024)
            }
        };

        let url = format!("https://qrng.anu.edu.au/API/jsonI.php?length={}&type=hex16&size={}", length, size);
        let url = url.as_str();

        REQWEST_CLIENT.read().unwrap().get(url).send()
    }
}

/// Extracts the bytes from the downloaded string for anu qrng
pub fn extract_values_anu(len_expected: usize, data: String) -> Result<Vec<u8>, QuantumError> {
    if !data.contains("\"success\":true") {
        return QuantumError::throw("[QuantumRandom] Data downloaded, but invalid data detected!");
    }

    let parts = substring(data, "[", "]").replace("\"", "").replace(",", "").into_bytes().par_chunks(2).take(len_expected).map(|arr| unsafe {
        u8::from_str_radix(str::from_utf8_unchecked(arr), 16).unwrap() ^ random::<u8>()
    }).collect::<Vec<u8>>();


    if ENABLE_DEBUG {
        println!("Total # of parts: {}", parts.len());
    }

    if parts.len() != len_expected {
        return QuantumError::throw("[QuantumRandom] Invalid input length!");
    }

    Ok(parts)
}


/// Asyncronously splits the number of requests to maximize the volume of traffic
async fn get_data_async(length: u32) -> Result<Vec<u8>, QuantumError> {
    let mut futures0 = vec![];
    let mut iter_count = 0;

    if length < MAX_BLOCK_SIZE {
        futures0.push(get_raw_data_async(length as usize, 0));
        iter_count += 1;
    } else {
        let mut amt_left = length;
        while amt_left > MAX_BLOCK_SIZE {
            futures0.push(get_raw_data_async(MAX_BLOCK_SIZE as usize, 0));
            amt_left -= MAX_BLOCK_SIZE;
            iter_count += 1;
        }

        if amt_left >= 1 {
            futures0.push(get_raw_data_async(amt_left as usize, 0));
            iter_count += 1;
        }
    }

    if iter_count != futures0.len() {
        return QuantumError::throw("[QuantumRandom] unable to setup asynchronous split streams");
    }

    Ok(futures::stream::iter(futures0.into_iter())
        .fold(Vec::with_capacity(length as usize), |mut acc, fut| async {
            let res = fut.await.and_then(|res| Ok(res));
            match res {
                Ok(vec) => {
                    acc.extend(vec);
                    acc
                },
                Err(_) => Vec::with_capacity(0)
            }
        }).await)
}

/// Asynchronously produces `len` number of u8's from the local EntropyBank
#[allow(dead_code)]
async fn next_u8s_eb(len: usize) -> Result<Vec<u8>, QuantumError> {
    EntropyBank::load(None).await.and_then(move |res| {
        if let Ok(res) = res.write().shuffle_and_get(len, false) {
            Ok(res)
        } else {
            QuantumError::throw("[QuantumRandom] Unable to load entropy bank")
        }
    })
}

/// Asynchronously produces `length` number of u8's
async fn get_data(length: usize) -> Result<Vec<u8>, QuantumError> {
    get_data_async(length as u32).await
}

/// Asynchronously produces `len` number of u8's
pub async fn next_u8s(len: usize) -> Result<Vec<u8>, QuantumError> {
    get_data(len).await
}

/// Asynchronously produces `len` number of u16's
pub async fn next_u16s(len: usize) -> Result<Vec<u16>, QuantumError> {
    get_data(len * 2).await.and_then(move |res| {
        Ok(res.par_chunks(2).take(len).map(|chunk| {
            BigEndian::read_u16(chunk)
        }).collect::<Vec<u16>>())
    }).map_err(|err| err)
}

/// Asynchronously produces `len` number of u32's
pub async fn next_u32s(len: usize) -> Result<Vec<u32>, QuantumError> {
    get_data(len * 4).await.and_then(move |res| {
        Ok(res.par_chunks(4).take(len).map(|chunk| {
            BigEndian::read_u32(chunk)
        }).collect::<Vec<u32>>())
    }).map_err(|err| err)
}

/// Asynchronously produces `len` number of u64's
pub async fn next_u64s(len: usize) -> Result<Vec<u64>, QuantumError> {
    get_data(len * 8).await.and_then(move |res| {
        Ok(res.par_chunks(8).take(len).map(|chunk| {
            BigEndian::read_u64(chunk)
        }).collect::<Vec<u64>>())
    }).map_err(|err| err)
}

/// Asynchronously produces `len` number of u128's
pub async fn next_u128s(len: usize) -> Result<Vec<u128>, QuantumError> {
    get_data(len * 16).await.and_then(move |res| {
        Ok(res.par_chunks(16).take(len).map(|chunk| {
            BigEndian::read_u128(chunk)
        }).collect::<Vec<u128>>())
    }).map_err(|err| err)
}

/// Asynchronously produces `len` number of i8's
pub async fn next_i8s(len: usize) -> Result<Vec<i8>, QuantumError> {
    get_data(len).await.and_then(|res| {
        Ok(res.iter().map(|byte| {
            u8_to_i8(byte)
        }).collect::<Vec<i8>>())
    })
}

/// Asynchronously produces `len` number of i16's
pub async fn next_i16s(len: usize) -> Result<Vec<i16>, QuantumError> {
    get_data(len * 2).await.and_then(move |res| {
        Ok(res.par_chunks(2).take(len).map(|chunk| {
            u16_to_i16(&BigEndian::read_u16(chunk))
        }).collect::<Vec<i16>>())
    }).map_err(|err| err)
}

/// Asynchronously produces `len` number of i32's
pub async fn next_i32s(len: usize) -> Result<Vec<i32>, QuantumError> {
    get_data(len * 4).await.and_then(move |res| {
        Ok(res.par_chunks(4).take(len).map(|chunk| {
            u32_to_i32(&BigEndian::read_u32(chunk))
        }).collect::<Vec<i32>>())
    }).map_err(|err| err)
}

/// Asynchronously produces `len` number of i64's
pub async fn next_i64s(len: usize) -> Result<Vec<i64>, QuantumError> {
    get_data(len * 8).await.and_then(move |res| {
        Ok(res.par_chunks(8).take(len).map(|chunk| {
            u64_to_i64(&BigEndian::read_u64(chunk))
        }).collect::<Vec<i64>>())
    }).map_err(|err| err)
}

/// Asynchronously produces `len` number of i128's
pub async fn next_i128s(len: usize) -> Result<Vec<i128>, QuantumError> {
    get_data(len * 16).await.and_then(move |res| {
        Ok(res.par_chunks(16).take(len).map(|chunk| {
            u128_to_i128(&BigEndian::read_u128(chunk))
        }).collect::<Vec<i128>>())
    }).map_err(|err| err)
}

/// Misc functions
fn substring<T: AsRef<str>>(arr: T, start: &str, end: &str) -> String {
    let arr = arr.as_ref();
    let start_idx = arr.find(start).unwrap();
    let end_idx = arr.find(end).unwrap();
    arr.chars().skip(start_idx + 1).take(end_idx - start_idx - 1).collect()
}

#[inline]
fn u8_to_i8(input: &u8) -> i8 {
    let limit = i8::max_value() as u8;
    if *input >= limit {
        (*input - limit) as i8
    } else {
        *input as i8 - limit as i8
    }
}

#[inline]
fn u16_to_i16(input: &u16) -> i16 {
    let limit = i16::max_value() as u16;
    if *input >= limit {
        (*input - limit) as i16
    } else {
        *input as i16 - limit as i16
    }
}

#[inline]
fn u32_to_i32(input: &u32) -> i32 {
    let limit = i32::max_value() as u32;
    if *input >= limit {
        (*input - limit) as i32
    } else {
        *input as i32 - limit as i32
    }
}

#[inline]
fn u64_to_i64(input: &u64) -> i64 {
    let limit = i64::max_value() as u64;
    if *input >= limit {
        (*input - limit) as i64
    } else {
        *input as i64 - limit as i64
    }
}

#[inline]
fn u128_to_i128(input: &u128) -> i128 {
    let limit = i128::max_value() as u128;
    if *input >= limit {
        (*input - limit) as i128
    } else {
        *input as i128 - limit as i128
    }
}