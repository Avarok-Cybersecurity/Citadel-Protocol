//! # Cryptographic Types and Utilities
//!
//! This module provides core cryptographic types and utilities for the Citadel Protocol,
//! including secure memory management, algorithm selection, and parameter configuration.
//!
//! ## Key Components
//!
//! ### Secure Memory Management
//!
//! The module provides `SecBuffer` for secure handling of sensitive data:
//!
//! ```rust
//! use citadel_types::crypto::SecBuffer;
//!
//! // Create a secure buffer
//! let mut buffer = SecBuffer::empty();
//!
//! // Work with the buffer securely
//! {
//!     let mut handle = buffer.handle();
//!     handle.extend_from_slice(b"sensitive data");
//! } // Memory is locked when handle is dropped
//! ```
//!
//! ### Cryptographic Parameters
//!
//! Configure cryptographic algorithms and security levels:
//!
//! ```rust
//! use citadel_types::crypto::{KemAlgorithm, EncryptionAlgorithm, SecurityLevel};
//!
//! // Create parameters
//! let params = KemAlgorithm::Kyber
//!     + EncryptionAlgorithm::ChaCha20Poly_1305;
//!
//! // Set security level
//! let level = SecurityLevel::High;
//! ```
//!
//! ### Algorithm Selection
//!
//! Supported algorithms include:
//!
//! - KEM (Key Encapsulation Mechanism)
//!   - Kyber (1024)
//! - Encryption
//!   - ChaCha20-Poly1305
//!   - AES-GCM
//!   - Ascon
//! - Signatures
//!   - Falcon
//!
//! ## Security Considerations
//!
//! - All sensitive data should be stored in `SecBuffer`
//! - Use appropriate security levels for your use case
//! - Consider perfect secrecy mode for maximum security
//! - Properly handle algorithm selection based on requirements

use crate::utils;
use crate::utils::validate_crypto_params;
use bytes::{Bytes, BytesMut};
use packed_struct::derive::{PackedStruct, PrimitiveEnum_u8};
use packed_struct::{PackedStruct, PrimitiveEnum};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Formatter};
use std::ops::{Add, Deref, DerefMut};
use strum::{EnumCount, ParseError};
use uuid::Uuid;

pub const LARGEST_NONCE_LEN: usize = KYBER_NONCE_LENGTH_BYTES;

pub const CHA_CHA_NONCE_LENGTH_BYTES: usize = 12;
pub const ASCON_NONCE_LENGTH_BYTES: usize = 16;
pub const AES_GCM_NONCE_LENGTH_BYTES: usize = 12;
pub const KYBER_NONCE_LENGTH_BYTES: usize = 32;

pub const KEM_ALGORITHM_COUNT: u8 = KemAlgorithm::COUNT as u8;

impl From<CryptoParameters> for u8 {
    fn from(val: CryptoParameters) -> Self {
        let bytes: [u8; 1] = val.pack().unwrap();
        bytes[0]
    }
}

pub trait AlgorithmsExt:
    strum::IntoEnumIterator + for<'a> TryFrom<&'a str> + Debug + PrimitiveEnum<Primitive = u8>
{
    fn list() -> Vec<Self> {
        Self::iter().collect()
    }

    fn try_from_str<R: AsRef<str>>(t: R) -> Result<Self, ParseError> {
        Self::try_from(t.as_ref()).map_err(|_| ParseError::VariantNotFound)
    }

    fn names() -> Vec<String> {
        Self::iter()
            .map(|r| format!("{r:?}").to_lowercase())
            .collect()
    }

    fn from_u8(input: u8) -> Option<Self> {
        Self::from_primitive(input)
    }

    fn as_u8(&self) -> u8 {
        self.to_primitive()
    }

    fn set_crypto_param(&self, params: &mut CryptoParameters);
}

pub fn add_inner<L: AlgorithmsExt, R: AlgorithmsExt>(lhs: L, rhs: R) -> CryptoParameters {
    let mut ret = CryptoParameters::default();
    lhs.set_crypto_param(&mut ret);
    rhs.set_crypto_param(&mut ret);
    ret
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Default)]
pub enum SecrecyMode {
    /// Slowest, but ensures each packet gets encrypted with a unique symmetrical key
    Perfect,
    /// Fastest. Meant for high-throughput environments. Each message will attempt to get re-keyed, but if not possible, will use the most recent symmetrical key
    #[default]
    BestEffort,
}

impl TryFrom<u8> for SecrecyMode {
    type Error = crate::errors::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Perfect),
            1 => Ok(Self::BestEffort),
            _ => Err(Self::Error::Other(format!(
                "Cannot cast `{}` into SecrecyMode",
                value
            ))),
        }
    }
}

/// A memory-secure wrapper for shipping around Bytes
pub struct SecBuffer {
    pub inner: BytesMut,
}

impl SecBuffer {
    /// Creates an unlocked, empty buffer
    pub fn empty() -> Self {
        Self::with_capacity(0)
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self::from(BytesMut::with_capacity(cap))
    }

    /// Returns the inner element without dropping the memory
    pub fn into_buffer(mut self) -> BytesMut {
        self.unlock();
        std::mem::take(&mut self.inner)
    }

    /// For accessing the inner element
    pub fn handle(&mut self) -> SecureBufMutHandle {
        SecureBufMutHandle::new(self)
    }

    /// returns the length of the buffer
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    fn lock(&self) {
        unsafe { utils::mem::mlock(self.slice().as_ptr(), self.inner.len()) }
    }

    fn unlock(&self) {
        unsafe { utils::mem::munlock(self.slice().as_ptr(), self.inner.len()) }
    }

    fn zeroize(&mut self) {
        unsafe { utils::mem::zeroize(self.slice().as_ptr(), self.inner.len()) }
    }

    fn slice(&self) -> &[u8] {
        &self.inner[..]
    }

    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct SecureBufMutHandle<'a> {
    inner: &'a mut SecBuffer,
}

impl<'a> SecureBufMutHandle<'a> {
    fn new(inner: &'a mut SecBuffer) -> SecureBufMutHandle<'a> {
        inner.unlock();
        Self { inner }
    }
}

impl Deref for SecureBufMutHandle<'_> {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.inner.inner
    }
}

impl DerefMut for SecureBufMutHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.inner
    }
}

impl Drop for SecureBufMutHandle<'_> {
    fn drop(&mut self) {
        self.inner.lock()
    }
}

impl AsRef<[u8]> for SecBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner[..]
    }
}

impl AsMut<[u8]> for SecBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
    }
}

impl From<Vec<u8>> for SecBuffer {
    fn from(inner: Vec<u8>) -> Self {
        Self::from(BytesMut::from(Bytes::from(inner)))
    }
}

impl From<BytesMut> for SecBuffer {
    fn from(inner: BytesMut) -> Self {
        let this = Self { inner };
        this.lock();
        this
    }
}

impl<const N: usize> From<[u8; N]> for SecBuffer {
    fn from(this: [u8; N]) -> Self {
        Self::from(&this as &[u8])
    }
}

impl From<&[u8]> for SecBuffer {
    fn from(this: &[u8]) -> Self {
        Self::from(BytesMut::from(this))
    }
}

impl From<&str> for SecBuffer {
    fn from(this: &str) -> Self {
        Self::from(BytesMut::from(this))
    }
}

impl Drop for SecBuffer {
    fn drop(&mut self) {
        self.unlock();
        self.zeroize();
    }
}

impl Debug for SecBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "***SECRET***")
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for SecBuffer {
    fn eq(&self, other: &T) -> bool {
        // Constant time comparison to prevent timing attacks
        let this = self.as_ref();
        let other = other.as_ref();
        utils::const_time_compare(this, other)
    }
}

impl Clone for SecBuffer {
    fn clone(&self) -> Self {
        self.unlock();
        let ret = SecBuffer::from(self.inner.clone());
        self.lock();
        ret
    }
}

impl Serialize for SecBuffer {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        self.unlock();
        let ret = self.inner.serialize(serializer);
        self.lock();
        ret
    }
}

impl<'de> Deserialize<'de> for SecBuffer {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from(BytesMut::deserialize(deserializer)?))
    }
}

impl SecurityLevel {
    /// Returns byte representation of self
    pub fn value(self) -> u8 {
        match self {
            SecurityLevel::Standard => 0,
            SecurityLevel::Reinforced => 1,
            SecurityLevel::High => 2,
            SecurityLevel::Ultra => 3,
            SecurityLevel::Extreme => 4,
            SecurityLevel::Custom(val) => val,
        }
    }

    /// Possibly returns the security_level given an input value
    pub fn for_value(val: usize) -> Option<Self> {
        Some(SecurityLevel::from(u8::try_from(val).ok()?))
    }
}

#[derive(PackedStruct, Default, Serialize, Deserialize, Copy, Clone, Debug)]
#[packed_struct(bit_numbering = "msb0")]
pub struct CryptoParameters {
    #[packed_field(bits = "0..=2", ty = "enum")]
    pub encryption_algorithm: EncryptionAlgorithm,
    #[packed_field(bits = "3..=5", ty = "enum")]
    pub kem_algorithm: KemAlgorithm,
    #[packed_field(bits = "6..=7", ty = "enum")]
    pub sig_algorithm: SigAlgorithm,
}

impl TryFrom<u8> for CryptoParameters {
    type Error = crate::errors::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value: [u8; 1] = [value];
        let this: CryptoParameters = CryptoParameters::unpack(&value)
            .map_err(|err| crate::errors::Error::Other(err.to_string()))?;
        validate_crypto_params(&this)?;
        Ok(this)
    }
}

#[derive(
    PrimitiveEnum_u8,
    Default,
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    strum::EnumString,
    strum::EnumIter,
)]
pub enum EncryptionAlgorithm {
    #[default]
    AES_GCM_256 = 0,
    ChaCha20Poly_1305 = 1,
    Kyber = 2,
    Ascon80pq = 3,
}

#[derive(
    PrimitiveEnum_u8,
    Default,
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    strum::EnumString,
    strum::EnumIter,
    strum::EnumCount,
)]
pub enum KemAlgorithm {
    #[strum(ascii_case_insensitive)]
    #[default]
    Kyber = 0,
}

#[derive(
    PrimitiveEnum_u8,
    strum::EnumString,
    strum::EnumIter,
    Default,
    Serialize,
    Deserialize,
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
)]
pub enum SigAlgorithm {
    #[default]
    None = 0,
    Falcon1024 = 1,
}

impl AlgorithmsExt for KemAlgorithm {
    fn set_crypto_param(&self, params: &mut CryptoParameters) {
        params.kem_algorithm = *self;
    }
}

impl AlgorithmsExt for EncryptionAlgorithm {
    fn set_crypto_param(&self, params: &mut CryptoParameters) {
        params.encryption_algorithm = *self;
    }
}

impl AlgorithmsExt for SigAlgorithm {
    fn set_crypto_param(&self, params: &mut CryptoParameters) {
        params.sig_algorithm = *self;
    }
}

impl<R: AlgorithmsExt> Add<R> for KemAlgorithm {
    type Output = CryptoParameters;

    fn add(self, rhs: R) -> Self::Output {
        add_inner(self, rhs)
    }
}

impl<R: AlgorithmsExt> Add<R> for EncryptionAlgorithm {
    type Output = CryptoParameters;

    fn add(self, rhs: R) -> Self::Output {
        add_inner(self, rhs)
    }
}

impl<R: AlgorithmsExt> Add<R> for SigAlgorithm {
    type Output = CryptoParameters;

    fn add(self, rhs: R) -> Self::Output {
        add_inner(self, rhs)
    }
}

impl<R: AlgorithmsExt> Add<R> for CryptoParameters {
    type Output = CryptoParameters;

    fn add(mut self, rhs: R) -> Self::Output {
        rhs.set_crypto_param(&mut self);
        self
    }
}

impl<T: AlgorithmsExt> From<T> for CryptoParameters {
    fn from(this: T) -> Self {
        let mut ret = CryptoParameters::default();
        this.set_crypto_param(&mut ret);
        ret
    }
}

/// Provides the enumeration for all security levels
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Default)]
pub enum SecurityLevel {
    #[default]
    Standard,
    Reinforced,
    High,
    Ultra,
    Extreme,
    Custom(u8),
}

impl From<u8> for SecurityLevel {
    fn from(val: u8) -> Self {
        match val {
            0 => SecurityLevel::Standard,
            1 => SecurityLevel::Reinforced,
            2 => SecurityLevel::High,
            3 => SecurityLevel::Ultra,
            4 => SecurityLevel::Extreme,
            n => SecurityLevel::Custom(n),
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Default)]
pub enum HeaderObfuscatorSettings {
    /// Enables header obfuscation to help mitigate some deep packet inspection techniques using a pseudorandom key
    Enabled,
    #[default]
    /// Disables header obfuscation (default)
    Disabled,
    /// Enables header obfuscation with a specific key. This value must be symmetric between both endpoints, otherwise the obfuscation will fail
    EnabledWithKey(u128),
}

impl From<u128> for HeaderObfuscatorSettings {
    fn from(val: u128) -> Self {
        HeaderObfuscatorSettings::EnabledWithKey(val)
    }
}

impl From<bool> for HeaderObfuscatorSettings {
    fn from(value: bool) -> Self {
        if value {
            HeaderObfuscatorSettings::Enabled
        } else {
            HeaderObfuscatorSettings::Disabled
        }
    }
}

impl From<Uuid> for HeaderObfuscatorSettings {
    fn from(value: Uuid) -> Self {
        HeaderObfuscatorSettings::EnabledWithKey(value.as_u128())
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::SecBuffer;

    #[test]
    fn test_secbuffer_cmp_same() {
        let a = SecBuffer::from("Hello");
        let b = SecBuffer::from("Hello");
        assert_eq!(a, b);
    }

    #[test]
    fn test_secbuffer_cmp_diff() {
        let a = SecBuffer::from("Hello");
        let b = SecBuffer::from("World");
        assert_ne!(a, b);
    }

    #[test]
    fn test_secbuffer_cmp_diff2() {
        let a = SecBuffer::from("Hello");
        let b = SecBuffer::from("World................");
        assert_ne!(a, b);
    }

    #[test]
    fn test_secbuffer_cmp_diff3() {
        let a = SecBuffer::from("Hello................");
        let b = SecBuffer::from("World");
        assert_ne!(a, b);
    }
}
