use crate::entropy_bank::PORT_RANGE;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use std::fmt::{Display, Formatter};

/// Default Error type for this crate
pub enum CryptError<T = String> {
    /// Encrypt Error
    Encrypt(T),
    /// Decrypt Error
    Decrypt(T),
    /// Drill update error
    DrillUpdateError(T),
    /// Out of bounds
    OutOfBoundsError,
    /// This occurs if the byte-valued security level desired does not correspond to an actual [SecurityLevel]
    BadSecuritySetting,
}

impl<T> CryptError<T> {
    /// Use for converting to different types
    pub fn into_string(self) -> String
    where
        T: Into<String>,
    {
        match self {
            CryptError::Encrypt(s) => s.into(),
            CryptError::Decrypt(s) => s.into(),
            CryptError::DrillUpdateError(s) => s.into(),
            CryptError::OutOfBoundsError => "[CryptError] Out of bounds exception".to_string(),
            CryptError::BadSecuritySetting => "[CryptError] Bad security setting".to_string(),
        }
    }

    pub fn as_str(&self) -> &str
    where
        T: AsRef<str>,
    {
        match self {
            CryptError::Encrypt(s) => s.as_ref(),
            CryptError::Decrypt(s) => s.as_ref(),
            CryptError::DrillUpdateError(s) => s.as_ref(),
            CryptError::OutOfBoundsError => "[CryptError] Out of bounds exception",
            CryptError::BadSecuritySetting => "[CryptError] Bad security setting",
        }
    }
}

impl<T: AsRef<str>> std::fmt::Debug for CryptError<T> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.as_str())
    }
}

impl<T: AsRef<str>> Display for CryptError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Creates a port pair mapping at random
pub fn create_port_mapping() -> Vec<(u16, u16)> {
    let mut input_ports = Vec::with_capacity(PORT_RANGE);
    let mut output_ports = Vec::with_capacity(PORT_RANGE);

    for i in 0..PORT_RANGE {
        input_ports.push(i);
        output_ports.push(i);
    }

    let mut rng = thread_rng();
    input_ports.as_mut_slice().shuffle(&mut rng);
    output_ports.as_mut_slice().shuffle(&mut rng);

    let mut output_vec = Vec::with_capacity(PORT_RANGE);
    for i in 0..PORT_RANGE {
        output_vec.push((input_ports[i] as u16, output_ports[i] as u16));
    }

    output_vec
}
