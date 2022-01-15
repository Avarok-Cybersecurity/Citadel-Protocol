use std::iter;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use chrono::Utc;
use std::path::{Path, PathBuf};
use crate::io::FsError;

/// Generates a random string. Use
pub fn generate_random_string(count: usize) -> String {
    iter::repeat(())
        .map(|()| thread_rng().sample(Alphanumeric))
        .take(count)
        .collect()
}

/// Returns the present timestamp in ISO 8601 format
pub fn get_present_formatted_timestamp() -> String {
    Utc::now().to_rfc3339()
}

/// Returns a PathBuf given a path input
pub fn get_pathbuf<P: AsRef<Path>>(path: P) -> PathBuf {
    PathBuf::from(path.as_ref())
}

impl From<std::io::Error> for FsError<String> {
    fn from(err: std::io::Error) -> Self {
        FsError::IoError(err.to_string())
    }
}