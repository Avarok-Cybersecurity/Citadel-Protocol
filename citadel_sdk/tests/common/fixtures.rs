//! Download-and-cache helper for the public media fixtures used by the media integration tests.
//!
//! Fixtures are fetched once into a cache directory and verified by pinned SHA-256 on every use.
//! A hash mismatch is an error (never a silent re-download). With `CITADEL_OFFLINE=1` an absent
//! fixture is reported loudly and the test is expected to return early.
#![allow(dead_code)]

use std::fmt;
use std::io::Read;
use std::path::PathBuf;

pub const FIXTURE_DIR_ENV: &str = "CITADEL_MEDIA_FIXTURE_DIR";
pub const OFFLINE_ENV: &str = "CITADEL_OFFLINE";
const MAX_FIXTURE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixture {
    /// 3 s, PCM16 stereo 44.1 kHz (563,756 B).
    Wav,
    /// libvpx test vector: 352x288 VP8, 13 frames, ~6.6 KB each (86,405 B).
    Vp8Ivf,
}

impl Fixture {
    pub const fn url(self) -> &'static str {
        match self {
            Fixture::Wav => "https://download.samplelib.com/wav/sample-3s.wav",
            Fixture::Vp8Ivf => "https://storage.googleapis.com/downloads.webmproject.org/test_data/libvpx/vp80-05-sharpness-1428.ivf",
        }
    }

    pub const fn file_name(self) -> &'static str {
        match self {
            Fixture::Wav => "sample-3s.wav",
            Fixture::Vp8Ivf => "vp80-05-sharpness-1428.ivf",
        }
    }

    pub const fn sha256(self) -> &'static str {
        match self {
            Fixture::Wav => "b3726eac5c9612ea20e245314812575bf9df5fb6b8024b80c7cfe9033452bb2b",
            Fixture::Vp8Ivf => "be11270301ff4ccfcf86c48939606b6c726352860d7dd799b1cca15a97c8e724",
        }
    }
}

#[derive(Debug)]
pub enum FixtureError {
    Io(std::io::Error),
    Http(String),
    Sha256Mismatch {
        fixture: Fixture,
        expected: &'static str,
        actual: String,
    },
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixtureError::Io(err) => write!(f, "fixture io error: {err}"),
            FixtureError::Http(err) => write!(f, "fixture download failed: {err}"),
            FixtureError::Sha256Mismatch {
                fixture,
                expected,
                actual,
            } => write!(
                f,
                "fixture {fixture:?} sha256 mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for FixtureError {}

impl From<std::io::Error> for FixtureError {
    fn from(err: std::io::Error) -> Self {
        FixtureError::Io(err)
    }
}

/// `CITADEL_MEDIA_FIXTURE_DIR`, else `<workspace>/target/media_fixtures`.
pub fn fixture_dir() -> PathBuf {
    match std::env::var_os(FIXTURE_DIR_ENV) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("media_fixtures"),
    }
}

fn offline() -> bool {
    std::env::var(OFFLINE_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Returns the verified local path, or `Ok(None)` only when offline and not cached.
pub fn ensure(fixture: Fixture) -> Result<Option<PathBuf>, FixtureError> {
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(fixture.file_name());

    if path.exists() {
        verify(fixture, &path)?;
        return Ok(Some(path));
    }
    if offline() {
        eprintln!(
            "SKIPPING: fixture {:?} absent at {} and {OFFLINE_ENV}=1",
            fixture,
            path.display()
        );
        return Ok(None);
    }

    let bytes = download(fixture.url())?;
    let part = dir.join(format!("{}.part", fixture.file_name()));
    std::fs::write(&part, &bytes)?;
    if let Err(err) = verify(fixture, &part) {
        let _ = std::fs::remove_file(&part);
        return Err(err);
    }
    std::fs::rename(&part, &path)?;
    Ok(Some(path))
}

/// Convenience for tests: the verified bytes, or `None` when offline and not cached.
pub fn ensure_bytes(fixture: Fixture) -> Result<Option<Vec<u8>>, FixtureError> {
    match ensure(fixture)? {
        Some(path) => Ok(Some(std::fs::read(path)?)),
        None => Ok(None),
    }
}

fn download(url: &str) -> Result<Vec<u8>, FixtureError> {
    let response = ureq::get(url)
        .call()
        .map_err(|err| FixtureError::Http(err.to_string()))?;
    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(MAX_FIXTURE_BYTES)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn verify(fixture: Fixture, path: &std::path::Path) -> Result<(), FixtureError> {
    let actual = sha256::digest(std::fs::read(path)?);
    if actual == fixture.sha256() {
        Ok(())
    } else {
        Err(FixtureError::Sha256Mismatch {
            fixture,
            expected: fixture.sha256(),
            actual,
        })
    }
}
