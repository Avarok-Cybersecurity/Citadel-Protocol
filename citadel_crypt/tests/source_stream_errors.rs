//! A transfer whose source fails to read part-way ends with that error on the group channel, so
//! the sender never reports a truncated transfer as complete.
#![cfg(not(target_family = "wasm"))]

use bytes::BufMut;
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::misc::CryptError;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::scramble::streaming_crypt_scrambler::{
    scramble_encrypt_source, FixedSizedSource, ObjectSource,
};
use citadel_crypt::scramble::wave_binding::WaveBinding;
use citadel_io::tokio;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
use citadel_types::proto::{ObjectId, TransferType};
use std::io::Read;
use std::time::Duration;

type R = StackedRatchet;
const PSKS: &[&[u8]] = &[b"psk"];
const HDR: usize = 44;
const GROUP: usize = 16 * 1024;

fn pair() -> (R, R) {
    let opts = ConstructorOpts::new_vec_init(
        EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem768Fips203,
        SecurityLevel::Standard,
    );
    let mut a = <R as Ratchet>::Constructor::new_alice(opts.clone(), 99, 0).unwrap();
    let mut b =
        <R as Ratchet>::Constructor::new_bob(99, opts, a.stage0_alice().unwrap(), PSKS).unwrap();
    a.stage1_alice(b.stage0_bob().unwrap(), PSKS).unwrap();
    (a.finish().unwrap(), b.finish().unwrap())
}

/// Declares three groups' worth of bytes; yields the first `readable` of them, then fails (or
/// reaches its end early).
struct Failing {
    readable: usize,
    fail: bool,
}

struct FailingReader {
    remaining: usize,
    fail: bool,
}

impl Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return if self.fail {
                Err(std::io::Error::other("the source became unreadable"))
            } else {
                Ok(0)
            };
        }
        let n = buf.len().min(self.remaining);
        buf[..n].fill(7);
        self.remaining -= n;
        Ok(n)
    }
}

impl FixedSizedSource for FailingReader {
    fn length(&self) -> std::io::Result<u64> {
        Ok(3 * GROUP as u64)
    }
}

impl ObjectSource for Failing {
    fn try_get_stream(&mut self) -> Result<Box<dyn FixedSizedSource>, CryptError> {
        Ok(Box::new(FailingReader {
            remaining: self.readable,
            fail: self.fail,
        }))
    }
    fn get_source_name(&self) -> Result<String, CryptError> {
        Ok("failing.bin".to_string())
    }
    fn path(&self) -> Option<std::path::PathBuf> {
        None
    }
}

/// Runs the transfer and returns (groups delivered, whether the channel then carried an error).
async fn run(source: Failing) -> (usize, bool) {
    let (alice, bob) = pair();
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    scramble_encrypt_source::<_, _, HDR, _>(
        source,
        Some(GROUP),
        ObjectId::zero(),
        tx,
        stop_rx,
        SecurityLevel::Standard,
        alice,
        None,
        HDR,
        bob.get_cid(),
        0,
        TransferType::FileTransfer,
        WaveBinding::Bound,
        |_v, _b, _o, _c, buf: &mut bytes::BytesMut| {
            for x in 0..HDR {
                buf.put_u8(x as u8)
            }
        },
    )
    .unwrap();
    let mut groups = 0;
    loop {
        match tokio::time::timeout(Duration::from_secs(60), rx.recv())
            .await
            .expect("the transfer neither finished nor failed")
        {
            Some(Ok(_)) => groups += 1,
            Some(Err(_)) => return (groups, true),
            None => return (groups, false),
        }
    }
}

#[tokio::test]
async fn a_source_that_reads_fully_delivers_every_group() {
    assert_eq!(
        run(Failing {
            readable: 3 * GROUP,
            fail: true
        })
        .await,
        (3, false)
    );
}

#[tokio::test]
async fn a_source_that_fails_part_way_ends_the_transfer_with_an_error() {
    assert_eq!(
        run(Failing {
            readable: GROUP,
            fail: true
        })
        .await,
        (1, true)
    );
}

#[tokio::test]
async fn a_source_that_ends_early_ends_the_transfer_with_an_error() {
    assert_eq!(
        run(Failing {
            readable: GROUP + 10,
            fail: false
        })
        .await,
        (1, true)
    );
}
