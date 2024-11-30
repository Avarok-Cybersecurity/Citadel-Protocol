//! # Streaming Cryptographic Scrambler
//!
//! This module provides asynchronous streaming encryption and scrambling capabilities for large data sources.
//! It enables secure transmission of data streams by breaking them into encrypted groups and managing their
//! transmission with backpressure support.
//!
//! ## Features
//! - Asynchronous streaming encryption of large data sources
//! - Support for file-based and in-memory data sources
//! - Configurable group sizes for optimal performance
//! - Backpressure support through async/await
//! - Custom header inscription for packets
//! - Progress tracking and cancellation support
//!
//! ## Usage Example
//! ```rust
//! use citadel_crypt::{
//!     streaming_crypt_scrambler::{scramble_encrypt_source, BytesSource},
//!     SecurityLevel, ObjectId, TransferType
//! };
//! use tokio::sync::mpsc;
//! use tokio::sync::oneshot;
//!
//! async fn encrypt_stream() {
//!     // Create channels for group sending and stopping
//!     let (group_sender, mut group_receiver) = mpsc::channel(10);
//!     let (stop_sender, stop_receiver) = oneshot::channel();
//!     
//!     // Create a source (e.g., from bytes)
//!     let data = vec![0u8; 1024];
//!     let source = BytesSource::from(data);
//!     
//!     // Header inscriber function
//!     let header_inscriber = |vector: &PacketVector,
//!                            bank: &EntropyBank,
//!                            obj_id: ObjectId,
//!                            cid: u64,
//!                            bytes: &mut BytesMut| {
//!         // Inscribe header data
//!     };
//!     
//!     // Start encryption
//!     let result = scramble_encrypt_source(
//!         source,
//!         None, // Use default group size
//!         ObjectId::new(),
//!         group_sender,
//!         stop_receiver,
//!         SecurityLevel::Standard,
//!         hyper_ratchet,
//!         static_aux_ratchet,
//!         header_size,
//!         target_cid,
//!         group_id,
//!         TransferType::Standard,
//!         header_inscriber,
//!     ).await;
//! }
//! ```
//!
//! ## Important Notes
//! - Maximum group size is limited to prevent excessive memory usage
//! - Sources are consumed during streaming and cannot be reused
//! - Implements efficient buffering for optimal performance
//! - Supports both filesystem and in-memory sources
//!
//! ## Related Components
//! - [`crypt_splitter`](crate::scramble::crypt_splitter): Core encryption and packet splitting
//! - [`EntropyBank`](crate::entropy_bank::EntropyBank): Cryptographic entropy source
//! - [`PacketVector`](crate::packet_vector::PacketVector): Packet orientation management
//! - [`StackedRatchet`](crate::stacked_ratchet::StackedRatchet): Key management

use bytes::BytesMut;
use citadel_io::tokio;
use futures::task::Context;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::pin::Pin;
use tokio::sync::mpsc::Sender as GroupChanneler;
use tokio::sync::oneshot::Receiver;

use crate::entropy_bank::EntropyBank;
use crate::packet_vector::PacketVector;
use crate::scramble::crypt_splitter::{par_scramble_encrypt_group, GroupSenderDevice};

use crate::misc::CryptError;
use crate::stacked_ratchet::StackedRatchet;
use citadel_io::tokio_stream::{Stream, StreamExt};
use citadel_io::Mutex;
use citadel_types::crypto::SecurityLevel;
use citadel_types::prelude::ObjectId;
use citadel_types::proto::TransferType;
use futures::Future;
use num_integer::Integer;
use std::sync::Arc;
use std::task::Poll;
use tokio::task::{JoinError, JoinHandle};
use zeroize::Zeroizing;

/// 3Mb per group
pub const MAX_BYTES_PER_GROUP: usize = crate::scramble::crypt_splitter::MAX_BYTES_PER_GROUP;
const DEFAULT_BYTES_PER_GROUP: usize = 1024 * 1024 * 3;

/// Used for streaming sources of a fixed size
pub trait FixedSizedSource: Read + Send + 'static {
    fn length(&self) -> std::io::Result<u64>;
}

#[cfg(feature = "filesystem")]
impl FixedSizedSource for std::fs::File {
    fn length(&self) -> std::io::Result<u64> {
        self.metadata().map(|r| r.len())
    }
}

/// Generic function for inscribing headers on packets
pub trait HeaderInscriberFn:
    for<'a> Fn(&'a PacketVector, &'a EntropyBank, ObjectId, u64, &'a mut BytesMut)
    + Send
    + Sync
    + 'static
{
}
impl<
        T: for<'a> Fn(&'a PacketVector, &'a EntropyBank, ObjectId, u64, &'a mut BytesMut)
            + Send
            + Sync
            + 'static,
    > HeaderInscriberFn for T
{
}

#[auto_impl::auto_impl(Box)]
pub trait ObjectSource: Send + Sync + 'static {
    fn try_get_stream(&mut self) -> Result<Box<dyn FixedSizedSource>, CryptError>;
    fn get_source_name(&self) -> Result<String, CryptError>;
    fn path(&self) -> Option<PathBuf>;
}

macro_rules! impl_file_src {
    ($value:ty) => {
        #[cfg(feature = "filesystem")]
        impl ObjectSource for $value {
            fn try_get_stream(&mut self) -> Result<Box<dyn FixedSizedSource>, CryptError> {
                std::fs::File::open(self)
                    .map_err(|err| CryptError::Encrypt(err.to_string()))
                    .map(|r| Box::new(r) as Box<dyn FixedSizedSource>)
            }

            fn get_source_name(&self) -> Result<String, CryptError> {
                let name = std::path::Path::new(self);
                name.file_name()
                    .ok_or_else(|| CryptError::Encrypt("Unable to get filename".to_string()))?
                    .to_str()
                    .map(|r| r.to_string())
                    .ok_or_else(|| CryptError::Encrypt("Unable to get filename/2".to_string()))
            }

            fn path(&self) -> Option<PathBuf> {
                let path = std::path::PathBuf::from(self);
                Some(path)
            }
        }
    };
}

impl_file_src!(PathBuf);
impl_file_src!(&'static str);
impl_file_src!(String);

pub struct BytesSource {
    pub inner: Option<Zeroizing<Vec<u8>>>,
}

// The only time this is cloned is for a post-file-transfer hook,
// wherein the delete() function is called. As such, we don't need
// the inner device
impl Clone for BytesSource {
    fn clone(&self) -> Self {
        Self { inner: None }
    }
}

impl ObjectSource for BytesSource {
    fn try_get_stream(&mut self) -> Result<Box<dyn FixedSizedSource>, CryptError> {
        struct VecReader {
            len: usize,
            cursor: std::io::Cursor<Zeroizing<Vec<u8>>>,
        }

        impl std::io::Read for VecReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.cursor.read(buf)
            }
        }

        impl FixedSizedSource for VecReader {
            fn length(&self) -> std::io::Result<u64> {
                Ok(self.len as u64)
            }
        }

        let inner = self
            .inner
            .take()
            .ok_or_else(|| CryptError::Encrypt("Source has already been exhausted".into()))?;
        let len = inner.len();
        let cursor = std::io::Cursor::new(inner);
        Ok(Box::new(VecReader { len, cursor }))
    }

    fn get_source_name(&self) -> Result<String, CryptError> {
        let rand_id = rand::random::<u128>();
        Ok(format!("{rand_id}.bin"))
    }

    fn path(&self) -> Option<PathBuf> {
        None
    }
}

impl<T: Into<Vec<u8>>> From<T> for BytesSource {
    fn from(value: T) -> Self {
        Self {
            inner: Some(value.into().into()),
        }
    }
}

/// As the networking protocol receives ACKs from the packets it gets from the sender, it should call the waker that this function sends through `waker_sender` once
/// it is close to finishing the group (depending on speed).
///
/// `stop`: Should be called when all groups are done transmitting
///
/// `header_inscriber`: the feed order for u64's is first the target_cid, and then the object-ID
///
/// This is ran on a separate thread on the threadpool. Returns the number of bytes and number of groups
#[allow(clippy::too_many_arguments)]
pub fn scramble_encrypt_source<S: ObjectSource, F: HeaderInscriberFn, const N: usize>(
    mut source: S,
    max_group_size: Option<usize>,
    object_id: ObjectId,
    group_sender: GroupChanneler<Result<GroupSenderDevice<N>, CryptError>>,
    stop: Receiver<()>,
    security_level: SecurityLevel,
    hyper_ratchet: StackedRatchet,
    static_aux_ratchet: StackedRatchet,
    header_size_bytes: usize,
    target_cid: u64,
    group_id: u64,
    transfer_type: TransferType,
    header_inscriber: F,
) -> Result<(usize, usize, usize), CryptError> {
    let path = source.path();
    let source = source.try_get_stream()?;
    let object_len = source
        .length()
        .map_err(|err| CryptError::Encrypt(err.to_string()))? as usize;
    log::trace!(target: "citadel", "Object length: {} | Path: {:?}", object_len, path);
    let max_bytes_per_group = max_group_size.unwrap_or(DEFAULT_BYTES_PER_GROUP);

    if max_bytes_per_group > MAX_BYTES_PER_GROUP {
        return Err(CryptError::Encrypt(format!(
            "Maximum group size cannot be larger than {MAX_BYTES_PER_GROUP} bytes",
        )));
    }

    let total_groups = Integer::div_ceil(&object_len, &max_bytes_per_group);

    log::trace!(target: "citadel", "Will parallel_scramble_encrypt file object {}, which is {} bytes or {} MB. {} groups total", object_id, object_len, (object_len as f32)/(1024f32*1024f32), total_groups);
    let reader = BufReader::with_capacity(std::cmp::min(object_len, max_bytes_per_group), source);

    let buffer = Arc::new(Mutex::new(vec![
        0u8;
        std::cmp::min(
            object_len,
            max_bytes_per_group
        )
    ]));
    let file_scrambler = AsyncCryptScrambler {
        total_groups,
        buffer,
        groups_rendered: 0,
        object_id,
        header_size_bytes,
        target_cid,
        group_id,
        security_level,
        hyper_ratchet,
        static_aux_ratchet,
        reader,
        transfer_type,
        file_len: object_len,
        max_bytes_per_group,
        read_cursor: 0,
        header_inscriber: Arc::new(header_inscriber),
        poll_amt: 0,
        cur_task: None,
    };

    let handle = tokio::task::spawn(async move {
        let res = citadel_io::tokio::select! {
            res0 = stopper(stop) => res0,
            res1 = file_streamer(group_sender.clone(), file_scrambler) => res1
        };

        if let Err(err) = res {
            let _ = group_sender.try_send(Err(err));
        }
    });

    // drop the handle, we will not be using it
    drop(handle);

    Ok((object_len, total_groups, max_bytes_per_group))
}

async fn stopper(stop: Receiver<()>) -> Result<(), CryptError> {
    stop.await
        .map_err(|err| CryptError::Encrypt(err.to_string()))
}

async fn file_streamer<F: HeaderInscriberFn, R: Read, const N: usize>(
    group_sender: GroupChanneler<Result<GroupSenderDevice<N>, CryptError>>,
    mut file_scrambler: AsyncCryptScrambler<F, R, N>,
) -> Result<(), CryptError> {
    while let Some(val) = file_scrambler.next().await {
        group_sender
            .send(Ok(val))
            .await
            .map_err(|err| CryptError::Encrypt(err.to_string()))?;
    }

    Ok(())
}

#[allow(dead_code)]
struct AsyncCryptScrambler<F: HeaderInscriberFn, R: Read, const N: usize> {
    reader: BufReader<R>,
    hyper_ratchet: StackedRatchet,
    static_aux_ratchet: StackedRatchet,
    security_level: SecurityLevel,
    transfer_type: TransferType,
    file_len: usize,
    read_cursor: usize,
    object_id: ObjectId,
    header_size_bytes: usize,
    target_cid: u64,
    group_id: u64,
    total_groups: usize,
    groups_rendered: usize,
    max_bytes_per_group: usize,
    poll_amt: usize,
    buffer: Arc<Mutex<Vec<u8>>>,
    header_inscriber: Arc<F>,
    cur_task: Option<JoinHandle<Result<GroupSenderDevice<N>, CryptError<String>>>>,
}

impl<F: HeaderInscriberFn, R: Read, const N: usize> AsyncCryptScrambler<F, R, N> {
    fn poll_task(
        groups_rendered: &mut usize,
        read_cursor: &mut usize,
        poll_amt: usize,
        cur_task: &mut Option<JoinHandle<Result<GroupSenderDevice<N>, CryptError<String>>>>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<GroupSenderDevice<N>>> {
        let res: Result<Result<GroupSenderDevice<N>, CryptError<String>>, JoinError> =
            futures::ready!(Pin::new(cur_task.as_mut().unwrap()).poll(cx));
        if let Ok(Ok(sender)) = res {
            *groups_rendered += 1;
            *read_cursor += poll_amt;
            *cur_task = None;
            Poll::Ready(Some(sender))
        } else {
            log::error!(target: "citadel", "Unable to par_scramble_encrypt group");
            Poll::Ready(None)
        }
    }
}

impl<F: HeaderInscriberFn, R: Read, const N: usize> Unpin for AsyncCryptScrambler<F, R, N> {}

impl<F: HeaderInscriberFn, R: Read, const N: usize> AsyncCryptScrambler<F, R, N> {
    fn poll_scramble_next_group(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<GroupSenderDevice<N>>> {
        let Self {
            hyper_ratchet,
            static_aux_ratchet,
            file_len,
            read_cursor,
            buffer,
            group_id,
            groups_rendered,
            header_size_bytes,
            target_cid,
            object_id,
            header_inscriber,
            reader,
            security_level,
            max_bytes_per_group,
            cur_task,
            transfer_type,
            poll_amt,
            ..
        } = &mut *self;

        if cur_task.is_some() {
            return Self::poll_task(groups_rendered, read_cursor, *poll_amt, cur_task, cx);
        }

        if *read_cursor != *file_len {
            let remaining = *file_len - *read_cursor;
            let poll_len = std::cmp::min(remaining, *max_bytes_per_group);
            let mut lock = buffer.lock();
            let bytes = &mut lock[..poll_len];
            if reader.read_exact(bytes).is_ok() {
                let group_id_input = *group_id + (*groups_rendered as u64);
                drop(lock);
                let header_inscriber = header_inscriber.clone();
                let buffer = buffer.clone();
                let security_level = *security_level;
                let hyper_ratchet = hyper_ratchet.clone();
                let static_aux_ratchet = static_aux_ratchet.clone();
                let header_size_bytes = *header_size_bytes;
                let target_cid = *target_cid;
                let object_id = *object_id;
                let transfer_type = transfer_type.clone();

                let task = tokio::task::spawn_blocking(move || {
                    par_scramble_encrypt_group(
                        &buffer.lock()[..poll_len],
                        security_level,
                        &hyper_ratchet,
                        &static_aux_ratchet,
                        header_size_bytes,
                        target_cid,
                        object_id,
                        group_id_input,
                        transfer_type,
                        |a, b, c, d, e| (header_inscriber)(a, b, c, d, e),
                    )
                });

                *cur_task = Some(task);
                *poll_amt = poll_len;
                Self::poll_task(groups_rendered, read_cursor, *poll_amt, cur_task, cx)
            } else {
                log::error!(target: "citadel", "Error polling exact amt {}", poll_len);
                Poll::Ready(None)
            }
        } else {
            log::trace!(target: "citadel", "Done rendering all groups!");
            Poll::Ready(None)
        }
    }
}

impl<F: HeaderInscriberFn, R: Read, const N: usize> Stream for AsyncCryptScrambler<F, R, N> {
    type Item = GroupSenderDevice<N>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_scramble_next_group(cx)
    }
}
