use bytes::BytesMut;
use futures::task::Context;
use std::io::{BufReader, Read};
use tokio::macros::support::Pin;
use tokio::sync::mpsc::Sender as GroupChanneler;
use tokio::sync::oneshot::Receiver;

use crate::entropy_bank::{EntropyBank, SecurityLevel};
use crate::packet_vector::PacketVector;
use crate::scramble::crypt_splitter::{par_scramble_encrypt_group, GroupSenderDevice};

use crate::misc::blocking_spawn::{BlockingSpawn, BlockingSpawnError};
use crate::misc::CryptError;
use crate::stacked_ratchet::StackedRatchet;
use citadel_io::Mutex;
use futures::Future;
use num_integer::Integer;
use std::sync::Arc;
use std::task::Poll;
use tokio_stream::{Stream, StreamExt};

/// 3Mb per group
pub const MAX_BYTES_PER_GROUP: usize = crate::scramble::crypt_splitter::MAX_BYTES_PER_GROUP;
const DEFAULT_BYTES_PER_GROUP: usize = 1024 * 1024 * 3;

/// Used for streaming sources of a fixed size
pub trait FixedSizedStream: Read + Send + 'static {
    fn length(&self) -> std::io::Result<u64>;
}

#[cfg(feature = "filesystem")]
impl FixedSizedStream for std::fs::File {
    fn length(&self) -> std::io::Result<u64> {
        self.metadata().map(|r| r.len())
    }
}

/// Generic function for inscribing headers on packets
pub trait HeaderInscriberFn:
    for<'a> Fn(&'a PacketVector, &'a EntropyBank, u32, u64, &'a mut BytesMut) + Send + Sync + 'static
{
}
impl<
        T: for<'a> Fn(&'a PacketVector, &'a EntropyBank, u32, u64, &'a mut BytesMut)
            + Send
            + Sync
            + 'static,
    > HeaderInscriberFn for T
{
}

#[auto_impl::auto_impl(Box)]
pub trait ObjectSource: Send + Sync + 'static {
    fn try_get_stream(&mut self) -> Result<Box<dyn FixedSizedStream>, CryptError>;
    fn get_source_name(&self) -> Result<String, CryptError>;
}

#[cfg(feature = "filesystem")]
impl ObjectSource for std::path::PathBuf {
    fn try_get_stream(&mut self) -> Result<Box<dyn FixedSizedStream>, CryptError> {
        std::fs::File::open(self)
            .map_err(|err| CryptError::Encrypt(err.to_string()))
            .map(|r| Box::new(r) as Box<dyn FixedSizedStream>)
    }

    fn get_source_name(&self) -> Result<String, CryptError> {
        self.file_name()
            .ok_or_else(|| CryptError::Encrypt("Unable to get filename".to_string()))?
            .to_str()
            .map(|r| r.to_string())
            .ok_or_else(|| CryptError::Encrypt("Unable to get filename/2".to_string()))
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
    object_id: u32,
    group_sender: GroupChanneler<Result<GroupSenderDevice<N>, CryptError>>,
    stop: Receiver<()>,
    security_level: SecurityLevel,
    hyper_ratchet: StackedRatchet,
    header_size_bytes: usize,
    target_cid: u64,
    group_id: u64,
    header_inscriber: F,
) -> Result<(usize, usize), CryptError> {
    let source = source.try_get_stream()?;
    let object_len = source
        .length()
        .map_err(|err| CryptError::Encrypt(err.to_string()))? as usize;
    let max_bytes_per_group = max_group_size.unwrap_or(DEFAULT_BYTES_PER_GROUP);

    if max_bytes_per_group > MAX_BYTES_PER_GROUP {
        return Err(CryptError::Encrypt(format!(
            "Maximum group size cannot be larger than {} bytes",
            MAX_BYTES_PER_GROUP
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
        reader,
        file_len: object_len,
        max_bytes_per_group,
        read_cursor: 0,
        header_inscriber: Arc::new(header_inscriber),
        poll_amt: 0,
        cur_task: None,
    };

    let _ = tokio::task::spawn(async move {
        let res = tokio::select! {
            res0 = stopper(stop) => res0,
            res1 = file_streamer(group_sender.clone(), file_scrambler) => res1
        };

        if let Err(err) = res {
            let _ = group_sender.try_send(Err(err));
        }
    });

    Ok((object_len, total_groups))
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
    security_level: SecurityLevel,
    file_len: usize,
    read_cursor: usize,
    object_id: u32,
    header_size_bytes: usize,
    target_cid: u64,
    group_id: u64,
    total_groups: usize,
    groups_rendered: usize,
    max_bytes_per_group: usize,
    poll_amt: usize,
    buffer: Arc<Mutex<Vec<u8>>>,
    header_inscriber: Arc<F>,
    cur_task: Option<BlockingSpawn<Result<GroupSenderDevice<N>, CryptError<String>>>>,
}

impl<F: HeaderInscriberFn, R: Read, const N: usize> AsyncCryptScrambler<F, R, N> {
    fn poll_task(
        groups_rendered: &mut usize,
        read_cursor: &mut usize,
        poll_amt: usize,
        cur_task: &mut Option<BlockingSpawn<Result<GroupSenderDevice<N>, CryptError<String>>>>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<GroupSenderDevice<N>>> {
        let res: Result<Result<GroupSenderDevice<N>, CryptError<String>>, BlockingSpawnError> =
            futures::ready!(Pin::new(cur_task.as_mut().unwrap()).poll(cx));
        return if let Ok(Ok(sender)) = res {
            *groups_rendered += 1;
            *read_cursor += poll_amt;
            *cur_task = None;
            Poll::Ready(Some(sender))
        } else {
            log::error!(target: "citadel", "Unable to par_scramble_encrypt group");
            Poll::Ready(None)
        };
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
                std::mem::drop(lock);
                // let mut compressed = Vec::new();
                // flate3::Compressor::new().deflate(bytes as &[u8])
                // let len = flate2::bufread::DeflateEncoder::new(bytes as &[u8], flate2::Compression::fast()).read_to_end(&mut compressed).unwrap();
                let header_inscriber = header_inscriber.clone();
                let buffer = buffer.clone();
                let security_level = *security_level;
                let hyper_ratchet = hyper_ratchet.clone();
                let header_size_bytes = *header_size_bytes;
                let target_cid = *target_cid;
                let object_id = *object_id;

                let task = crate::misc::blocking_spawn::spawn_blocking(move || {
                    par_scramble_encrypt_group(
                        &buffer.lock()[..poll_len],
                        security_level,
                        &hyper_ratchet,
                        header_size_bytes,
                        target_cid,
                        object_id,
                        group_id_input,
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
