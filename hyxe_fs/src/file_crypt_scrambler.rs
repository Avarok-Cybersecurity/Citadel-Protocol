use bytes::BytesMut;
use tokio::sync::mpsc::Sender as GroupChanneler;
use tokio::sync::oneshot::Receiver;
use futures::task::Context;
use num::Integer;
use std::marker::PhantomData;
use std::io::{BufReader, Read};
use tokio::macros::support::Pin;

use hyxe_crypt::drill::{Drill, SecurityLevel};
use hyxe_crypt::net::crypt_splitter::{GroupSenderDevice, par_scramble_encrypt_group};
use hyxe_crypt::prelude::PacketVector;

use crate::io::FsError;
use std::task::Poll;
use tokio_stream::{Stream,StreamExt};
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use tokio::task::{JoinHandle, JoinError};
use hyxe_crypt::misc::CryptError;
use futures::Future;
use std::sync::Arc;
use parking_lot::Mutex;

/// The max file size is 100Mb (1024 bytes per Kb, 1024 kb per Mb, times 100)
pub const MAX_FILE_SIZE: usize = 1024 * 1024 * 100;
/// 3Mb per group
pub const MAX_BYTES_PER_GROUP: usize = hyxe_crypt::net::crypt_splitter::MAX_BYTES_PER_GROUP;
const DEFAULT_BYTES_PER_GROUP: usize = 1024 * 1024 * 3;

/// As the networking protocol receives ACKs from the packets it gets from the sender, it should call the waker that this function sends through `waker_sender` once
/// it is close to finishing the group (depending on speed).
///
/// `stop`: Should be called when all groups are done transmitting
///
/// `header_inscriber`: the feed order for u64's is first the target_cid, and then the object-ID
///
/// This is ran on a separate thread on the threadpool. Returns the number of bytes and number of groups
#[allow(unused_results)]
pub fn scramble_encrypt_file<F: Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync + 'static, const N: usize>(std_file: std::fs::File, max_group_size: Option<usize>, object_id: u32, group_sender: GroupChanneler<Result<GroupSenderDevice<N>, FsError<String>>>, stop: Receiver<()>, security_level: SecurityLevel, hyper_ratchet: HyperRatchet, header_size_bytes: usize, target_cid: u64, group_id: u64, header_inscriber: F) -> Result<(usize, usize), FsError<String>> {
    let metadata = std_file.metadata().map_err(|err| FsError::IoError(err.to_string()))?;
    let max_bytes_per_group = max_group_size.unwrap_or(DEFAULT_BYTES_PER_GROUP);
    if !metadata.is_file() {
        return Err(FsError::IoError(format!("Supplied entry is not a file")));
    }

    if max_bytes_per_group > MAX_BYTES_PER_GROUP {
        return Err(FsError::Generic(format!("Maximum group size cannot be larger than {} bytes", MAX_BYTES_PER_GROUP)))
    }

    let file_len = metadata.len() as usize;
    let total_groups = file_len.div_ceil(&max_bytes_per_group);

    println!("\n\rWill parallel_scramble_encrypt file object {}, which is {} bytes or {} MB. {} groups total", object_id, file_len, (file_len as f32)/(1024f32*1024f32), total_groups);
    let reader = BufReader::with_capacity(std::cmp::min(file_len, max_bytes_per_group), std_file);

    let buffer = Arc::new(Mutex::new(vec![0u8; std::cmp::min(file_len, max_bytes_per_group)]));
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
        file_len,
        max_bytes_per_group,
        read_cursor: 0,
        header_inscriber: Arc::new(header_inscriber),
        poll_amt: 0,
        cur_task: None,
        _pd: Default::default(),
    };

    tokio::task::spawn(async move {
        let res = tokio::select! {
            res0 = stopper(stop) => res0,
            res1 = file_streamer(group_sender.clone(), file_scrambler) => res1
        };

        if let Err(err) = res {
            let _ = group_sender.try_send(Err(err));
        }
    });

    Ok((file_len, total_groups))
}

async fn stopper(stop: Receiver<()>) -> Result<(), FsError<String>> {
    stop.await.map_err(|err| FsError::Generic(err.to_string()))
}

async fn file_streamer<F: Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync + 'static, R: Read, const N: usize>(group_sender: GroupChanneler<Result<GroupSenderDevice<N>, FsError<String>>>, mut file_scrambler: AsyncCryptScrambler<'_, F, R, N>) -> Result<(), FsError<String>> {
    while let Some(val) = file_scrambler.next().await {
        group_sender.send(Ok(val)).await.map_err(|err| FsError::Generic(err.to_string()))?;
    }

    Ok(())
}

#[allow(dead_code)]
struct AsyncCryptScrambler<'a, F: Fn(&'a PacketVector, &'a Drill, u32, u64, &'a mut BytesMut) + Send + Sync + 'static, R: Read, const N: usize> {
    reader: BufReader<R>,
    hyper_ratchet: HyperRatchet,
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
    cur_task: Option<JoinHandle<Result<GroupSenderDevice<N>, CryptError<String>>>>,
    _pd: PhantomData<&'a ()>,
}

impl<'a, F: Fn(&'a PacketVector, &'a Drill, u32, u64, &'a mut BytesMut) + Send + Sync + 'static, R: Read, const N: usize> AsyncCryptScrambler<'a, F, R, N> {
    fn poll_task(groups_rendered: &mut usize, read_cursor: &mut usize, poll_amt: usize, cur_task: &mut Option<JoinHandle<Result<GroupSenderDevice<N>, CryptError<String>>>>, cx: &mut Context<'_>) -> Poll<Option<GroupSenderDevice<N>>> {
        let res: Result<Result<GroupSenderDevice<N>, CryptError<String>>, JoinError> = futures::ready!(Pin::new(cur_task.as_mut().unwrap()).poll(cx));
        return if let Ok(Ok(sender)) = res {
            *groups_rendered += 1;
            *read_cursor += poll_amt;
            *cur_task = None;
            Poll::Ready(Some(sender))
        } else {
            log::error!("Unable to par_scramble_encrypt group");
            Poll::Ready(None)
        }
    }
}

impl<'a, F: Fn(&'a PacketVector, &'a Drill, u32, u64, &'a mut BytesMut) + Send + Sync + 'static, R: Read, const N: usize> Unpin for AsyncCryptScrambler<'a, F, R, N> {}

impl<F: Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync + 'static, R: Read, const N: usize> AsyncCryptScrambler<'_, F, R, N> {
    fn poll_scramble_next_group(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<GroupSenderDevice<N>>> {
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
            return Self::poll_task(groups_rendered,read_cursor, *poll_amt, cur_task, cx);
        }

        if *read_cursor != *file_len {
            let remaining = *file_len - *read_cursor;
            let poll_len = std::cmp::min(remaining, *max_bytes_per_group);
            let mut lock = buffer.lock();
            let bytes = &mut lock[..poll_len];
            if let Ok(_) = reader.read_exact(bytes) {
                let group_id_input = *group_id + (*groups_rendered as u64);
                // let mut compressed = Vec::new();
                // flate3::Compressor::new().deflate(bytes as &[u8])
                // let len = flate2::bufread::DeflateEncoder::new(bytes as &[u8], flate2::Compression::fast()).read_to_end(&mut compressed).unwrap();
                std::mem::drop(lock);
                let header_inscriber = header_inscriber.clone();
                let buffer = buffer.clone();
                let security_level = *security_level;
                let hyper_ratchet = hyper_ratchet.clone();
                let header_size_bytes = *header_size_bytes;
                let target_cid = *target_cid;
                let object_id = *object_id;

                let task = tokio::task::spawn_blocking(move || {
                    par_scramble_encrypt_group(&buffer.lock()[..poll_len], security_level, &hyper_ratchet,  header_size_bytes, target_cid, object_id, group_id_input, |a, b, c, d, e| {
                        (header_inscriber)(a, b, c, d, e)
                    })
                });

                *cur_task = Some(task);
                *poll_amt = poll_len;
                return Self::poll_task(groups_rendered,read_cursor,*poll_amt, cur_task, cx);
            } else {
                log::error!("Error polling exact amt {}", poll_len);
                Poll::Ready(None)
            }
        } else {
            log::info!("Done rendering all groups!");
            Poll::Ready(None)
        }
    }
}

impl<F: Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync + 'static, R: Read, const N: usize> Stream for AsyncCryptScrambler<'_, F, R, N> {
    type Item = GroupSenderDevice<N>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_scramble_next_group(cx)
    }
}