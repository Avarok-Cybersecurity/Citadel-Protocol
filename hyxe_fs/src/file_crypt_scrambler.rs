use bytes::BytesMut;
use tokio::sync::mpsc::Sender as GroupChanneler;
use tokio::sync::oneshot::Receiver;
use futures::task::Context;
use num::Integer;
use serde::export::PhantomData;
use std::io::{BufReader, Read};
use tokio::macros::support::Pin;

use hyxe_crypt::drill::{Drill, SecurityLevel};
use hyxe_crypt::net::crypt_splitter::{GroupSenderDevice, par_scramble_encrypt_group};
use hyxe_crypt::prelude::PacketVector;

use crate::io::FsError;
use std::task::Poll;
use tokio::stream::{Stream,StreamExt};
use hyxe_crypt::hyper_ratchet::HyperRatchet;

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
pub fn scramble_encrypt_file<F: Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync + 'static>(std_file: std::fs::File, max_group_size: Option<usize>, object_id: u32, group_sender: GroupChanneler<GroupSenderDevice>, stop: Receiver<()>, security_level: SecurityLevel, hyper_ratchet: HyperRatchet, header_size_bytes: usize, target_cid: u64, group_id: u64, header_inscriber: F) -> Result<(usize, usize), FsError<String>> {
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

    let buffer = vec![0u8; std::cmp::min(file_len, max_bytes_per_group)];
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
        header_inscriber,
        _pd: Default::default(),
    };

    tokio::task::spawn(async move {
        futures::future::try_join(stopper(stop), file_streamer(group_sender, file_scrambler)).await
    });

    Ok((file_len, total_groups))
}

#[allow(trivial_bounds)]
async fn stopper(stop: Receiver<()>) -> Result<(), ()> {
    stop.await.map_err(|_| ())?;
    Err(())
}

async fn file_streamer<F: Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync + 'static, R: Read>(mut group_sender: GroupChanneler<GroupSenderDevice>, mut file_scrambler: AsyncCryptScrambler<'_, F, R>) -> Result<(), ()> {
    while let Some(val) = file_scrambler.next().await {
        group_sender.send(val).await.map_err(|_| ())?;
    }

    Err(())
}

#[allow(dead_code)]
struct AsyncCryptScrambler<'a, F: Fn(&'a PacketVector, &'a Drill, u32, u64, &'a mut BytesMut) + Send + Sync + 'static, R: Read> {
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
    buffer: Vec<u8>,
    header_inscriber: F,
    _pd: PhantomData<&'a ()>,
}

impl<'a, F: Fn(&'a PacketVector, &'a Drill, u32, u64, &'a mut BytesMut) + Send + Sync + 'static, R: Read> Unpin for AsyncCryptScrambler<'a, F, R> {}

impl<F: Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync + 'static, R: Read> AsyncCryptScrambler<'_, F, R> {
    fn poll_scramble_next_group(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<GroupSenderDevice>> {
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
            ..
        } = &mut *self;
        if *read_cursor != *file_len {
            let remaining = *file_len - *read_cursor;
            let poll_amt = std::cmp::min(remaining, *max_bytes_per_group);
            let bytes = &mut buffer[..poll_amt];
            if let Ok(_) = reader.read_exact(bytes) {
                let group_id_input = *group_id + (*groups_rendered as u64);
                // let mut compressed = Vec::new();
                // flate3::Compressor::new().deflate(bytes as &[u8])
                // let len = flate2::bufread::DeflateEncoder::new(bytes as &[u8], flate2::Compression::fast()).read_to_end(&mut compressed).unwrap();
                if let Ok(sender) = par_scramble_encrypt_group(bytes, *security_level, hyper_ratchet,  *header_size_bytes, *target_cid, *object_id, group_id_input, |a, b, c, d, e| {
                    (header_inscriber)(a, b, c, d, e)
                }) {
                    *groups_rendered += 1;
                    *read_cursor += poll_amt;
                    Poll::Ready(Some(sender))
                } else {
                    log::error!("Error parallel scrambling file");
                    Poll::Ready(None)
                }
            } else {
                log::error!("Error polling exact amt {}", poll_amt);
                Poll::Ready(None)
            }
        } else {
            log::info!("Done rendering all groups!");
            Poll::Ready(None)
        }
    }
}

impl<F: Fn(&PacketVector, &Drill, u32, u64, &mut BytesMut) + Send + Sync + 'static, R: Read> Stream for AsyncCryptScrambler<'_, F, R> {
    type Item = GroupSenderDevice;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_scramble_next_group(cx)
    }
}