use std::marker::PhantomData;
use std::time::Instant;

use byteorder::NetworkEndian;
use bytes::ByteOrder;
use futures::{Async, Future, task, FutureExt};
use num::ToPrimitive;

use hyxe_crypt::drill_impls::DrillType;

use crate::connection::stream_wrappers::old::RawInboundItem;
use crate::packet::data_reconstructor::DataReconstructor;
use crate::prelude::misc::ConnectError;
use futures::task::Task;
use hyxe_netdata::packet::{PACKET_HEADER_BYTE_COUNT, StageDriverPacket, PacketStage};
use std::pin::Pin;
use crate::packet::inbound::expectancy::{Expectancy, ExpectancyResponse};
use hyxe_crypt::prelude::Drill;
use async_std::task::Waker;
use tokio_threadpool::ThreadPool;
use std::future::get_task_context;
use std::mem::MaybeUninit;

/// This is to limit the size of data allocated on the heap. Since the MAX_PACKET_SIZE
/// is 555 (as of 9/16/2019), then a wave can consume at most 10000 * 555 bytes in memory,
/// or 5.55 megabytes of memory. If your server is expected to handle larger transfers at once,
/// then a custom file-transfer program will have to be created that splits the data into multiple
/// 2D waveforms, and creates an expectancy for each one; finally, it must re-piece all the data
/// together. However, this is beyond the scope of the base program, and is left in the hands of
/// higher-level API developers to create.
pub const MAX_PACKETS_PER_OBJECT: usize = 10000;

/// This is to provide context for the stage 2 driver. It will drop the expectancy from memory if
/// the state is Delete
#[derive(PartialEq)]
pub enum ExpectancyStatus {
    /// The expectancy has been fulfilled and can now be sent to the API layer
    Fulfilled,
    /// The expectancy has yet to be completed
    Unfulfilled,
    /// The packet has been fully received and reconstructed, and has no expecting local downstream .await waypoints;
    /// thus, puch back into stage 2 of the [StageDriver]
    BackToStageDriver,
    /// This is similar to fulfilled, except the packet is meant to be forwarded next. This lets the
    /// stage driver
    ReconstructedNeedsForward,
    /// This signals the stage 2 driver to drop the ObjectExpectancy from memory
    NeedsDelete,
}

/// An expectation for an inbound wave or packet to arrive. This is periodically poll
#[repr(C)]
pub struct ObjectExpectancy<'stage2, 'driver: 'stage2> {
    /// The Expectancy ID / Object ID
    pub eid_oid: u64,
    timeout_ms: u64,
    creation_time: Instant,
    task: Option<Task>,
    /// If a callback was generated, this will be triggered once the future of Self completes
    expectancy_response_task: Option<Task>,
    expectancy_response_ptr: MaybeUninit<*mut ExpectancyResponse>,
    /// This additional field was a trade-off for having a Vector of vectors under waveform below. Since the inbound HEADER packet
    /// comes with a comma-separated array of values, we can add each to an array. However, for performance reasons, the index
    /// is placed instead of the packets per layer to have O(1) lookups
    wave_start_indexes: Vec<usize>,
    /// When a [WAVE_HEADER] packet arrives, its wid and pid components inversely map to the number of waves and
    /// the total number of expected packets. This allows us to allocate the total number of vectors needed beforehand.
    waveform2d_reconstructor: DataReconstructor,
    /// The status of the system.
    status: ExpectancyStatus,
    _phantom: PhantomData<&'stage2 Self>,
}

impl<'stage2, 'driver: 'stage2> ObjectExpectancy<'stage2, 'driver> {
    /// Creates a new expectancy meant for a wave of packets. This is called only when a OBJECT_HEADER approaches.
    /// `object_header`: This is the header type which describes the structure of the future inbound waveform.
    pub fn new<Drx: DrillType>(packet: RawInboundItem, drill: &Drill<Drx>, timeout_ms: u64) -> Option<Self> {
        let object_header = packet.get_header();
        let eid_oid = object_header.oid_eid.get();
        let pid_inverse = drill.get_pid_inverse(object_header.pid.get().to_f64()?);
        let wid_inverse = drill.get_wid_inverse(object_header.wid.get().to_f64()?);

        let payload = packet.get_payload();
        // there should be at least one u64 big endian value (total bytes in object) as well as one u16 big endian value
        if payload.len() < std::mem::size_of::<u64>() + std::mem::size_of::<u16>() {
            return None;
        }

        let (object_len_bytes, packets_per_wave_bytes) = payload.split_at(std::mem::size_of::<u64>());

        if packets_per_wave_bytes.len() % std::mem::size_of::<u16>() != 0 {
            return None;
        }

        let length = NetworkEndian::read_u64(object_len_bytes);

        let mut running_total = 0;

        let wave_start_indexes = packets_per_wave_bytes.chunks(std::mem::size_of::<u16>()).filter_map(|bytes_chunk| {
            if bytes_chunk.len() == std::mem::size_of::<u16>() {
                let additional = NetworkEndian::read_u16(bytes_chunk) as usize;
                let ret = additional + running_total;
                running_total += additional;
                Some(ret)
            } else {
                None
            }
        }).collect::<Vec<usize>>();

        if pid_inverse > MAX_PACKETS_PER_OBJECT || wid_inverse == 0 || packets_per_wave.len() != wid_inverse {
            None
        } else {
            Some(Self { eid_oid, timeout_ms, creation_time: Instant::now(), task: None, expectancy_response_task: None, expectancy_response_ptr: MaybeUninit::uninit(), wave_start_indexes, waveform2d_reconstructor:DataReconstructor::new(packet, PACKET_HEADER_BYTE_COUNT, length as usize), status: ExpectancyStatus::Unfulfilled, _phantom: Default::default() })
        }
    }

    /// Delivers a packet within. Automatically places the packet where it must belong in the array
    pub fn deliver_packet(&mut self, packet: &'driver mut RawInboundItem) -> Result<bool, ConnectError> {
        let pid = packet.get_header().pid.get();
        let wid = packet.get_header().wid.get();
        let idx = self.wave_start_indexes.get(wid as usize).unwrap_or(&7777777777777) + pid as usize;

        if idx >= 7777777777777 {
            Err(ConnectError::OutOfBoundsError)
        } else {
            match self.waveform2d_reconstructor.add_data(idx, packet.get_payload()) {
                Ok(true) => {
                    self.status = ExpectancyStatus::Fulfilled;
                    Ok(true)
                },

                Ok(false) => {
                    Ok(false)
                },

                Err(err) => {
                    Err(ConnectError::Generic("Error reconstructing data".to_string()))
                }
            }
        }
    }

    /// Wakes the async task, allowing the poll to continue
    pub fn notify(&self) {
        if let Some(task) = &self.task {
            task.notify()
        }
    }

    /// This can ONLY be called once the future of self is complete
    fn get_packet_ptr(&self) -> StageDriverPacket {
        self.waveform2d_reconstructor.get_packet_ptr()
    }

    fn run_callback_if_exists(&mut self, packet: Option<StageDriverPacket>) -> bool {
        if let Some(task) = self.expectancy_response_task.as_ref() {
            unsafe { self.expectancy_response_ptr.assume_init().as_mut().unwrap().notify(packet) };
            true
        } else {
            false
        }
    }
}

impl<'stage2, 'driver: 'stage2> Future for ObjectExpectancy<'stage2, 'driver> {
    type Item = Option<StageDriverPacket>;
    type Error = ConnectError;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        if self.task.is_none() {
            self.task = Some(task::current());
        }

        if (self.creation_time.elapsed().as_millis() >= self.timeout_ms as u128) && self.timeout_ms != 0 {
            self.status = ExpectancyStatus::NeedsDelete;
            self.run_callback_if_exists(None);
            Err(ConnectError::Timeout)
        } else {
            if self.waveform2d_reconstructor.is_finished() {
                let packet = self.get_packet_ptr();
                if self.run_callback_if_exists(Some(packet)) {
                    // Here, we end up bypassing all further stages and send the packet directly to whoever
                    // was expecting the packet
                    Ok(Async::Ready(None))
                } else {
                    // If there is no callback, that implies this packet will be re-injected into the [StageDriver],
                    // where it will later makes its way to the owner of the inbound_rx/[StageDriver] output
                    self.status = ExpectancyStatus::BackToStageDriver;
                    Ok(Async::Ready(Some(packet.clone())))
                }
            } else {
                Ok(Async::NotReady)
            }
        }
    }
}

impl Expectancy for ObjectExpectancy {
    fn generate_callback(&mut self) -> Pin<Box<ExpectancyResponse>> {
        let mut exp_response = ExpectancyResponse::new();
        exp_response.poll().unwrap(); // We poll the expectancy, and in doing so, it sets its internal task. This should not fail on first-poll, as all it does is set the internal task
        self.expectancy_response_task = unsafe { Some(exp_response.get_task()) }; // we set the task for this ObjectExpectancy
        let _ = self.expectancy_response_ptr.write(&mut *exp_response as *mut ExpectancyResponse); // We then write a pointer to a heap-pinned ExpectancyResponse
        exp_response // We return the Heap-pinned wrapper to the ExpectancyResponse with certainty that the pointer we wrote will still be valid and not dangling
    }

    fn get_packet(&mut self) -> Option<StageDriverPacket> {
        if self.waveform2d_reconstructor.is_finished() {
            Some(self.get_packet_ptr())
        } else {
            None
        }
    }

    unsafe fn get_packet_unchecked(&mut self) -> StageDriverPacket {
        self.get_packet_ptr()
    }

    fn is_fulfilled(&self) -> bool {
        self.waveform2d_reconstructor.is_finished()
    }

    fn needs_delete(&self) -> bool {
        if self.status == ExpectancyStatus::NeedsDelete {
            return true
        } else {
            // The expectancy doesn't need to be deleted, but what if the packet is flagged for
            // deletion?

            // Check to see if the packet needs deleting, as it may be flagged for deletion
            // while being passed around as a [StageDriverPacket]
            if self.waveform2d_reconstructor.is_finished() {
                if self.get_packet_ptr().stage == PacketStage::NeedsDelete {
                    return true;
                }
            }
        }

        false
    }
}