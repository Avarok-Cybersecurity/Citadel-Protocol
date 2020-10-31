use crate::packet::inbound::stage2::object_expectancy::ExpectancyStatus;
use std::time::Instant;
use crate::connection::stream_wrappers::old::RawInboundItem;
use futures::{Future, Async, task};
use crate::packet::misc::ConnectError;
use futures::task::Task;
use crate::packet::inbound::object_expectancy::ExpectancyStatus;
use std::pin::Pin;
use std::mem::MaybeUninit;
use crate::packet::inbound::expectancy::{Expectancy, ExpectancyResponse};
use hyxe_netdata::packet::{StageDriverPacket, PacketStage};

/// Creates a new expectancy which expects a small response (one packet)
pub struct SingletonExpectancy {
    eid_oid: u64,
    timeout_ms: u64,
    creation_time: Instant,
    task: Option<Task>,
    expectancy_response_task: Option<Task>, // if this exists, then `expectancy_response_ptr` also exists
    expectancy_response_ptr: MaybeUninit<*mut ExpectancyResponse>,
    delivered_packet: Pin<Box<MaybeUninit<RawInboundItem>>>,
    /// The state of the Expectancy
    status: ExpectancyStatus
}

impl SingletonExpectancy {
    /// Creates a new expectancy. This should be placed directly on the stage 2 driver
    ///
    /// `eid_oid`: The object ID expected
    /// `timeout_ms`: The maximum time that the stage driver will wait for the packet. If timeout is `0`, there wont be a timeout
    pub fn new(eid_oid: u64, timeout_ms: u64) -> Self {
        Self { eid_oid, timeout_ms, creation_time: Instant::now(), task: None, expectancy_response_task: None, expectancy_response_ptr: MaybeUninit::uninit(), delivered_packet: unsafe { Pin::new_unchecked(Box::new_uninit()) }, status: ExpectancyStatus::Unfulfilled }
    }

    /// Delivers the packet
    pub fn deliver_packet(&mut self, packet: RawInboundItem) -> Result<(), ConnectError> {
        if self.is_fulfilled() {
            Err(ConnectError::Generic("Packet already exists".to_string()))
        } else {
            self.status == ExpectancyStatus::Fulfilled;
            self.delivered_packet.write(packet);
            Ok(())
        }
    }

    /// Wakes the task, allowing any .await waypoints to continue on
    pub fn notify(&self) {
        if let Some(task) = &self.task {
            task.notify()
        }
    }

    /// This can ONLY be called once the future of self is complete, otherwise UB will happen
    fn get_packet_ptr(&self) -> StageDriverPacket {
        StageDriverPacket::from(&self.delivered_packet)
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

impl Future for SingletonExpectancy {
    type Item = Option<StageDriverPacket>;
    type Error = ConnectError;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        if self.task.is_none() {
            self.task = Some(task::current());
        }

        if (self.creation_time.elapsed().as_millis() >= self.timeout_ms as u128) && self.timeout_ms != 0 {
            self.status = ExpectancyStatus::NeedsDelete; // Allows the [StageDriver] to delete this expectancy once it runs the periodic cleanup
            self.run_callback_if_exists(None);
            Err(ConnectError::Timeout) // Ensures that any .await waypoints are aware that this expectancy timed-out
        } else {
            match self.status {
                ExpectancyStatus::Fulfilled => {
                    let packet = self.get_packet_ptr();
                    if self.run_callback_if_exists(Some(packet)) {
                        // Here, we end up bypassing all further stages and send the packet directly to whoever
                        // was expecting the packet. Since this is an [ObjectExpectancy], we don't have to worry
                        Ok(Async::Ready(None))
                    } else {
                        self.status = ExpectancyStatus::BackToStageDriver;
                        Ok(Async::Ready(Some(packet.clone())))
                    }
                },

                _ => {
                    Ok(Async::NotReady)
                }
            }
        }
    }
}

impl Expectancy for SingletonExpectancy {
    fn generate_callback(&mut self) -> Pin<Box<ExpectancyResponse>> {
        let mut exp_response = ExpectancyResponse::new();
        exp_response.poll().unwrap(); // We poll the expectancy, and in doing so, it sets its internal task. This should not fail on first-poll, as all it does is set the internal task
        self.expectancy_response_task = unsafe { Some(exp_response.get_task()) }; // we set the task for this ObjectExpectancy
        let _ = self.expectancy_response_ptr.write(&mut *exp_response as *mut ExpectancyResponse); // We then write a pointer to a heap-pinned ExpectancyResponse
        exp_response // We return the Heap-pinned wrapper to the ExpectancyResponse with certainty that the pointer we wrote will still be valid and not dangling
    }

    fn get_packet(&mut self) -> Option<StageDriverPacket> {
        match self.status {
            ExpectancyStatus::Fulfilled => {
                Ok(Async::Ready(self.get_packet_ptr()))
            },

            _ => {
                Ok(Async::NotReady)
            }
        }
    }

    unsafe fn get_packet_unchecked(&mut self) -> StageDriverPacket {
        self.get_packet_ptr()
    }

    fn is_fulfilled(&self) -> bool {
        self.status == ExpectancyStatus::Fulfilled
    }

    fn needs_delete(&self) -> bool {
        if self.status == ExpectancyStatus::NeedsDelete {
            return true
        } else {
            // The expectancy doesn't need to be deleted, but what if the packet is flagged for
            // deletion?

            // Check to see if the packet needs deleting, as it may be flagged for deletion
            // while being passed around as a [StageDriverPacket]
            if self.is_fulfilled() {
                if self.get_packet_ptr().stage == PacketStage::NeedsDelete {
                    return true;
                }
            }
        }

        false
    }
}