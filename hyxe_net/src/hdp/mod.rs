use futures::Future;
use std::pin::Pin;
use futures::task::{Context, Poll};

/// Used at each HyperNode
pub mod hdp_server;
/// The fundamental packet types
pub mod hdp_packet;
/// Contains the library for processing inbound packet types. all #[inline]'d
pub mod hdp_packet_processor;
/// Manages multiple sessions
pub mod hdp_session_manager;
/// Each CID gets a session
pub mod hdp_session;
/// Packet validations. This is not the same as encryption
pub mod validation;
/// For creating specific packet types
pub mod hdp_packet_crafter;
/// ~!
pub mod time;
/// For keeping track of the stages of different processes
pub mod state_container;
/// For the custom BytesCodec that doesn't overflow
pub mod codec;
/// For organizing the stage containers
pub mod state_subcontainers;
/// A cloneable handle for sending data through UDP ports
pub mod outbound_sender;
/// For handling file-transfer
pub mod file_transfer;

pub mod nat_handler;
///
pub mod peer;

pub(crate) mod session_queue_handler;
pub mod misc;

/// For denoting to the compiler that running the future is thread-safe
/// It is up to the caller to ensure the supplied future is not going to be called
/// from multiple threads concurrently. IF there is a single instance of the task, then
/// use this. If there will be multiple, use the safer version in misc::ThreadSafeFuture
pub struct AssertSendSafeFuture<'a, Out: 'a>(Pin<Box<dyn Future<Output=Out> + 'a>>);

unsafe impl<'a, Out: 'a> Send for AssertSendSafeFuture<'a, Out> {}

impl<'a, Out: 'a> AssertSendSafeFuture<'a, Out> {
    /// Wraps a future, asserting it is safe to use in a multithreaded context at the possible cost of race conditions, locks, etc
    pub unsafe fn new(fx: impl Future<Output=Out> + 'a) -> Self {
        Self(Box::pin(fx))
    }

    pub fn new_silent(fx: impl Future<Output=Out> + 'a) -> Self {
        Self(Box::pin(fx))
    }
}

impl<'a, Out: 'a> Future for AssertSendSafeFuture<'a, Out> {
    type Output = Out;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}