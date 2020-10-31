use hyxe_crypt::drill::SecurityLevel;
use crate::packet::inbound::stage_driver::StageDriverPacket;
use hyxe_netdata::packet::StageDriverPacket;
use std::mem::MaybeUninit;
use async_std::task::{Waker, Context, Poll};
use std::pin::Pin;
use futures::{Future, Async};
use futures::task::Task;
use std::fmt::{Display, Formatter};

/// A type for unifying all 3 types of Expectancies: Singleton's, Objects, and Null's
pub trait Expectancy {
    /// This creates a response which is waked once this expectancy finishes.
    fn generate_callback(&mut self) -> Pin<Box<ExpectancyResponse>>;
    /// Possibly returns a pointer to a heap-pinned packet
    fn get_packet(&mut self) -> Option<StageDriverPacket>;
    /// Returns a pointer to a heap-pinned packet without checking
    unsafe fn get_packet_unchecked(&mut self) -> StageDriverPacket;
    /// Returns true if the expectancy is fulfilled and ready for being sent to other threads
    fn is_fulfilled(&self) -> bool;
    /// Determines if the expectancy needs deletion or not. If the expectancy needs deletion, it will be removed
    /// along with the packet. Only flag for deletion once all [StageDriverPacket's] are cleansed from memory
    fn needs_delete(&self) -> bool;
}

/// This is an object sent by the [Session]. If you are uncertain which to use, select Auto.
/// An [ExpectancyRequest] is not enough to facilitate the arrival of data. Instead, you must
/// send an [ExpectancyRequest] to the internal [StageDriver], and thereafter, send the data
/// with `expects_response` equal to `true` coupled with the `eid_oid` supplied within the
/// [ExpectancyRequest]. By following this procedure, you allow the inbound direction to detect
/// a packet or object of packets with a unique `eid_oid`. If only a single packet is expected,
/// then you will receive a packet with a size of at most [MAX_PACKET_SIZE=555]. Even in the
/// case that you expect an object of packets, you will still receive an single (jumbo) packet
/// that stores a concatenation of all the data within the payload of the packet in the proper
/// order. By supplying the `CID` within the [ExpectancyRequest], the [StageDriver] will ensure
/// that the data forwarded internally to the [Session] layer is an element of the session.
///
/// Sometimes, you may expect information, but do not know if the data will be larger than
/// [MAX_PACKET_SIZE]. If this is the case, then supply `Auto`. This is similar to specifying
/// `Object`, however, there are some differences. Whereas `Object` expects an exact payload and
/// creates a more rigidly-defined header, `Auto` creates a packet with a mostly empty header that
/// is flagged to get entirely replaced once EITHER the [OBJECT_HEADER] or singleton packet returns.
///
/// A note about the `security_level`: This is a *request*. By default, the internal system honors
/// security level requests, but ultimately, the adjacent node has the choice. Like a real-life
/// conversation in a public setting, it is up to the person you're talking-to to control their
/// audacity ... choose your connections wisely!
pub enum ExpectancyRequest {
    /// Your CID, eid_oid, timeout (ms), security level requested
    Singleton(u64, u64, u64, SecurityLevel),
    /// Your CID, eid_oid, payload bytes expected, timeout (ms), security level requested
    Object(u64, u64, usize, u64, SecurityLevel),
    /// Your CID, eid_oid, timeout (ms), security level requested
    Auto(u64, u64, u64, SecurityLevel),
}

impl Display for ExpectancyRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ExpectancyRequest::Singleton(cid, eid_oid, timeout, security_level) => {
                write!(f, "[Singleton] [CID: {} | EID_OID: {} | Timeout: {} | security_level: {} ]", cid, eid_oid, timeout, security_level)
            },

            ExpectancyRequest::Object(cid, eid_oid, payload, timeout, security_level) => {
                write!(f, "[Object] [CID: {} | EID_OID: {} | Timeout: {} | Payload Size: {} | security_level: {} ]", cid, eid_oid, payload, timeout, security_level)
            },

            ExpectancyRequest::Auto(cid, eid_oid, timeout, security_level) => {
                write!(f, "[Auto] [CID: {} | EID_OID: {} | Timeout: {} | security_level: {} ]", cid, eid_oid, timeout, security_level)
            }
        }
    }
}

/// The purpose of the [ExpectancyResponse] is to awaken a .await waypoint existent within the closure of the [BridgeHandler].
/// Sometimes, when the [BridgeHandler] sends data, it expects a response from an endpoint. After the [BridgeHandler] sends data
/// outbound, it then makes a call to the [StageDriver] with a particular [ExpectancyRequest]. The [StageDriver] then immediately
/// creates a future-awaitable [ExpectancyResponse]. Before returning the [ExpectancyResponse], the lower-level [T: Expectancy] type
/// must obtain the waker from the [ExpectancyResponse]. To do that, the [T: Expectancy] type polls the [ExpectancyResponse], and
/// then within the poll() function of [ExpectancyResponse], the waker is set and then obtained by the [T: Expectancy] type.
/// This allows the [T: Expectancy] type to wake the [ExpectancyResponse] upon completion
pub struct ExpectancyResponse {
    deliverable: MaybeUninit<StageDriverPacket>,
    task: Option<Task>,
    delivered: bool,
}

unsafe impl Send for ExpectancyResponse {}
unsafe impl Sync for ExpectancyResponse {}

impl ExpectancyResponse {
    /// Creates a new .awaitable [ExpectancyResponse]
    pub fn new() -> Pin<Box<Self>> {
        Box::pin(Self { deliverable: MaybeUninit::uninit(), task: None, delivered: false })
    }

    /// Notifies the task
    pub unsafe fn notify(&mut self, packet: Option<StageDriverPacket>) {
        if let Some(packet) = packet {
            let _ = self.deliverable.write(packet);
        }
        self.delivered = true;
        self.task.unwrap().notify()
    }

    /// Delivers the packet into the deliverable field
    pub fn deliver_packet(&mut self, packet: StageDriverPacket) {
        let _ = self.deliverable.write(packet);
    }

}

impl Future for ExpectancyResponse {
    /// If this future returns `None`, that implies a timeout has reached. Otherwise, the expectancy was fulfilled
    type Item = Option<StageDriverPacket>;
    type Error = ();

    /// This gets polled twice. The first time is manual, the second time is invoked manually by the [StageDriver]'s expectancy layer
    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        if self.task.is_none() {
            self.task = Some(futures::task::current());
            return Ok(Async::NotReady);
        }

        if self.delivered {
            unsafe { Ok(Async::Ready(Some(self.deliverable.assume_init()))) }
        } else {
            Ok(Async::Ready(None))
        }
    }
}