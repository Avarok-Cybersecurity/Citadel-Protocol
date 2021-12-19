use crate::connection::stream_wrappers::old::RawInboundItem;
use futures::{Future, Async};
use std::pin::Pin;
use hyxe_netdata::packet::{RawInboundPacket, PacketStage, StageDriverPacket};
use std::ops::{Deref, DerefMut};
use crate::packet::inbound::expectancy::{Expectancy, ExpectancyResponse};

/// The null expectancy type is simply a "transparent" abstraction that serves no expectancy-like functionality. It is
/// to help keep the metaphor of the program consistent with the idea that all packets are to be expected, with the
/// exception of packets that don't have an expectancy but need forwarding, or, packets that reach the end of their
/// lives at the receiving node
pub struct NullExpectancy {
    packet: Pin<Box<RawInboundItem>>
}

impl NullExpectancy {
    /// Generates a new null expectancy
    pub fn new(packet: RawInboundItem) -> Self {
        Self { packet: Box::pin(packet) }
    }

    /// This can ONLY be called once the future of self is complete
    fn get_packet_ptr(&mut self) -> StageDriverPacket {
        StageDriverPacket::from(&mut self.packet)
    }
}

impl Future for NullExpectancy {
    type Item = StageDriverPacket;
    type Error = !;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        Ok(Async::Ready(self.get_packet_ptr()))
    }
}

impl From<RawInboundItem> for NullExpectancy {
    fn from(packet: RawInboundPacket) -> Self {
        Self::new(packet)
    }
}

impl Deref for NullExpectancy {
    type Target = RawInboundItem;

    fn deref(&self) -> &Self::Target {
        &*self.packet.as_ref()
    }
}

impl DerefMut for NullExpectancy {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.packet.as_mut()
    }
}

impl Expectancy for NullExpectancy {
    fn generate_callback(&mut self) -> ExpectancyResponse {
        unimplemented!("We ain't expecting nothing, captain!")
    }

    fn get_packet(&mut self) -> Option<StageDriverPacket> {
        Some(self.get_packet_ptr())
    }

    unsafe fn get_packet_unchecked(&mut self) -> StageDriverPacket {
        self.get_packet_ptr()
    }

    fn is_fulfilled(&self) -> bool {
        true
    }

    fn needs_delete(&self) -> bool {
        self.packet.stage == PacketStage::NeedsDelete
    }
}