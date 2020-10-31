use std::collections::VecDeque;
use crate::connection::stream_wrappers::old::RawInboundItem;
use std::marker::PhantomData;
use futures::{Sink, AsyncSink, Async};
use crate::packet::inbound::PacketDriver;
use crate::packet::inbound::stage_driver::StageDriverPacket;
use hyxe_netdata::packet::{PacketStage, StageDriverPacket};

/// All packets that have either a DO_CONNECT, CONNECT_ALIVE, DO_DISCONNECT, etc, will be forwarded here
pub mod login;

/// Stage 1: At this point, we have received packets which have a valid layout. Furthermore, there may be reconstructed waveforms
pub struct Stage2Sink<'this_stage, 'driver: 'this_stage> {
    needs_forward: VecDeque<StageDriverPacket>,
    rebound: VecDeque<StageDriverPacket>,
    /// These packets have reached their destination, and are neither forwarded nor rebounded
    black_hole: VecDeque<StageDriverPacket>,
    _phantom: PhantomData<&'this_stage Self>
}

impl<'this_stage, 'driver: 'this_stage> Stage2Sink<'this_stage, 'driver> {
    /// Creates a new stage 1 sink
    pub fn new() -> Self {
        Self { needs_forward: VecDeque::new(), rebound: VecDeque::new(), black_hole: VecDeque::new(), _phantom: Default::default() }
    }
}

impl<'this_stage, 'driver: 'this_stage> Sink for Stage2Sink<'this_stage, 'driver> {
    type SinkItem = StageDriverPacket;
    type SinkError = ();

    fn start_send(&mut self, item: Self::SinkItem) -> Result<AsyncSink<Self::SinkItem>, Self::SinkError> {
        match item.stage {
            PacketStage::Stage1Forward => {
                item.stage = PacketStage::Stage2; // set to stage 2 to prevent
                self.needs_forward.push_back(item);
            },

            PacketStage::Stage1Rebound => {
                item.stage = PacketStage::Stage2;
                self.rebound.push_back(item);
            },

            PacketStage::Stage1BlackHole => {
                item.stage = PacketStage::Stage2;
                self.black_hole.push_back(item);
            },

            _ => panic!("Bad program logic. Only Forwards, Rebounds, or Black Hole packets may reach this stage")
        }

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, Self::SinkError> {
        let len = self.fifo.len();
        let _ = self.fifo.drain(0..len).map(|packet| {
            // determine packet action
            println!("Packet made it to stage 2.. END (for now)");
        }).collect::<Vec<()>>();

        self.advance_drive()
    }

    fn close(&mut self) -> Result<Async<()>, Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl<'this_stage, 'driver: 'this_stage> PacketDriver<'this_stage, 'driver> for Stage1Sink<'this_stage, 'driver> {
    fn drive(&'driver mut self) -> Result<Async<()>, Self::SinkError> {
        Ok(Async::Ready(()))
    }
}