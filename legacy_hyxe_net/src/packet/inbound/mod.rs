/// The stage driver is the zeroth stage + the driving mechanism. It accepts packets from the sockets, converts the raw inbound packets into processed inbound packets, and then stores them internally.
/// packets are now able to be scanned for local expectancies. The OID_EID (Object_ID/Expectancy_ID) is used for service-layer filters (apps) that expect a response.
///
/// Since multiple packets may belong to a single oid_eid, stage 0 may also reconstruct entire waveforms. In order for reconstruction to occur, there must be a [OBJECT_HEADER] packet
///
/// There are four main paths that a packet can take for stage 0:
/// [1]:
pub mod stage_driver;

/// Contains the types for internal communication with the [Session] layer.
pub mod expectancy;

/// Expectancies are futures that effectively hold a subroutine's status from ending until the expectancy is fulfilled or fails.
/// In particular, the object_expectancy is created when an inbound [OBJECT_HEADER] packet enters
pub mod object_expectancy;

/// Unlike an [ObjectExpectancy], this is an expectation for a small response that needs only 1 packet to communicate a return statement
pub mod singleton_expectancy;

/// This type is for packets which are to be directly forwarded, or, packets which go into a network black-hole
pub mod null_expectancy;

/// While the packets sent here from stage 0 are properly aligned and have valid values, the action is still unknown. Stage 1 determines the action, decrypts each packet, and then sends each packet to a sub-stage 1 sink.
pub mod stage2;


/// If a packet makes it to stage 3, then that implies one of two things. Either:
/// [1] The packet has an expectancy of zero; this is received data
use futures::{Async, Sink};
/// The operations executed by any subroutine hereunder should never block, as it is called by the sink upon drainage
pub trait PacketDriver<'next_stage, 'driver: 'next_stage>: Sink {
    /// This function has to perform this action at the end of each stage past stage 0:
    /// [1] drain the packets from the current stage's internal allocated vector
    /// [2] Using the drained values, update the stage (if necessary). Then, drop the
    /// mutable reference (this allows the StageDriver to drive the packets up one stage
    /// or drop the owned packets from memory entirely). TODO: Determine the exacts of
    /// this mechanism.
    fn drive(&mut self) -> Result<Async<()>, Self::SinkError>;

    /// This is the function that should be called from the sink
    fn advance_drive(&mut self) -> Result<Async<()>, Self::SinkError> {
        self.drive()
    }
}