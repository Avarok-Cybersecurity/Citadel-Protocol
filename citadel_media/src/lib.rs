//! Codec-agnostic media transport primitives: fragmentation, reassembly, jitter
//! buffering, send-queue policy, track descriptors and WAV/IVF demuxing.
//!
//! This crate performs no I/O. Time is injected via [`MediaInstant`] and the
//! demuxers operate on caller-provided `std::io::Read`/`Write` handles only.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod config;
pub mod demux;
pub mod descriptor;
pub mod error;
pub mod frame;
pub mod jitter;
pub mod packetizer;
pub mod queue;
pub mod reassembly;
pub mod stats;
pub mod time;
pub mod wire;

pub use config::MediaConfig;
pub use descriptor::{ControlMessage, MediaTrackDescriptor};
pub use error::{DemuxError, MediaError};
pub use frame::{FrameFlags, FrameHeader, MediaFrame, TrackId, TrackKind};
pub use jitter::{JitterBuffer, PopResult, PushResult};
pub use packetizer::{FragmentOut, Fragments, Packetizer};
pub use queue::SendQueue;
pub use reassembly::{ReassembleOutcome, Reassembler};
pub use stats::MediaStats;
pub use time::MediaInstant;
pub use wire::{FragmentHeader, WireMessage, FRAGMENT_HEADER_LEN, WIRE_VERSION};
