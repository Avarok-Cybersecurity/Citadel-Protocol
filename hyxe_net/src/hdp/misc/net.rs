use tokio_util::codec::LengthDelimitedCodec;
use crate::hdp::misc::clean_shutdown::{clean_framed_shutdown, CleanShutdownSink, CleanShutdownStream};
use bytes::Bytes;
use tokio::io::{AsyncWrite, AsyncRead};
use crate::macros::ContextRequirements;

/// Wraps a stream into a split interface for I/O that safely shuts-down the interface
/// upon drop
pub fn safe_split_stream<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements>(stream: S)
    -> (CleanShutdownSink<S, LengthDelimitedCodec, Bytes>, CleanShutdownStream<S, LengthDelimitedCodec, Bytes>){
    // With access to the primary stream, we can now communicate through it from this session
    let framed = LengthDelimitedCodec::builder()
        .length_field_offset(0) // default value
        .length_field_length(4)
        .length_adjustment(0)   // default value
        // `num_skip` is not needed, the default is to skip
        .new_framed(stream);

    clean_framed_shutdown(framed)
}