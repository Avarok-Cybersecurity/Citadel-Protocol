//! Implementations of `io::Write` to transparently handle base64.
pub use self::encoder::EncoderWriter;

mod encoder;

#[cfg(test)]
mod encoder_tests;
