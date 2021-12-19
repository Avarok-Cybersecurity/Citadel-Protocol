/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */
use std::{cmp, io, usize};

use bytes::{BufMut, BytesMut};
use tokio::codec::{Encoder, Decoder};
use hyxe_netdata::connection::NetStreamMetadata;
use std::time::Instant;
use std::marker::PhantomData;
use crate::prelude::RawInboundItem;

/// for benches irrelevant side note: (unused_results, warnings, unused_features, warnings above)
/// `codec` contains optimized and unique algorithms for encoding/decoding that aren't present in rust's crate repository (e.g., base64)
/// A simple `Codec` implementation that splits up data into lines.
pub struct Base64Codec<'cxn, 'a: 'cxn, T: AsRef<[u8]> + 'a> {
    // Stored index of the next index to examine for a `\n` character.
    // This is used to optimize searching.
    // For example, if `decode` was called with `abc`, it would hold `3`,
    // because that is the next index to examine.
    // The next time `decode` is called with `abcde\n`, the method will
    // only look at `de\n` before returning.
    next_index: usize,

    /// The maximum length for a given line. If `usize::MAX`, lines will be
    /// read until a `\n` character is reached.
    max_length: usize,

    /// Are we currently discarding the remainder of a line which was over
    /// the length limit?
    is_discarding: bool,
    stream_metadata: NetStreamMetadata,
    _phantom: PhantomData<&'cxn &'a T>
}


impl<'cxn, 'a: 'cxn, T: AsRef<[u8]> + 'a> Base64Codec<'cxn, 'a, T> {
    /// Returns a `LinesCodec` for splitting up data into lines.
    ///
    /// # Note
    ///
    /// The returned `LinesCodec` will not have an upper bound on the length
    /// of a buffered line. See the documentation for [`new_with_max_length`]
    /// for information on why this could be a potential security risk.
    ///
    /// [`new_with_max_length`]: #method.new_with_max_length
    pub fn new(stream_metadata: NetStreamMetadata) -> Self {
        Base64Codec {
            next_index: 0,
            max_length: usize::MAX,
            is_discarding: false,
            stream_metadata,
            _phantom: PhantomData
        }
    }

    /// Returns a `LinesCodec` with a maximum line length limit.
    ///
    /// If this is set, calls to `LinesCodec::decode` will return a
    /// [`LengthError`] when a line exceeds the length limit. Subsequent calls
    /// will discard up to `limit` bytes from that line until a newline
    /// character is reached, returning `None` until the line over the limit
    /// has been fully discarded. After that point, calls to `decode` will
    /// function as normal.
    ///
    /// # Note
    ///
    /// Setting a length limit is highly recommended for any `LinesCodec` which
    /// will be exposed to untrusted input. Otherwise, the size of the buffer
    /// that holds the line currently being read is unbounded. An attacker could
    /// exploit this unbounded buffer by sending an unbounded amount of input
    /// without any `\n` characters, causing unbounded memory consumption.
    ///
    /// [`LengthError`]: ../struct.LengthError
    pub fn new_with_max_length(stream_metadata: NetStreamMetadata, max_length: usize) -> Self {
        Base64Codec {
            max_length,
            ..Base64Codec::new(stream_metadata)
        }
    }

    /// Returns the maximum line length when decoding.
    ///
    /// ```
    /// use std::usize;
    /// use tokio_codec::LinesCodec;
    ///
    /// let codec = LinesCodec::new();
    /// assert_eq!(codec.max_length(), usize::MAX);
    /// ```
    /// ```
    /// use tokio_codec::LinesCodec;
    ///
    /// let codec = LinesCodec::new_with_max_length(256);
    /// assert_eq!(codec.max_length(), 256);
    /// ```
    pub fn max_length(&self) -> usize {
        self.max_length
    }

    fn discard(&mut self, newline_offset: Option<usize>, read_to: usize, buf: &mut BytesMut) {
        let discard_to = if let Some(offset) = newline_offset {
            // If we found a newline, discard up to that offset and
            // then stop discarding. On the next iteration, we'll try
            // to read a line normally.
            self.is_discarding = false;
            offset + self.next_index + 1
        } else {
            // Otherwise, we didn't find a newline, so we'll discard
            // everything we read. On the next iteration, we'll continue
            // discarding up to max_len bytes unless we find a newline.
            read_to
        };
        buf.advance(discard_to);
        self.next_index = 0;
    }
}

impl<'cxn, 'a: 'cxn, T: AsRef<[u8]> + 'cxn> Decoder for Base64Codec<'cxn, 'a, T> where Self: 'a {
    type Item = RawInboundItem;
    // TODO: in the next breaking change, this should be changed to a custom
    // error type that indicates the "max length exceeded" condition better.
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        println!("[CODEC] RECV {}", buf.len());
        loop {
            // Determine how far into the buffer we'll search for a newline. If
            // there's no max_length set, we'll read to the end of the buffer.
            let read_to = cmp::min(self.max_length.saturating_add(1), buf.len());


            let newline_offset = buf[self.next_index..read_to]
                .iter()
                .position(|b| *b == b'\n');

            if self.is_discarding {
                self.discard(newline_offset, read_to, buf);
            } else {
                return if let Some(offset) = newline_offset {
                    // Found a line!
                    let newline_index = offset + self.next_index;
                    self.next_index = 0;

                    let mut line = buf.split_to(newline_index + 1); // use to be newline_index + 1

                    // Get rid of the '\n' at the end of line
                    line.truncate(line.len() - 1);

                    match base64::decode_config_bytes_auto(&mut line, base64::STANDARD_NO_PAD) {
                        Ok(_) => {
                            Ok(Some(RawInboundItem::new(self.stream_metadata, Instant::now(), line)))
                        }

                        Err(err) => {
                            println!("Decode Err: {}", err.to_string());
                            //TODO: [ON-RELEASE] remove below to not stop entire program
                            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unable to decode inbound packet via base64 algorithm"))
                        }
                    }
                } else if buf.len() > self.max_length {
                    // Reached the maximum length without finding a
                    // newline, return an error and start discarding on the
                    // next call.
                    self.is_discarding = true;
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        "CODEC line length limit exceeded",
                    ))
                } else {
                    // We didn't find a line or reach the length limit, so the next
                    // call will resume searching at the current offset.
                    self.next_index = read_to;
                    Ok(None)
                };
            }
        }
    }
}

impl<'cxn, 'a: 'cxn, T: AsRef<[u8]> + 'a> Encoder for Base64Codec<'cxn, 'a, T> {
    type Item = T;
    type Error = io::Error;

    fn encode(&mut self, line: Self::Item, buf: &mut BytesMut) -> Result<(), io::Error> {
        // Add +1 for the \n
        let line = line.as_ref();
        let expected_max = ((line.len() + 3) * 3 / 4) + 1;
        if buf.remaining_mut() <= expected_max {
            buf.reserve(expected_max + 1);
        }

        match base64::encode_config_bytes(line, base64::STANDARD_NO_PAD, buf) {
            Ok(_) => {
                buf.put(b'\n');
                Ok(())
            }

            Err(err) => {
                Err(err)
            }
        }
    }
}