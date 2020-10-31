/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

/// Futures 0.1
pub mod old {
    use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender, Receiver};
    use futures::{Future, Stream, Sink};


    use crate::packet::misc::ConnectError;
    use tokio::codec::Framed;
    use crate::prelude::Base64Codec;
    use hyxe_netdata::packet::RawInboundPacket;
    use tokio::prelude::{AsyncRead, AsyncWrite};
    use hyxe_netdata::connection::NetStreamMetadata;

    /// Useful for toggling between Input types
    pub type OutboundItem = Vec<u8>;

    /// Useful for toggling between Output types
    pub type RawInboundItem = RawInboundPacket;

    /// `stream`: The data source to listen upon
    /// `outbound_rx`: The receiver which then sends information across the stream
    /// `inbound_sink`: The location for sending information after reception from stream
    /// `dc_rc_tube_rx`: The receiver for kill signals
    pub fn base64<'cxn, 'a: 'cxn, S: 'a + AsyncRead + AsyncWrite>(stream: S, metadata: NetStreamMetadata, outbound_rx: UnboundedReceiver<OutboundItem>, inbound_sink: UnboundedSender<RawInboundItem>, dc_rc_tube_rx: Receiver<u8>) -> impl Future<Item=(), Error=ConnectError> + 'cxn {
        let framed = Framed::<S,Base64Codec<OutboundItem>>::new(stream, Base64Codec::new(metadata));

        let (outbound_sink, inbound_stream) = framed.split();

        let inbound = inbound_stream.map_err(|err| ConnectError::Generic(err.to_string()))
            .forward(inbound_sink.sink_map_err(|err| ConnectError::Generic(err.to_string())));

        let outbound = outbound_rx.map_err(|_| ConnectError::Generic("Outbound R/X not working".to_string())).forward(outbound_sink.sink_map_err(|err| ConnectError::Generic(err.to_string())));

        let stopper = dc_rc_tube_rx.map_err(|_| ConnectError::Generic("[Error] DC Tube Error (unknown)".to_string())).for_each(move |cmd| {
            match cmd {
                super::super::STREAM_SHUTDOWN => {
                    println!("[AsyncStreamHandler] Shutting down stream");
                    Err(ConnectError::Shutdown)
                },

                super::super::STREAM_RESTART => {
                    println!("[AsyncStreamHandler] Restarting stream");
                    // TODO: Handle restart signal
                    Err(ConnectError::Restart)
                },

                _ => {
                    println!("[AsyncStreamHandler] unknown command!");
                    Ok(())
                }
            }
        }).map_err(|err| err);


        inbound.select2(outbound).map(|_| ()).select2(stopper).map(|_| ()).and_then(|_| {
            //insert shutdown expression here (one possible location)
            Ok(())
        }).map_err(|_| ConnectError::Generic("Stream ending".to_string()))
    }

}

// Futures 0.3
/*
pub mod new {
    use crate::codec::Base64Codec;

    use futures2::compat::{Future01CompatExt, Stream01CompatExt};

    use hyxe_shared::packet::RawInboundPacket;
    use hyxe_shared::connection::NetStreamMetadata;

    use tokio::codec::Framed;
    use futures::sink::Sink;
    use futures2::{TryFutureExt, TryStreamExt, SinkExt};
    use futures::stream::Stream;
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, Receiver};
    use futures::future::Future;
    use crate::packet::misc::ConnectError;
    use std::error::Error;
    use tokio::io::{AsyncRead, AsyncWrite};
    use futures2::StreamExt;


    /// Useful for toggling between Input types
    pub type OutboundItem = Vec<u8>;

    /// Useful for toggling between Output types
    pub type RawInboundItem<'cxn> = RawInboundPacket<'cxn>;

    /// `stream`: The data source to listen upon
    /// `outbound_rx`: The receiver which then sends information across the stream
    /// `inbound_sink`: The location for sending information after reception from stream
    /// `dc_rc_tube_rx`: The receiver for kill signals
    pub async fn base64<'cxn, S: 'cxn + AsyncRead + AsyncWrite + StreamExt>(stream: S, metadata: &'cxn NetStreamMetadata, outbound_rx: UnboundedReceiver<OutboundItem>, mut inbound_sink: UnboundedSender<RawInboundItem<'cxn>>, dc_rc_tube_rx: Receiver<u8>) -> Result<(), ConnectError<'cxn>> {

        let framed = Framed::<S,Base64Codec<OutboundItem>>::new(stream, Base64Codec::new(metadata));

        let (outbound_sink, inbound_stream) = framed.split();

        let mut inbound = inbound_stream.map_err(|err| ConnectError::Generic(err.description()))
            .forward(inbound_sink.sink_map_err(|err| ConnectError::Generic(err.description())));


        let outbound = outbound_rx.map_err(|err| ConnectError::Generic(err.description())).forward(outbound_sink.sink_map_err(|err| ConnectError::Generic(err.description())));

        let stopper = dc_rc_tube_rx.map_err(|err| ConnectError::Generic("[Error] DC Tube Error (unknown)")).for_each(move |cmd| {
            match cmd {
                super::super::STREAM_SHUTDOWN => {
                    println!("[AsyncStreamHandler] Shutting down stream");
                    Err(ConnectError::Generic(""))
                },

                super::super::STREAM_RESTART => {
                    println!("[AsyncStreamHandler] Restarting stream");
                    Err(ConnectError::Generic(""))
                },

                _ => {
                    println!("[AsyncStreamHandler] unknown command!");
                    return Ok(())
                }
            }
        }).map_err(|err| err);


        futures::lazy(|| inbound.select2(outbound).map(|e| ()).select2(stopper).map(|e| ()).and_then(|_| {
            //insert shutdown expression here (one possible location)
            Ok(())
        })).map_err(|err| ConnectError::Generic("")).compat().await
    }
}
*/