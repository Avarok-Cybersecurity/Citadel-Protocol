#[cfg(test)]
mod tests {
    #[test]
    fn dummy() {
        println!("Compile success!");
    }

    #[test]
    fn nonces() {
        let input = b"Hello, world!";
        let nonce = 777333777333;

        let nonced_bytes = apply_nonce(input, nonce);
        let unnonced_bytes = unapply_nonce(nonced_bytes, nonce).unwrap();

        assert_eq!(unnonced_bytes, input);
    }

}

/*
use futures2::executor::block_on;
use hyxewave_net::prelude::*;
use std::net::{SocketAddr, IpAddr};
use tokio::net::{TcpStream, TcpListener};
use bytes::{BytesMut, BufMut};
use futures2::channel::mpsc::{unbounded, channel, UnboundedReceiver, UnboundedSender, Receiver};
use std::str::FromStr;
use futures2::{Future, Stream, StreamExt};
use hyxewave_net::misc::HyxeError;
use hyxewave_net::connection::STREAM_SHUTDOWN;
use std::ops::DerefMut;
use futures2::compat::Future01CompatExt;
use futures2::{Future, TryFutureExt};

#[test]
fn client() {
    block_on(tt());
}

async fn tt() -> Result<(), ()>{
    client_async().compat().await
}

fn client_async() -> impl Future<Item=(), Error=()> {
    futures::lazy(|| {

        let local_addr_to = SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 25001);
        let client = TcpStream::connect(&local_addr_to).compat();

        let mut msg = "Hello world from client!".as_bytes().to_vec();
        //let msg: &'b mut Vec<u8> = &mut msg;
        let (outbound_tx, outbound_rx) = unbounded::<OutboundItem>();
        let (inbound_tx, inbound_rx) = unbounded::<RawInboundItem>();
        let (stop_cxn_tube_tx, stop_cxn_tube_rx) = channel::<u8>(1);

        let out = outbound_tx.clone();

        let client = client.from_err().and_then(move |cxn| {
            println!("[Registration Client] Connection with {} established!", cxn.peer_addr().unwrap().to_string());

            outbound_tx.unbounded_send(msg).unwrap_or(());
            stream_wrappers::old::base64(cxn, outbound_rx, inbound_tx, stop_cxn_tube_rx)
        }).map_err(|err| {
            println!("ERR: {:#?}", err);
        });


        let listener = inbound_rx.for_each(move |packet| {
            let resp = String::from_utf8(packet.to_vec()).unwrap();
            println!("Packet received: {}", resp);
            let mut resp = format!("You said: {}", resp).into_bytes();
            //stop_cxn_tube_tx.send(STREAM_SHUTDOWN).unwrap_or(());
            out.unbounded_send(resp).unwrap_or(());
            Ok(())
        }).map_err(|_| ());

        client.join(listener).map(|_| ())
    })
}

#[test]
fn server() {
    block_on(server_async().compat());
}

fn server_async() -> impl Future<Item=(), Error=()> {
    futures::lazy(|| {
        let local_addr = SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), 25001);
        let server = TcpListener::bind(&local_addr).unwrap();

        let (inbound_tx, inbound_rx) = unbounded::<RawInboundItem>();

        println!("Server started...");
        let mut server = server.incoming().map_err(|err| HyxeError::CONVERTED("Converted", true)).for_each(move |stream| {
            let addr = stream.peer_addr().unwrap();
            println!("[Registration Server] Connection with {} established!", addr.to_string());
            let (outbound_tx, outbound_rx) = unbounded::<OutboundItem>();
            let (_stop_tx, stop_rx) = channel::<u8>(1);
            let mut msg = "Thank you for connecting".as_bytes().to_vec();
            msg.reserve(msg.len() + 2);

            outbound_tx.unbounded_send(msg.clone());
            msg.put_u8(b'1');
            outbound_tx.unbounded_send(msg.clone());
            msg.put_u8(b'2');
            outbound_tx.unbounded_send(msg);

            crate::stream_wrappers::base64_tcp(stream, outbound_rx, inbound_tx.clone(), stop_rx)
        }).map_err(|err| {
            println!("ERR: {:#?}", err);
        });

        let mut listener = inbound_rx.for_each(|packet| {
            println!("Packet received: {}", String::from_utf8(packet.to_vec()).unwrap());
            Ok(())
        }).map_err(|_| ());

        listener.join(server).map_err(|_| ()).map(|res| ())
    })
}
*/