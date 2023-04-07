use citadel_proto::prelude::NodeType;
use citadel_sdk::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
use citadel_sdk::prelude::*;
use futures::StreamExt;
use std::net::SocketAddr;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    std::println!(" Server is now listening..! \n");

    let server = NodeBuilder::default()
        .with_insecure_skip_cert_verification()
        .with_node_type(NodeType::server(SocketAddr::from_str("127.0.0.1:25021").unwrap()).unwrap())
        .build(ClientConnectListenerKernel::new(
            move |connect_success, _remote| async move {

                std::println!(" Client has successfully connected..! \n");

                let (sink, mut stream) = connect_success.channel.split();

                let response = stream.next().await;
                match response.unwrap().as_ref() {
                    b"ping" => std::println!(" PING RECEIVED... \n"),
                    _ => std::println!(" PING NOT RECEIVED... \n"),
                }

                let ping = SecureProtocolPacket::from(b"pong" as &[u8]);
                sink.send_message(ping).await.unwrap();

                std::println!(" Connection closing... \n");

                Ok(())
            },
        ))
        .unwrap();

        let _result = match server.await {
            Ok(_result) => _result,
            Err(error) => panic!("Problem waiting for client connection: {:?}", error),
        };

    std::println!(" Server is now shutting down... \n");
}
