use citadel_proto::prelude::{
    EncryptionAlgorithm, KemAlgorithm, SecrecyMode, SecureProtocolPacket,
    SessionSecuritySettingsBuilder, UdpMode,
};
use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use citadel_sdk::prelude::NodeBuilder;
use futures::StreamExt;
use std::net::SocketAddr;
use std::str::FromStr;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    std::println!(" Client is now attempting to connect to server... \n");

    let uuid = Uuid::new_v4();

    let session_security = SessionSecuritySettingsBuilder::default()
        .with_secrecy_mode(SecrecyMode::BestEffort)
        .with_crypto_params(KemAlgorithm::Kyber + EncryptionAlgorithm::AES_GCM_256)
        .build()
        .unwrap();

    let client_kernel = SingleClientServerConnectionKernel::new_passwordless(
        uuid,
        SocketAddr::from_str("127.0.0.1:25021").unwrap(),
        UdpMode::Enabled,
        session_security,
        move |connect_success, remote| async move {

            std::println!(" Client has successfully connected..! \n");

            let (sink, mut stream) = connect_success.channel.split();

            let ping = SecureProtocolPacket::from(b"ping" as &[u8]);
            sink.send_message(ping).await.unwrap();

            std::println!(" Ping message sent... waiting... \n");

            let response = stream.next().await;
            match response.unwrap().as_ref() {
                b"pong" => std::println!(" PONG RECEIVED... \n"),
                _ => std::println!(" PONG NOT RECEIVED... \n"),
            }

            std::println!(" Client can now close connection... \n");

            remote.shutdown_kernel().await?;

            Ok(())
        },
    )
    .unwrap();

    let client = NodeBuilder::default().with_insecure_skip_cert_verification().build(client_kernel).unwrap();

    let _result = match client.await {
        Ok(_result) => _result,
        Err(error) => panic!("Problem connecting to server: {:?}", error),
    };

    std::println!(" Client now closing... \n");
}
