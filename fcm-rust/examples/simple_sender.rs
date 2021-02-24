#[macro_use]
extern crate serde_derive;

use argparse::{ArgumentParser, Store};
use fcm::{Client, MessageBuilder};

#[derive(Serialize)]
struct CustomData {
    message: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pretty_env_logger::init();

    let mut device_token = String::new();
    let mut api_key = String::new();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("A simple FCM notification sender");
        ap.refer(&mut device_token)
            .add_option(&["-t", "--device_token"], Store, "Device token");
        ap.refer(&mut api_key)
            .add_option(&["-k", "--api_key"], Store, "API key");
        ap.parse_args_or_exit();
    }

    let client = Client::new();
    let data = CustomData { message: "howdy" };

    let mut builder = MessageBuilder::new(&api_key, &device_token);
    builder.data(&data)?;

    let response = client.send(builder.finalize()).await?;
    println!("Sent: {:?}", response);

    Ok(())
}
