#![doc(html_root_url = "https://panicbit.github.io/fcm-rust/fcm/")]
//! fcm
//! ===
//!
//! A client for asynchronous sending of Firebase Cloud Messages, or Push Notifications.
//!
//! # Examples:
//!
//! To send out a FCM Message with some custom data:
//!
//! ```no_run
//! # use std::collections::HashMap;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let client = fcm::Client::new();
//!
//! let mut map = HashMap::new();
//! map.insert("message", "Howdy!");
//!
//! let mut builder = fcm::MessageBuilder::new("<FCM API Key>", "<registration id>");
//! builder.data(&map);
//!
//! let response = client.send(builder.finalize()).await?;
//! println!("Sent: {:?}", response);
//! # Ok(())
//! # }
//! ```
//!
//! To send a message using FCM Notifications, we first build the notification:
//!
//! ```rust
//! # fn main() {
//! let mut builder = fcm::NotificationBuilder::new();
//! builder.title("Hey!");
//! builder.body("Do you want to catch up later?");
//! let notification = builder.finalize();
//! # }
//! ```
//!
//! And then set it in the message, before sending it:
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let client = fcm::Client::new();
//!
//! let mut notification_builder = fcm::NotificationBuilder::new();
//! notification_builder.title("Hey!");
//! notification_builder.body("Do you want to catch up later?");
//!
//! let notification = notification_builder.finalize();
//! let mut message_builder = fcm::MessageBuilder::new("<FCM API Key>", "<registration id>");
//! message_builder.notification(notification);
//!
//! let response = client.send(message_builder.finalize()).await?;
//! println!("Sent: {:?}", response);
//! # Ok(())
//! # }
//! ```

#[allow(unused_imports)]
#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

mod message;
pub use crate::message::*;
mod notification;
pub use crate::notification::*;
mod client;
pub use crate::client::*;

pub use crate::client::response::FcmError as Error;
