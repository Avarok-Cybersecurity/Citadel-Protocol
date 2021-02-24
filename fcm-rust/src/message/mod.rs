use std::borrow::Cow;

use erased_serde::Serialize;
use serde_json::{self, Value};

use crate::notification::Notification;

#[cfg(test)]
mod tests;

#[derive(Serialize, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Normal,
    High,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct MessageBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    collapse_key: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    content_available: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    delay_while_idle: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    dry_run: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    notification: Option<Notification<'a>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<Priority>,

    #[serde(skip_serializing_if = "Option::is_none")]
    registration_ids: Option<Vec<Cow<'a, str>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    restricted_package_name: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    time_to_live: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'a str>,
}

/// Represents a FCM message. Construct the FCM message
/// using various utility methods and finally send it.
/// # Examples:
/// ```rust
/// use fcm::MessageBuilder;
///
/// let mut builder = MessageBuilder::new("<FCM API Key>", "<registration id>");
/// builder.dry_run(true);
/// let message = builder.finalize();
/// ```
#[derive(Debug)]
pub struct Message<'a> {
    pub api_key: &'a str,
    pub body: MessageBody<'a>,
}

///
/// A builder to get a `Message` instance.
///
/// # Examples
///
/// ```rust
/// use fcm::MessageBuilder;
///
/// let mut builder = MessageBuilder::new("<FCM API Key>", "<registration id>");
/// builder.dry_run(true);
/// let message = builder.finalize();
/// ```
#[derive(Debug)]
pub struct MessageBuilder<'a> {
    api_key: &'a str,
    collapse_key: Option<&'a str>,
    content_available: Option<bool>,
    data: Option<Value>,
    delay_while_idle: Option<bool>,
    dry_run: Option<bool>,
    notification: Option<Notification<'a>>,
    priority: Option<Priority>,
    registration_ids: Option<Vec<Cow<'a, str>>>,
    restricted_package_name: Option<&'a str>,
    time_to_live: Option<i32>,
    to: Option<&'a str>,
}

impl<'a> MessageBuilder<'a> {
    /// Get a new instance of Message. You need to supply to.
    pub fn new(api_key: &'a str, to: &'a str) -> Self {
        MessageBuilder {
            api_key: api_key,
            to: Some(to),
            registration_ids: None,
            collapse_key: None,
            priority: None,
            content_available: None,
            delay_while_idle: None,
            time_to_live: None,
            restricted_package_name: None,
            dry_run: None,
            data: None,
            notification: None,
        }
    }

    /// Get a new instance of Message. You need to supply registration ids.
    pub fn new_multi<S>(api_key: &'a str, ids: &'a [S]) -> Self
        where
            S: Into<Cow<'a, str>> + AsRef<str>,
    {
        let converted = ids.iter().map(|a| a.as_ref().into()).collect();

        MessageBuilder {
            api_key: api_key,
            to: None,
            registration_ids: Some(converted),
            collapse_key: None,
            priority: None,
            content_available: None,
            delay_while_idle: None,
            time_to_live: None,
            restricted_package_name: None,
            dry_run: None,
            data: None,
            notification: None,
        }
    }

    /// String value to replace format specifiers in the body string.
    pub fn registration_ids<S>(&mut self, ids: &'a [S]) -> &mut Self
        where
            S: Into<Cow<'a, str>> + AsRef<str>,
    {
        let converted = ids.iter().map(|a| a.as_ref().into()).collect();

        self.registration_ids = Some(converted);
        self
    }

    /// Set this parameter to identify groups of messages that can be collapsed.
    pub fn collapse_key(&mut self, collapse_key: &'a str) -> &mut Self {
        self.collapse_key = Some(collapse_key);
        self
    }

    /// Set the priority of the message. You can set Normal or High priorities.
    /// # Examples:
    /// ```rust
    /// use fcm::{MessageBuilder, Priority};
    ///
    /// let mut builder = MessageBuilder::new("<FCM API Key>", "<registration id>");
    /// builder.priority(Priority::High);
    /// let message = builder.finalize();
    /// ```
    pub fn priority(&mut self, priority: Priority) -> &mut Self {
        self.priority = Some(priority);
        self
    }

    /// To set the `content-available` field on iOS
    pub fn content_available(&mut self, content_available: bool) -> &mut Self {
        self.content_available = Some(content_available);
        self
    }

    /// When set to `true`, sends the message only when the device is active.
    pub fn delay_while_idle(&mut self, delay_while_idle: bool) -> &mut Self {
        self.delay_while_idle = Some(delay_while_idle);
        self
    }

    /// How long (in seconds) to keep the message on FCM servers in case the device
    /// is offline. The maximum and default is 4 weeks.
    pub fn time_to_live(&mut self, time_to_live: i32) -> &mut Self {
        self.time_to_live = Some(time_to_live);
        self
    }

    /// Package name of the application where the registration tokens must match.
    pub fn restricted_package_name(&mut self, restricted_package_name: &'a str) -> &mut Self {
        self.restricted_package_name = Some(restricted_package_name);
        self
    }

    /// When set to `true`, allows you to test FCM without actually sending the message.
    pub fn dry_run(&mut self, dry_run: bool) -> &mut Self {
        self.dry_run = Some(dry_run);
        self
    }

    /// Use this to add custom key-value pairs to the message. This data
    /// must be handled appropriately on the client end. The data can be
    /// anything that Serde can serialize to JSON.
    ///
    /// # Examples:
    /// ```rust
    /// use fcm::MessageBuilder;
    /// use std::collections::HashMap;
    ///
    /// let mut map = HashMap::new();
    /// map.insert("message", "Howdy!");
    ///
    /// let mut builder = MessageBuilder::new("<FCM API Key>", "<registration id>");
    /// builder.data(&map);
    /// let message = builder.finalize();
    /// ```
    pub fn data(&mut self, data: &dyn Serialize) -> Result<&mut Self, serde_json::Error> {
        self.data = Some(serde_json::to_value(data)?);
        Ok(self)
    }

    /// Use this to set a `Notification` for the message.
    /// # Examples:
    /// ```rust
    /// use fcm::{MessageBuilder, NotificationBuilder};
    ///
    /// let mut builder = NotificationBuilder::new();
    /// builder.title("Hey!");
    /// builder.body("Do you want to catch up later?");
    /// let notification = builder.finalize();
    ///
    /// let mut builder = MessageBuilder::new("<FCM API Key>", "<registration id>");
    /// builder.notification(notification);
    /// let message = builder.finalize();
    /// ```
    pub fn notification(&mut self, notification: Notification<'a>) -> &mut Self {
        self.notification = Some(notification);
        self
    }

    /// Complete the build and get a `Message` instance
    pub fn finalize(self) -> Message<'a> {
        Message {
            api_key: self.api_key,
            body: MessageBody {
                to: self.to,
                registration_ids: self.registration_ids,
                collapse_key: self.collapse_key,
                priority: self.priority,
                content_available: self.content_available,
                delay_while_idle: self.delay_while_idle,
                time_to_live: self.time_to_live,
                restricted_package_name: self.restricted_package_name,
                dry_run: self.dry_run,
                data: self.data.clone(),
                notification: self.notification,
            },
        }
    }
}
