use crate::notification::NotificationBuilder;
use serde_json;
use std::borrow::Cow;
use crate::{MessageBuilder, Priority};

#[test]
fn should_create_new_message() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.to, Some("token"));
}

#[test]
fn should_leave_nones_out_of_the_json() {
    let msg = MessageBuilder::new("api_key", "token").finalize();
    let payload = serde_json::to_string(&msg.body).unwrap();

    let expected_payload = json!({
        "to": "token"
    })
    .to_string();

    assert_eq!(expected_payload, payload);
}

#[test]
fn should_add_custom_data_to_the_payload() {
    let mut builder = MessageBuilder::new("api_key", "token");

    #[derive(Serialize)]
    struct CustomData {
        foo: &'static str,
        bar: bool,
    };

    let data = CustomData {
        foo: "bar",
        bar: false,
    };

    builder.data(&data).unwrap();

    let msg = builder.finalize();
    let payload = serde_json::to_string(&msg.body).unwrap();

    let expected_payload = json!({
        "data": {
            "foo": "bar",
            "bar": false,
        },
        "to": "token"
    })
    .to_string();

    assert_eq!(expected_payload, payload);
}

#[test]
fn should_be_able_to_render_a_full_message_to_json() {
    let mut builder = MessageBuilder::new("api_key", "token");

    builder
        .registration_ids(&["one", "two"])
        .collapse_key("foo")
        .priority(Priority::High)
        .content_available(false)
        .delay_while_idle(true)
        .time_to_live(420)
        .restricted_package_name("pkg")
        .notification(NotificationBuilder::new().finalize())
        .dry_run(false);

    let payload = serde_json::to_string(&builder.finalize().body).unwrap();

    let expected_payload = json!({
        "to": "token",
        "registration_ids": ["one", "two"],
        "collapse_key": "foo",
        "priority": "high",
        "content_available": false,
        "delay_while_idle": true,
        "time_to_live": 420,
        "restricted_package_name": "pkg",
        "dry_run": false,
        "notification": {},
    })
    .to_string();

    assert_eq!(expected_payload, payload);
}

#[test]
fn should_set_registration_ids() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.registration_ids, None);

    let mut builder = MessageBuilder::new("api_key", "token");
    builder.registration_ids(&["id1"]);
    let msg = builder.finalize();

    assert_eq!(msg.body.registration_ids, Some(vec![Cow::from("id1")]));
}

#[test]
fn should_set_collapse_key() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.collapse_key, None);

    let mut builder = MessageBuilder::new("api_key", "token");
    builder.collapse_key("key");
    let msg = builder.finalize();

    assert_eq!(msg.body.collapse_key, Some("key"));
}

#[test]
fn should_set_priority() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.priority, None);

    let mut builder = MessageBuilder::new("api_key", "token");
    builder.priority(Priority::Normal);
    let msg = builder.finalize();

    assert_eq!(msg.body.priority, Some(Priority::Normal));
}

#[test]
fn should_set_content_available() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.content_available, None);

    let mut builder = MessageBuilder::new("api_key", "token");
    builder.content_available(true);
    let msg = builder.finalize();

    assert_eq!(msg.body.content_available, Some(true));
}

#[test]
fn should_set_delay_while_idle() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.delay_while_idle, None);

    let mut builder = MessageBuilder::new("api_key", "token");
    builder.delay_while_idle(true);
    let msg = builder.finalize();

    assert_eq!(msg.body.delay_while_idle, Some(true));
}

#[test]
fn should_set_time_to_live() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.time_to_live, None);

    let mut builder = MessageBuilder::new("api_key", "token");
    builder.time_to_live(10);
    let msg = builder.finalize();

    assert_eq!(msg.body.time_to_live, Some(10));
}

#[test]
fn should_set_restricted_package_name() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.restricted_package_name, None);

    let mut builder = MessageBuilder::new("api_key", "token");
    builder.restricted_package_name("name");
    let msg = builder.finalize();

    assert_eq!(msg.body.restricted_package_name, Some("name"));
}

#[test]
fn should_set_dry_run() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.dry_run, None);

    let mut builder = MessageBuilder::new("api_key", "token");
    builder.dry_run(true);
    let msg = builder.finalize();

    assert_eq!(msg.body.dry_run, Some(true));
}

#[test]
fn should_set_notifications() {
    let msg = MessageBuilder::new("api_key", "token").finalize();

    assert_eq!(msg.body.notification, None);

    let nm = NotificationBuilder::new().finalize();

    let mut builder = MessageBuilder::new("api_key", "token");
    builder.notification(nm);
    let msg = builder.finalize();

    assert!(msg.body.notification != None);
}
