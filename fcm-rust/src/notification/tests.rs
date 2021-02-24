use serde_json;
use std::borrow::Cow;
use crate::NotificationBuilder;

#[test]
fn should_be_able_to_render_a_full_notification_to_json() {
    let mut builder = NotificationBuilder::new();

    builder
        .title("foo")
        .body("bar")
        .icon("gif")
        .sound("pling")
        .badge("12")
        .tag("spook")
        .color("#666666")
        .click_action("spam")
        .body_loc_key("PLAY")
        .body_loc_args(&["foo", "bar"])
        .title_loc_key("PAUSE")
        .title_loc_args(&["omg", "lol"]);

    let payload = serde_json::to_string(&builder.finalize()).unwrap();

    let expected_payload = json!({
        "badge": "12",
        "body": "bar",
        "body_loc_args": ["foo", "bar"],
        "body_loc_key": "PLAY",
        "click_action": "spam",
        "color": "#666666",
        "icon": "gif",
        "sound": "pling",
        "tag": "spook",
        "title": "foo",
        "title_loc_args": ["omg", "lol"],
        "title_loc_key": "PAUSE"
    })
    .to_string();

    assert_eq!(expected_payload, payload);
}

#[test]
fn should_set_notification_title() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.title, None);

    let mut builder = NotificationBuilder::new();
    builder.title("title");
    let nm = builder.finalize();

    assert_eq!(nm.title, Some("title"));
}

#[test]
fn should_set_notification_body() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.body, None);

    let mut builder = NotificationBuilder::new();
    builder.body("body");
    let nm = builder.finalize();

    assert_eq!(nm.body, Some("body"));
}

#[test]
fn should_set_notification_icon() {
    let mut builder = NotificationBuilder::new();
    builder.icon("newicon");
    let nm = builder.finalize();

    assert_eq!(nm.icon, Some("newicon"));
}

#[test]
fn should_set_notification_sound() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.sound, None);

    let mut builder = NotificationBuilder::new();
    builder.sound("sound.wav");
    let nm = builder.finalize();

    assert_eq!(nm.sound, Some("sound.wav"));
}

#[test]
fn should_set_notification_badge() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.badge, None);

    let mut builder = NotificationBuilder::new();
    builder.badge("1");
    let nm = builder.finalize();

    assert_eq!(nm.badge, Some("1"));
}

#[test]
fn should_set_notification_tag() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.tag, None);

    let mut builder = NotificationBuilder::new();
    builder.tag("tag");
    let nm = builder.finalize();

    assert_eq!(nm.tag, Some("tag"));
}

#[test]
fn should_set_notification_color() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.color, None);

    let mut builder = NotificationBuilder::new();
    builder.color("color");
    let nm = builder.finalize();

    assert_eq!(nm.color, Some("color"));
}

#[test]
fn should_set_notification_click_action() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.click_action, None);

    let mut builder = NotificationBuilder::new();
    builder.click_action("action");
    let nm = builder.finalize();

    assert_eq!(nm.click_action, Some("action"));
}

#[test]
fn should_set_notification_body_loc_key() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.body_loc_key, None);

    let mut builder = NotificationBuilder::new();
    builder.body_loc_key("key");
    let nm = builder.finalize();

    assert_eq!(nm.body_loc_key, Some("key"));
}

#[test]
fn should_set_notification_body_loc_args() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.body_loc_args, None);

    let mut builder = NotificationBuilder::new();
    builder.body_loc_args(&["args"]);
    let nm = builder.finalize();

    assert_eq!(nm.body_loc_args, Some(vec![Cow::from("args")]));
}

#[test]
fn should_set_notification_title_loc_key() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.title_loc_key, None);

    let mut builder = NotificationBuilder::new();
    builder.title_loc_key("key");
    let nm = builder.finalize();

    assert_eq!(nm.title_loc_key, Some("key"));
}

#[test]
fn should_set_notification_title_loc_args() {
    let nm = NotificationBuilder::new().finalize();

    assert_eq!(nm.title_loc_args, None);

    let mut builder = NotificationBuilder::new();
    builder.title_loc_args(&["args"]);
    let nm = builder.finalize();

    assert_eq!(nm.title_loc_args, Some(vec![Cow::from("args")]));
}
