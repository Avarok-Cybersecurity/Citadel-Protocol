use super::*;

fn limits(max_message_bytes: u32, max_bytes: u64) -> GroupLogLimits {
    GroupLogLimits {
        max_age: Duration::from_secs(60),
        max_messages: 10,
        max_bytes,
        max_message_bytes,
    }
}

#[test]
fn limits_that_carry_the_minimum_body_are_accepted() {
    let min = GroupLogLimits::MIN_MESSAGE_BYTES;
    assert_eq!(limits(min, u64::from(min)).validate(), Ok(()));
}

#[test]
fn limits_below_the_minimum_body_are_refused() {
    let min = GroupLogLimits::MIN_MESSAGE_BYTES;
    assert_eq!(
        limits(min - 1, u64::from(min)).validate(),
        Err(GroupReplayRefusal::TooSmall)
    );
    assert_eq!(
        limits(min, u64::from(min) - 1).validate(),
        Err(GroupReplayRefusal::TooSmall)
    );
    let mut none_kept = limits(min, u64::from(min));
    none_kept.max_messages = 0;
    assert_eq!(none_kept.validate(), Err(GroupReplayRefusal::TooSmall));
    let mut no_age = limits(min, u64::from(min));
    no_age.max_age = Duration::ZERO;
    assert_eq!(no_age.validate(), Err(GroupReplayRefusal::TooSmall));
}

#[test]
fn a_groups_limits_are_held_to_the_servers() {
    let asked = GroupLogLimits {
        max_age: Duration::from_secs(100),
        max_messages: 5,
        max_bytes: 1_000_000,
        max_message_bytes: 40_000,
    };
    let server = GroupLogLimits {
        max_age: Duration::from_secs(10),
        max_messages: 50,
        max_bytes: 500_000,
        max_message_bytes: 30_000,
    };
    let held = asked.clamped_to(&server);
    assert_eq!(held.max_age, Duration::from_secs(10));
    assert_eq!(held.max_messages, 5);
    assert_eq!(held.max_bytes, 500_000);
    assert_eq!(held.max_message_bytes, 30_000);
}

#[test]
fn message_ids_are_fresh() {
    assert_ne!(GroupMessageId::random(), GroupMessageId::random());
}
