use super::*;

fn limits(per_ip: usize, total: usize, legacy: LegacyRegistration) -> ServerLimits {
    let nonzero = |n| NonZeroUsize::new(n).unwrap();
    ServerLimits {
        provisional_per_ip: nonzero(per_ip),
        provisional_total: nonzero(total),
        legacy_registration: legacy,
        outbound_queued_per_stream: nonzero(1_000),
        outbound_queued_total: nonzero(10_000),
        group_mail: GroupMailLimits {
            max_age: std::time::Duration::from_secs(60),
            max_messages: nonzero(8),
            max_bytes: nonzero(1 << 20),
        },
    }
}

fn ip(last: u8) -> IpAddr {
    IpAddr::from([10, 0, 0, last])
}

#[test]
fn an_address_is_held_up_to_its_limit_and_others_still_are() {
    let limits = limits(2, 10, LegacyRegistration::Refused);
    let held = [ip(1), ip(1), ip(2)];
    let code = admit_provisional(&limits, ip(1), held.into_iter())
        .unwrap_err()
        .code;
    assert_eq!(code, ErrorCode::ProvisionalPerIpAtCap);
    assert!(admit_provisional(&limits, ip(2), held.into_iter()).is_ok());
    assert!(admit_provisional(&limits, ip(3), held.into_iter()).is_ok());
}

#[test]
fn no_address_is_held_past_the_total() {
    let limits = limits(10, 3, LegacyRegistration::Refused);
    let held = [ip(1), ip(2), ip(3)];
    let code = admit_provisional(&limits, ip(4), held.into_iter())
        .unwrap_err()
        .code;
    assert_eq!(code, ErrorCode::ProvisionalTotalAtCap);
}

#[test]
fn a_server_that_refuses_legacy_registration_gives_no_turn() {
    let load = ServerLoad::new(limits(1, 1, LegacyRegistration::Refused));
    let code = load.legacy_hash_turn().err().unwrap().code;
    assert_eq!(code, ErrorCode::LegacyRegistrationRefused);
}

#[test]
fn legacy_hashes_take_turns_up_to_the_limit() {
    let two = NonZeroUsize::new(2).unwrap();
    let load = ServerLoad::new(limits(
        1,
        1,
        LegacyRegistration::Accepted {
            concurrent_hashes: two,
        },
    ));
    let first = load.legacy_hash_turn().unwrap();
    let _second = load.legacy_hash_turn().unwrap();
    let code = load.legacy_hash_turn().err().unwrap().code;
    assert_eq!(code, ErrorCode::LegacyRegistrationBusy);
    drop(first);
    assert!(
        load.legacy_hash_turn().is_ok(),
        "an ended turn was not returned"
    );
}
