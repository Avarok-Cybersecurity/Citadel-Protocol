use super::*;

fn refused(servers: &[&str]) -> StunServersError {
    StunServers::new(servers.iter().copied()).expect_err("the list must be refused")
}

#[test]
fn an_absent_list_is_refused_with_no_default() {
    assert_eq!(StunServers::required(None), Err(StunServersError::Missing));
}

#[test]
fn three_distinct_endpoints_are_accepted_in_order() {
    let list = ["stun.example.com:3478", "127.0.0.1:3479", "[::1]:3480"];
    let servers = StunServers::new(list).unwrap();
    assert_eq!(servers.as_slice(), list);
    let more = StunServers::new(["a.example:1", "b.example:2", "c.example:3", "d.example:4"]);
    assert_eq!(more.unwrap().as_slice().len(), 4, "more than three is fine");
}

#[test]
fn fewer_than_three_is_refused() {
    assert_eq!(
        refused(&["a.example:1", "b.example:2"]),
        StunServersError::TooFew { distinct: 2 }
    );
    assert_eq!(refused(&[]), StunServersError::TooFew { distinct: 0 });
}

#[test]
fn a_repeated_endpoint_is_refused() {
    assert_eq!(
        refused(&["a.example:1", "b.example:2", "a.example:1"]),
        StunServersError::Duplicate {
            entry: "a.example:1".into()
        }
    );
    // Host names compare case-insensitively; IP literals by address.
    assert_eq!(
        refused(&["A.example:1", "b.example:2", "a.EXAMPLE:1"]),
        StunServersError::Duplicate {
            entry: "a.EXAMPLE:1".into()
        }
    );
    assert!(matches!(
        refused(&["127.0.0.1:1", "b.example:2", "127.0.0.1:1"]),
        StunServersError::Duplicate { .. }
    ));
    // The same host on another port is another endpoint.
    assert!(StunServers::new(["a.example:1", "a.example:2", "a.example:3"]).is_ok());
}

#[test]
fn an_unparseable_endpoint_is_refused() {
    for bad in [
        "stun.example.com",
        "stun.example.com:",
        "stun.example.com:0",
        "stun.example.com:65536",
        "stun:stun.example.com:3478",
        "::1:3478",
        ":3478",
        " stun.example.com:3478",
        "stun.example.com:3478/path",
        "user@stun.example.com:3478",
        "-bad.example:3478",
        "a..example:3478",
        "127.0.0.1:0",
    ] {
        let err = refused(&[bad, "b.example:2", "c.example:3"]);
        assert!(
            matches!(&err, StunServersError::Unparseable { entry, .. } if entry == bad),
            "{bad:?} must be unparseable, got {err:?}"
        );
    }
}

#[test]
fn every_refusal_explains_itself() {
    for err in [
        StunServersError::Missing,
        refused(&["a.example:1"]),
        refused(&["a.example:1", "a.example:1", "b.example:1"]),
        refused(&["nope", "a.example:1", "b.example:1"]),
    ] {
        assert!(!err.to_string().is_empty());
    }
    assert!(StunServersError::Missing.to_string().contains("required"));
}

#[test]
fn a_comma_separated_spec_parses_like_a_list() {
    let servers: StunServers = "a.example:1,b.example:2,127.0.0.1:3".parse().unwrap();
    assert_eq!(
        servers.as_slice(),
        ["a.example:1", "b.example:2", "127.0.0.1:3"]
    );
    assert_eq!("".parse::<StunServers>(), Err(StunServersError::Missing));
    assert!(matches!(
        "a.example:1, b.example:2,c.example:3".parse::<StunServers>(),
        Err(StunServersError::Unparseable { .. })
    ));
    let round_trip: Vec<String> = servers.clone().into();
    assert_eq!(StunServers::new(round_trip).unwrap(), servers);
}
