//! A server's path policy, as its clients see it.
//!
//! The server sends its [`PathPolicy`](citadel_types::proto::PathPolicy) in connect SUCCESS, and
//! the client surfaces it on `ConnectSuccess`.

#[cfg(test)]
mod tests {
    use citadel_types::proto::{PathClasses, PathKind, PathPolicy, PathRule};
    use std::time::Duration;

    fn policy() -> PathPolicy {
        let rules = PathKind::ALL
            .into_iter()
            .map(|kind| PathRule {
                kind,
                enabled: true,
                attempt_timeout: Duration::from_secs(5),
                cost_weight: 1,
                classes: PathClasses::ALL,
            })
            .collect();
        PathPolicy::new(rules, PathClasses::NONE).unwrap()
    }

    #[test]
    fn connect_success_carries_the_policy() {
        use crate::proto::packet_crafter::do_connect::DoConnectFinalStatusPacket;
        use citadel_user::external_services::ServicesObject;
        use citadel_user::serialization::SyncIO;
        let current = DoConnectFinalStatusPacket {
            mailbox: None,
            peers: Vec::new(),
            post_login_object: ServicesObject::default(),
            message: b"welcome",
            resume_token: None,
            admission_challenge: None,
            path_policy: Some(policy()),
        };
        let bytes = current.serialize_to_vector().unwrap();
        let read = DoConnectFinalStatusPacket::deserialize_from_vector(&bytes).unwrap();
        assert_eq!(read.path_policy, Some(policy()));
    }
}
