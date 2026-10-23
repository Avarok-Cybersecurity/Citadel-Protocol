//! A server's path policy, as its clients see it.
//!
//! The server sends its [`PathPolicy`] in connect SUCCESS to each client at
//! [`PATH_POLICY_SINCE`] or later, and the client surfaces it on `ConnectSuccess`. Neither side
//! sends to, or reads from, a node below that version.
use crate::constants::{protocol_version_at_least, PATH_POLICY_SINCE};
use citadel_types::proto::PathPolicy;

/// `policy` if the adjacent node at `adjacent_version` takes part in path policies, else `None`.
/// Applied both to what is sent to it and to what is read from it.
pub(crate) fn exchanged_with(
    adjacent_version: Option<u32>,
    policy: Option<PathPolicy>,
) -> Option<PathPolicy> {
    policy.filter(|_| protocol_version_at_least(adjacent_version, PATH_POLICY_SINCE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PROTOCOL_VERSION;
    use citadel_types::proto::{PathClasses, PathKind, PathRule};
    use embedded_semver::Semver;
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
    fn connect_success_carries_the_policy_and_reads_in_both_directions() {
        use crate::proto::packet_crafter::do_connect::DoConnectFinalStatusPacket;
        use citadel_user::external_services::ServicesObject;
        use citadel_user::serialization::SyncIO;
        /// SUCCESS as a server at 0.12.1 sends it.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Older<'a> {
            mailbox: Option<crate::proto::peer::peer_layer::MailboxTransfer>,
            peers: Vec<citadel_types::user::MutualPeer>,
            post_login_object: ServicesObject,
            #[serde(borrow)]
            message: &'a [u8],
            resume_token: Option<crate::proto::session_resume::ResumeToken>,
            admission_challenge: Option<citadel_user::auth::pq::admission::AdmissionChallenge>,
        }
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
        let by_older = Older::deserialize_from_vector(&bytes).unwrap();
        assert_eq!(
            by_older.message, b"welcome",
            "an older client lost the message"
        );

        let older = Older {
            mailbox: None,
            peers: Vec::new(),
            post_login_object: ServicesObject::default(),
            message: b"welcome",
            resume_token: None,
            admission_challenge: None,
        };
        let from_older = older.serialize_to_vector().unwrap();
        let read = DoConnectFinalStatusPacket::deserialize_from_vector(&from_older).unwrap();
        assert_eq!(read.path_policy, None, "an absent policy appeared");
    }

    #[test]
    fn only_a_node_at_the_version_exchanges_a_policy() {
        let older = Some(Semver::new(0, 12, 1).to_u32().unwrap());
        assert_eq!(exchanged_with(older, Some(policy())), None);
        assert_eq!(exchanged_with(None, Some(policy())), None);
        assert_eq!(
            exchanged_with(Some(*PROTOCOL_VERSION), Some(policy())),
            Some(policy())
        );
    }
}
