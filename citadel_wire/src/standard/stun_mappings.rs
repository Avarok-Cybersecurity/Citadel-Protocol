//! Which STUN observations a NAT identification uses.
//!
//! Identification probes every configured STUN server at once, and needs
//! [`NAT_IDENTIFY_MAPPINGS`] observed mappings to model the NAT. The first that many answers
//! decide it; the rest are dropped unread. A server that is silent, unreachable or answers with
//! an error therefore costs nothing while enough others answer, and the identification no
//! longer waits on its slowest server.

use crate::nat_identification::SocketPair;
use futures::{Stream, StreamExt};
use std::fmt::Display;

/// How many observed mappings [`crate::nat_identification::NatType::new`] models a NAT from.
pub(crate) const NAT_IDENTIFY_MAPPINGS: usize = 3;

/// The first [`NAT_IDENTIFY_MAPPINGS`] mappings `probes` yields, in completion order. A probe
/// that ends without a mapping is skipped. Fails only once `probes` ends with too few.
pub(crate) async fn first_mappings<S, E>(
    mut probes: S,
) -> Result<[SocketPair; NAT_IDENTIFY_MAPPINGS], anyhow::Error>
where
    S: Stream<Item = Result<Option<SocketPair>, E>> + Unpin,
    E: Display,
{
    let mut mappings = Vec::with_capacity(NAT_IDENTIFY_MAPPINGS);
    let mut unanswered = Vec::new();
    while let Some(probe) = probes.next().await {
        match probe {
            Ok(Some(mapping)) => {
                mappings.push(mapping);
                if mappings.len() == NAT_IDENTIFY_MAPPINGS {
                    break;
                }
            }
            Ok(None) => unanswered.push("no mapping in the answer".to_string()),
            Err(err) => unanswered.push(err.to_string()),
        }
    }

    let found = mappings.len();
    mappings.try_into().map_err(|_| {
        anyhow::Error::msg(format!(
            "{found} of the {NAT_IDENTIFY_MAPPINGS} STUN mappings needed; the other servers: {unanswered:?}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{first_mappings, NAT_IDENTIFY_MAPPINGS};
    use crate::nat_identification::{SocketPair, IDENTIFY_TIMEOUT};
    use citadel_io::tokio;
    use futures::stream::{self, StreamExt};
    use std::net::SocketAddr;

    type Probe = Result<Option<SocketPair>, &'static str>;

    fn mapping(port: u16) -> Probe {
        let addr = |p: u16| SocketAddr::from(([203, 0, 113, 9], p));
        Ok(Some(SocketPair {
            internal: addr(port),
            external: addr(port),
        }))
    }

    fn ports(mappings: &[SocketPair]) -> Vec<u16> {
        mappings.iter().map(|m| m.external.port()).collect()
    }

    /// A server that never answers is a stream item that never arrives: identification must
    /// finish on the three that did, without polling past them. The paused clock turns a wait
    /// on the silent server into an immediate `Elapsed` instead of a hung test.
    #[tokio::test(start_paused = true)]
    async fn three_answers_decide_while_a_fourth_server_is_silent() {
        let answered = stream::iter([mapping(1), mapping(2), mapping(3)]);
        let silent = stream::pending::<Probe>();
        let found = tokio::time::timeout(IDENTIFY_TIMEOUT, first_mappings(answered.chain(silent)))
            .await
            .expect("waited on the silent server")
            .unwrap();
        assert_eq!(ports(&found), [1, 2, 3]);
    }

    #[tokio::test]
    async fn failed_and_empty_answers_are_skipped() {
        let probes = stream::iter([Err("refused"), mapping(1), Ok(None), mapping(2), mapping(3)]);
        let found = first_mappings(probes).await.unwrap();
        assert_eq!(ports(&found), [1, 2, 3]);
    }

    #[tokio::test]
    async fn too_few_answers_fail_with_what_the_others_said() {
        let probes = stream::iter([mapping(1), Err("refused"), mapping(2)]);
        let err = first_mappings(probes).await.unwrap_err().to_string();
        assert!(
            err.contains(&format!("2 of the {NAT_IDENTIFY_MAPPINGS}")),
            "{err}"
        );
        assert!(err.contains("refused"), "{err}");
    }
}
