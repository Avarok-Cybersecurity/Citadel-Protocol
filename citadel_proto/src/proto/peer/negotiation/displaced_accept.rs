//! A dial made while this side's accept of the peer's offer is still being exchanged.
//!
//! Both are offers for the same link, so both are recorded in the one attempt slot a peer has.
//! The dial used to replace the accept there, and R-DIAL 3 then judged the exchange the accept
//! started against the dial's offer: a dial stronger than the accepted offer refused the very
//! exchange this side had agreed to. The peer, mid-exchange, had set the dial aside for that
//! exchange to answer, so nothing was left and neither side connected.
//!
//! The dial still takes the slot, but it keeps the accept it displaced. An exchange is judged
//! against the offer it answers: the accept's own exchange against the accept, anything else
//! against the dial. When the accept's exchange makes the link, the dial is answered by it --
//! with the channel when the link meets the dial's offer, and refused when it falls short, so a
//! dial is never connected below its offer. The link the accept agreed to stands either way.
//! Pure: the callers hold the state and do the sending.

use crate::proto::peer::negotiation::refusal::below_policy_error;
use crate::proto::remote::Ticket;
use crate::proto::state_container::{AcceptRecord, OutgoingPeerConnectionAttempt};
use citadel_types::proto::{falls_short_of, SessionSecuritySettings};

/// The attempt slot after this side sends a dial (`accept: false`) or an accept on `ticket`.
pub(crate) fn record(
    previous: Option<OutgoingPeerConnectionAttempt>,
    ticket: Ticket,
    session_security_settings: SessionSecuritySettings,
    accept: bool,
) -> OutgoingPeerConnectionAttempt {
    let displaced_accept = if accept {
        None
    } else {
        previous.and_then(|previous| {
            if previous.accept {
                Some(AcceptRecord {
                    ticket: previous.ticket,
                    session_security_settings: previous.session_security_settings,
                })
            } else {
                previous.displaced_accept
            }
        })
    };
    OutgoingPeerConnectionAttempt {
        ticket,
        session_security_settings,
        accept,
        displaced_accept,
    }
}

/// The accept `attempt` displaced, when `exchange` is that accept's exchange.
fn answered_accept(
    attempt: &OutgoingPeerConnectionAttempt,
    exchange: Ticket,
) -> Option<AcceptRecord> {
    attempt
        .displaced_accept
        .filter(|accept| accept.ticket == exchange)
}

/// This side's offer for the exchange on `exchange`: what R-DIAL 3 judges its stamp against.
pub(crate) fn offer_answered(
    attempt: &OutgoingPeerConnectionAttempt,
    exchange: Ticket,
) -> SessionSecuritySettings {
    answered_accept(attempt, exchange).map_or(attempt.session_security_settings, |accept| {
        accept.session_security_settings
    })
}

/// Who a link built by the exchange on `exchange`, at `link`, is delivered to.
#[derive(Debug)]
pub(crate) struct Delivery {
    /// The offer the channel is delivered on (its ticket) and for.
    pub channel_to: OutgoingPeerConnectionAttempt,
    /// A dial the link falls short of: its ticket and the refusal it is answered with.
    pub refused_dial: Option<(Ticket, String)>,
}

pub(crate) fn deliver(
    attempt: OutgoingPeerConnectionAttempt,
    exchange: Option<Ticket>,
    link: SessionSecuritySettings,
) -> Delivery {
    let accept = exchange.and_then(|exchange| answered_accept(&attempt, exchange));
    match accept {
        Some(accept) if falls_short_of(link, attempt.session_security_settings) => Delivery {
            channel_to: OutgoingPeerConnectionAttempt {
                ticket: accept.ticket,
                session_security_settings: accept.session_security_settings,
                accept: true,
                displaced_accept: None,
            },
            refused_dial: Some((
                attempt.ticket,
                below_policy_error(link, attempt.session_security_settings),
            )),
        },
        _ => Delivery {
            channel_to: attempt,
            refused_dial: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::misc::session_security_settings::SessionSecuritySettingsBuilder;
    use citadel_types::crypto::SecurityLevel;

    const ACCEPT: Ticket = Ticket(1);
    const DIAL: Ticket = Ticket(2);
    const OTHER: Ticket = Ticket(3);

    fn at(level: SecurityLevel) -> SessionSecuritySettings {
        SessionSecuritySettingsBuilder::default()
            .with_security_level(level)
            .build()
            .unwrap()
    }

    fn level(settings: SessionSecuritySettings) -> u8 {
        settings.security_level.value()
    }

    /// This side accepted the peer's Standard offer, then dialled at `dial`.
    fn accept_then_dial(dial: SecurityLevel) -> OutgoingPeerConnectionAttempt {
        let accepted = record(None, ACCEPT, at(SecurityLevel::Standard), true);
        record(Some(accepted), DIAL, at(dial), false)
    }

    #[test]
    fn a_dial_keeps_the_accept_it_displaced() {
        let attempt = accept_then_dial(SecurityLevel::High);
        assert_eq!(attempt.ticket, DIAL);
        assert!(!attempt.accept);
        assert_eq!(attempt.displaced_accept.map(|a| a.ticket), Some(ACCEPT));
    }

    #[test]
    fn the_accepts_exchange_is_judged_against_the_accept() {
        let attempt = accept_then_dial(SecurityLevel::High);
        assert_eq!(level(offer_answered(&attempt, ACCEPT)), 0);
        assert_eq!(level(offer_answered(&attempt, DIAL)), 2);
        assert_eq!(
            level(offer_answered(&attempt, OTHER)),
            2,
            "an exchange that is not the accept's answers the dial"
        );
    }

    #[test]
    fn a_link_below_the_dial_goes_to_the_accept_and_refuses_the_dial() {
        let attempt = accept_then_dial(SecurityLevel::High);
        let delivery = deliver(attempt, Some(ACCEPT), at(SecurityLevel::Standard));
        assert_eq!(delivery.channel_to.ticket, ACCEPT);
        assert_eq!(level(delivery.channel_to.session_security_settings), 0);
        let (refused, error) = delivery.refused_dial.expect("the dial is answered");
        assert_eq!(refused, DIAL);
        assert!(error.starts_with("BelowPolicy"), "{error}");
    }

    #[test]
    fn a_link_that_meets_the_dial_answers_the_dial() {
        let attempt = accept_then_dial(SecurityLevel::Standard);
        let delivery = deliver(attempt, Some(ACCEPT), at(SecurityLevel::Standard));
        assert_eq!(delivery.channel_to.ticket, DIAL);
        assert!(delivery.refused_dial.is_none());
    }

    #[test]
    fn the_dials_own_exchange_is_delivered_to_the_dial() {
        let attempt = accept_then_dial(SecurityLevel::High);
        let delivery = deliver(attempt, Some(DIAL), at(SecurityLevel::High));
        assert_eq!(delivery.channel_to.ticket, DIAL);
        assert!(delivery.refused_dial.is_none());
    }

    #[test]
    fn an_accept_or_a_plain_dial_displaces_nothing() {
        let dialled = record(None, DIAL, at(SecurityLevel::High), false);
        assert!(dialled.displaced_accept.is_none());
        let redialled = record(Some(dialled), OTHER, at(SecurityLevel::High), false);
        assert!(redialled.displaced_accept.is_none());
        let accepted = record(
            Some(accept_then_dial(SecurityLevel::High)),
            OTHER,
            at(SecurityLevel::Standard),
            true,
        );
        assert!(accepted.accept);
        assert!(accepted.displaced_accept.is_none());
    }

    #[test]
    fn a_redial_still_carries_the_displaced_accept() {
        let redialled = record(
            Some(accept_then_dial(SecurityLevel::High)),
            OTHER,
            at(SecurityLevel::Extreme),
            false,
        );
        assert_eq!(redialled.displaced_accept.map(|a| a.ticket), Some(ACCEPT));
    }
}
