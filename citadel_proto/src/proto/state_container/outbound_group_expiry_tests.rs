use super::*;

fn seen() -> OutboundGroupObservation {
    OutboundGroupObservation {
        behind_another: false,
        header_answered: false,
        header_waited: Duration::ZERO,
        silent: false,
        silent_past_ceiling: false,
        session_silent: false,
    }
}

#[test]
fn an_unanswered_header_is_kept_until_its_deadline() {
    let waiting = OutboundGroupObservation {
        header_waited: FILE_GROUP_HEADER_ACK_DEADLINE - Duration::from_millis(1),
        ..seen()
    };
    assert_eq!(outbound_group_verdict(waiting), OutboundGroupVerdict::Keep);
}

#[test]
fn an_unanswered_header_fails_at_its_deadline_whatever_the_session_carries() {
    let late = OutboundGroupObservation {
        header_waited: FILE_GROUP_HEADER_ACK_DEADLINE,
        session_silent: false,
        ..seen()
    };
    assert_eq!(
        outbound_group_verdict(late),
        OutboundGroupVerdict::HeaderUnanswered
    );
}

#[test]
fn a_header_queued_behind_another_group_is_not_failed() {
    let queued = OutboundGroupObservation {
        behind_another: true,
        header_waited: FILE_GROUP_HEADER_ACK_DEADLINE * 4,
        ..seen()
    };
    assert_eq!(outbound_group_verdict(queued), OutboundGroupVerdict::Keep);
}

#[test]
fn a_header_answered_is_not_held_back_by_an_earlier_group() {
    let answered_but_silent = OutboundGroupObservation {
        behind_another: true,
        header_answered: true,
        silent: true,
        silent_past_ceiling: true,
        ..seen()
    };
    assert_eq!(
        outbound_group_verdict(answered_but_silent),
        OutboundGroupVerdict::Silent
    );
}

#[test]
fn an_answered_group_follows_the_receivers_silence_rule() {
    let answered = OutboundGroupObservation {
        header_answered: true,
        header_waited: FILE_GROUP_HEADER_ACK_DEADLINE * 4,
        ..seen()
    };
    // Answered: the header clock no longer matters.
    assert_eq!(outbound_group_verdict(answered), OutboundGroupVerdict::Keep);
    let silent_on_a_busy_session = OutboundGroupObservation {
        silent: true,
        ..answered
    };
    assert_eq!(
        outbound_group_verdict(silent_on_a_busy_session),
        OutboundGroupVerdict::Keep
    );
    let silent_on_a_silent_session = OutboundGroupObservation {
        silent: true,
        session_silent: true,
        ..answered
    };
    assert_eq!(
        outbound_group_verdict(silent_on_a_silent_session),
        OutboundGroupVerdict::Silent
    );
    let past_the_ceiling = OutboundGroupObservation {
        silent: true,
        silent_past_ceiling: true,
        ..answered
    };
    assert_eq!(
        outbound_group_verdict(past_the_ceiling),
        OutboundGroupVerdict::Silent
    );
}
