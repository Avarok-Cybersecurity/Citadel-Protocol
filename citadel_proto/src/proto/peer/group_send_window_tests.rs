use super::*;
use citadel_io::tokio;
use proptest::prelude::*;

fn taken(window: &Arc<SendWindow>) -> Credit {
    window.try_take().unwrap().expect("a free place")
}

#[test]
fn a_full_window_turns_the_next_sender_away_until_an_answer() {
    let window = SendWindow::new(2);
    taken(&window).written();
    taken(&window).written();
    assert!(window.try_take().unwrap().is_none());
    assert!(window.answered());
    taken(&window).written();
    assert_eq!(window.unanswered(), 2);
}

#[test]
fn a_credit_dropped_unwritten_returns_its_place() {
    let window = SendWindow::new(1);
    let credit = taken(&window);
    assert_eq!(window.free(), 0);
    drop(credit);
    assert_eq!(window.free(), 1);
    assert_eq!(window.unanswered(), 0);
}

#[test]
fn an_answer_with_nothing_unanswered_frees_nothing() {
    let window = SendWindow::new(2);
    assert!(!window.answered());
    assert_eq!(window.free(), 2);
}

#[test]
fn a_second_answer_for_one_message_frees_nothing_more() {
    let window = SendWindow::new(2);
    taken(&window).written();
    assert!(window.answered());
    assert!(!window.answered());
    assert_eq!(window.free(), 2);
}

#[tokio::test]
async fn one_sender_past_the_window_waits_and_the_rest_go() {
    const SIZE: usize = 4;
    let window = SendWindow::new(SIZE);
    let mut senders = tokio::task::JoinSet::new();
    for _ in 0..=SIZE {
        let window = window.clone();
        senders.spawn(async move { window.take().await.map(Credit::written) });
    }
    for _ in 0..SIZE {
        senders.join_next().await.unwrap().unwrap().unwrap();
    }
    tokio::task::yield_now().await;
    assert_eq!(senders.len(), 1, "the sender past the window went");
    assert!(window.answered());
    senders.join_next().await.unwrap().unwrap().unwrap();
    assert_eq!(window.unanswered(), SIZE);
}

#[tokio::test]
async fn closing_refuses_a_waiting_sender_and_every_later_one() {
    let window = SendWindow::new(1);
    taken(&window).written();
    let waiting = tokio::spawn({
        let window = window.clone();
        async move { window.take().await.map(|_| ()) }
    });
    tokio::task::yield_now().await;
    window.close();
    assert!(window.try_take().is_err(), "a closed window gave a place");
    assert_eq!(waiting.await.unwrap(), Err(WindowClosed));
    assert!(window.take().await.is_err());
}

#[tokio::test]
async fn a_sender_that_gives_up_waiting_takes_nothing() {
    let window = SendWindow::new(1);
    taken(&window).written();
    let waiting = tokio::spawn({
        let window = window.clone();
        async move { window.take().await.map(|_| ()) }
    });
    tokio::task::yield_now().await;
    waiting.abort();
    let _ = waiting.await;
    assert_eq!(
        window.unanswered(),
        1,
        "a sender that gave up left a place taken"
    );
    assert!(window.answered());
    assert_eq!(window.free(), 1);
    assert!(window.try_take().unwrap().is_some());
}

/// Senders to two groups share one window: a place goes to whoever asked first, so a sender to
/// one group is never passed over while another group's senders keep asking.
#[tokio::test]
async fn places_go_in_the_order_asked_whichever_group_asks() {
    let window = SendWindow::new(1);
    taken(&window).written();
    let (tx, mut order) = tokio::sync::mpsc::unbounded_channel();
    let mut senders = Vec::new();
    for group in ["a1", "a2", "b1", "a3"] {
        let (window, tx) = (window.clone(), tx.clone());
        senders.push(tokio::spawn(async move {
            window.take().await.unwrap().written();
            tx.send(group).unwrap();
        }));
        // Each sender is queued before the next asks.
        tokio::task::yield_now().await;
    }
    for expected in ["a1", "a2", "b1"] {
        assert!(window.answered());
        assert_eq!(order.recv().await, Some(expected));
    }
    assert!(order.try_recv().is_err(), "a sender went without a place");
    assert!(window.answered());
    assert_eq!(order.recv().await, Some("a3"));
    for sender in senders {
        sender.await.unwrap();
    }
}

#[derive(Debug, Clone)]
enum Step {
    Take,
    Write,
    Drop,
    Answer,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        Just(Step::Take),
        Just(Step::Write),
        Just(Step::Drop),
        Just(Step::Answer)
    ]
}

proptest! {
    /// Whatever happens, every place is free, held by an unwritten message, or unanswered, and
    /// no more are unanswered than the window holds.
    #[test]
    fn places_are_never_lost_or_made(size in 1usize..8, steps in prop::collection::vec(step(), 0..200)) {
        let window = SendWindow::new(size);
        let mut held = Vec::new();
        for step in steps {
            match step {
                Step::Take => held.extend(window.try_take().unwrap()),
                Step::Write => if let Some(credit) = held.pop() { credit.written() },
                Step::Drop => drop(held.pop()),
                Step::Answer => { let _ = window.answered(); }
            }
            prop_assert!(window.unanswered() <= size);
            prop_assert_eq!(window.free() + held.len() + window.unanswered(), size);
        }
    }
}
