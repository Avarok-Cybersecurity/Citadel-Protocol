//! A punch reports what it did beside its socket (S-W4): the attempt that punched, the bound it
//! ran under, how long it took, and the NAT it identified.

use super::{PunchBudget, UdpHolePuncher, MAX_RETRIES};
use crate::udp_traversal::linear::encrypted_config_container::identity_for_tests;
use citadel_io::tokio;
use netbeam::sync::test_utils::create_streams_with_addrs_and_lag;
use std::time::Duration;

#[tokio::test]
async fn a_punch_reports_its_attempt_duration_and_nat() {
    citadel_logging::setup_log();
    let (a, b) = create_streams_with_addrs_and_lag(0).await;
    let punch = |endpoint| {
        UdpHolePuncher::new(
            endpoint,
            identity_for_tests(),
            crate::stun_servers::unanswered_loopback(),
            PunchBudget::per_attempt(Duration::from_secs(4)),
        )
        .reported()
    };
    let (res_a, res_b) = tokio::join!(punch(&a), punch(&b));
    for punched in [res_a.expect("A punched"), res_b.expect("B punched")] {
        let report = punched.report;
        assert!((1..=MAX_RETRIES).contains(&report.attempt), "{report:?}");
        assert_eq!(report.attempts_allowed, MAX_RETRIES);
        assert!(report.elapsed > Duration::ZERO, "{report:?}");
        let identified = crate::nat_identification::NatType::offline().class();
        assert_eq!(report.local_nat, identified, "the NAT the punch identified");
    }
}
