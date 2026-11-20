//! A clock the test moves by hand, and nodes on it. A node on a clock nobody moves never reaches
//! a managed deadline: test setup run on it (a registration, a login) cannot race a real
//! deadline however slow the host is, and only the step under test meets one.

use crate::prefabs::server::empty::EmptyKernel;
use crate::prelude::link::{BoxFuture, Clock, Millis};
use crate::prelude::*;
use citadel_io::tokio::sync::watch;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Time that moves only when the test says so. Every managed deadline reads it.
pub struct ManualClock {
    now: watch::Sender<u64>,
}

impl ManualClock {
    pub fn new() -> Arc<Self> {
        Arc::new(ManualClock {
            now: watch::Sender::new(0),
        })
    }

    pub fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_millis()).unwrap();
        self.now.send_modify(|now| *now += by);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Millis {
        Millis(*self.now.borrow())
    }

    fn sleep_until(&self, at: Millis) -> BoxFuture<'static, ()> {
        let mut now = self.now.subscribe();
        Box::pin(async move {
            if now.wait_for(|now| *now >= at.0).await.is_err() {
                // The clock is gone: its time never comes.
                std::future::pending::<()>().await;
            }
        })
    }
}

/// A managed node's mode, on `clock`, under the test link policy (whose reattach grace, the
/// owner's 5 minutes, these tests never reach).
pub fn managed(clock: Arc<ManualClock>) -> LinkManagerMode {
    let policy = super::localhost_link_policy();
    LinkManagerMode::Managed(ManagedLinks::new(clock, policy).unwrap())
}

/// A test server on `clock`: it ends a provisional session only when the test moves the clock.
pub fn server_on<'a, R: Ratchet>(
    clock: Arc<ManualClock>,
) -> (NodeFuture<'a, EmptyKernel<R>>, SocketAddr) {
    super::server_test_node(EmptyKernel::default(), move |builder| {
        let _ = builder.with_link_manager(managed(clock));
    })
}
