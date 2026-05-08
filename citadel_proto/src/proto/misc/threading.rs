//! Threading Model Abstraction
//!
//! Provides standalone functions for multi-threaded vs single-threaded dispatch
//! with `cfg`-based internal selection. The `multi-threaded` feature determines
//! whether futures are spawned on the runtime (`rt.spawn`) or run within a
//! `LocalSet` (`localset.run_until`).
//!
//! All cfg-gates for the threading model are concentrated in this module so
//! the kernel layer (executor, node) remains feature-agnostic.

use crate::error::NetworkError;
use crate::kernel::kernel_executor::LocalSet;
use crate::kernel::{RuntimeFuture, RuntimeHandle};

/// Create a `LocalSet` if running in single-threaded mode.
///
/// On multi-threaded: returns `None` (futures are spawned on the runtime).
/// On single-threaded: returns `Some(LocalSet::new())` (futures run in a local set).
pub(crate) fn create_localset() -> Option<LocalSet> {
    #[cfg(not(feature = "multi-threaded"))]
    {
        Some(citadel_io::tokio::task::LocalSet::new())
    }

    #[cfg(feature = "multi-threaded")]
    {
        None
    }
}

/// Run the Citadel server future concurrently with the kernel future,
/// using the appropriate mechanism for the current threading model.
///
/// On multi-threaded: spawns `server` on the runtime via `rt.spawn()`.
/// On single-threaded: runs `server` within the provided `LocalSet`.
pub(crate) async fn run_server_with_kernel(
    rt: RuntimeHandle,
    server: impl RuntimeFuture,
    kernel: impl std::future::Future<Output = Result<(), NetworkError>>,
    localset: Option<LocalSet>,
) -> Result<(), NetworkError> {
    #[cfg(feature = "multi-threaded")]
    {
        use crate::proto::misc::panic_future::ExplicitPanicFuture;
        let _ = localset;
        let server_future = ExplicitPanicFuture::new(rt.spawn(server));
        citadel_io::tokio::select! {
            ret0 = kernel => ret0,
            ret1 = server_future => ret1.map_err(|err| NetworkError::Generic(err.to_string()))?
        }
    }

    #[cfg(not(feature = "multi-threaded"))]
    {
        let _ = rt;
        let localset = localset.unwrap();
        let server_future = localset.run_until(server);
        citadel_io::tokio::select! {
            ret0 = kernel => ret0,
            ret1 = server_future => ret1
        }
    }
}
