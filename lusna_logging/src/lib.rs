pub use tracing::*;

#[allow(unused_must_use)]
/// Sets up the logging for any crate
pub fn setup_log() {
    let _ = tracing_subscriber::fmt::try_init();

    log::trace!(target: "lusna", "TRACE enabled");
    log::debug!(target: "lusna", "DEBUG enabled");
    log::info!(target: "lusna", "INFO enabled");
    log::warn!(target: "lusna", "WARN enabled");
    log::error!(target: "lusna", "ERROR enabled");
}