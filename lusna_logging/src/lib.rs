pub use tracing::{self, trace, debug, info, warn, error};
use tracing_subscriber::fmt::SubscriberBuilder;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[allow(unused_must_use)]
/// Sets up the logging for any crate
pub fn setup_log() {
    let _ = SubscriberBuilder::default()
        .with_span_events(FmtSpan::FULL)
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .try_init();

    log::trace!(target: "lusna", "TRACE enabled");
    log::debug!(target: "lusna", "DEBUG enabled");
    log::info!(target: "lusna", "INFO enabled");
    log::warn!(target: "lusna", "WARN enabled");
    log::error!(target: "lusna", "ERROR enabled");
}