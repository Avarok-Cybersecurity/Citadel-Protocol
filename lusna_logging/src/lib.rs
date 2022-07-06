pub use tracing::{self, debug, error, info, trace, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::SubscriberBuilder;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[allow(unused_must_use)]
/// Sets up the logging for any crate
pub fn setup_log() {
    // MUST figure out how to make macro emit to 'lusna'
    let _ = SubscriberBuilder::default()
        .with_line_number(true)
        .with_file(true)
        .with_span_events(FmtSpan::FULL)
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .try_init();

    // NOTE: emitted events from span's ret/err do not work with custom targets.
    // Tracking issue: https://github.com/tokio-rs/tracing/issues/2183

    log::trace!(target: "lusna", "TRACE enabled");
    log::debug!(target: "lusna", "DEBUG enabled");
    log::info!(target: "lusna", "INFO enabled");
    log::warn!(target: "lusna", "WARN enabled");
    log::error!(target: "lusna", "ERROR enabled");
}
