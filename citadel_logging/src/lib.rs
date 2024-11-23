pub use tracing::{self, debug, error, info, instrument, trace, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::SubscriberBuilder;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Sets up the logging for any crate
pub fn setup_log() {
    std::panic::set_hook(Box::new(|info| {
        error!(target: "citadel", "Panic occurred: {}", info);
        std::process::exit(1);
    }));

    setup_log_no_panic_hook()
}

pub fn setup_log_no_panic_hook() {
    let _ = SubscriberBuilder::default()
        .with_line_number(true)
        .with_file(true)
        .with_span_events(FmtSpan::NONE)
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .try_init();
}
