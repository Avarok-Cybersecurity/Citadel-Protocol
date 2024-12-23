//! # Citadel Logging
//!
//! A structured logging facade for the Citadel Protocol, built on top of
//! the `tracing` ecosystem. This crate provides consistent logging setup
//! and configuration across all Citadel Protocol components.
//!
//! ## Features
//!
//! - Structured logging with spans and events
//! - File and line number information
//! - Environment-based log level filtering
//! - Panic handling with logging
//! - Async-aware instrumentation
//!
//! ## Usage
//!
//! ```rust
//! use citadel_logging::{setup_log, info, debug, error};
//!
//! // Initialize logging
//! setup_log();
//!
//! // Log at different levels
//! # #[derive(Debug)]
//! # struct Config;
//! # let config = Config;
//! # let error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Connection failed");
//!
//! info!(target: "citadel", "Starting application...");
//! debug!(target: "citadel", "Configuration loaded: {:?}", config);
//! error!(target: "citadel", "Failed to connect: {}", error);
//! ```
//!
//! ## Log Levels
//!
//! The following log levels are available, in order of increasing severity:
//!
//! - `trace`: Very detailed information for debugging
//! - `debug`: Useful debugging information
//! - `info`: General information about program execution
//! - `warn`: Potentially harmful situations
//! - `error`: Error conditions that should be addressed
//!
//! ## Environment Configuration
//!
//! Log levels can be configured via the `RUST_LOG` environment variable:
//!
//! ```bash
//! # Enable debug logging for citadel components
//! RUST_LOG=citadel=debug
//!
//! # Enable different levels for different components
//! RUST_LOG=citadel=debug,citadel_wire=trace
//! ```
//!
//! ## Panic Handling
//!
//! By default, `setup_log()` installs a panic hook that logs the panic
//! information before exiting. If you need to use a custom panic hook,
//! use `setup_log_no_panic_hook()` instead.
pub use tracing::{self, debug, error, info, instrument, trace, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::SubscriberBuilder;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Sets up logging with panic handling for any Citadel Protocol crate.
///
/// This function:
/// 1. Installs a panic hook that logs panic information
/// 2. Configures structured logging with file and line information
/// 3. Sets up environment-based log filtering
///
/// # Example
///
/// ```rust
/// use citadel_logging::setup_log;
///
///  setup_log();
///  // Your application code here
/// ```
///
/// # Panics
///
/// When a panic occurs, it will be logged at the error level before
/// the process exits with status code 1.
pub fn setup_log() {
    std::panic::set_hook(Box::new(|info| {
        error!(target: "citadel", "Panic occurred: {info}");
        std::process::exit(1);
    }));

    setup_log_no_panic_hook()
}

/// Sets up logging without installing a panic hook.
///
/// This function provides the same logging setup as `setup_log()` but
/// without modifying the panic hook. Use this if you need to use a
/// custom panic hook or if the default panic behavior is desired.
///
/// # Example
///
/// ```rust
/// use citadel_logging::setup_log_no_panic_hook;
///
///  // Install custom panic hook
///  std::panic::set_hook(Box::new(|info| {
///     // Custom panic handling
///  }));
///     
///  setup_log_no_panic_hook();
/// ```
pub fn setup_log_no_panic_hook() {
    let _ = SubscriberBuilder::default()
        .with_line_number(true) // Include line numbers in log output
        .with_file(true) // Include file names in log output
        .with_span_events(FmtSpan::NONE) // Don't log span lifecycle events
        .with_env_filter(EnvFilter::from_default_env())
        .without_time() // Use RUST_LOG env var
        .finish()
        .try_init();
}

/// Disables the panic hook installed by `setup_log()`.
pub fn should_panic_test() {
    let _ = std::panic::take_hook();
    setup_log_no_panic_hook();
}
