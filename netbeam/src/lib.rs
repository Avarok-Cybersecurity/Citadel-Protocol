#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;

pub mod reliable_conn;
pub mod sync;
pub mod time_tracker;

pub mod multiplex;

pub(crate) type ScopedFutureResult<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, anyhow::Error>> + Send + 'a>>;
