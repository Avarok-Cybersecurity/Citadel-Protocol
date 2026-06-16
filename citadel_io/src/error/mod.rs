//! The workspace-wide canonical error type.
//!
//! [`NetworkError`] is a single, pointer-sized error used across the entire Citadel workspace. Its
//! message lives in the [`ErrorCode`] registry (one `#[form = "..."]` per variant — see [`code`]),
//! and per-occurrence arguments are stored **lazily** (formatted only when Displayed). Every error
//! also records the call-site `"file:line"` (see [`crate::error!`]).
//!
//! Construct errors with the [`crate::error!`] macro: `error!(ErrorCode::Variant, arg0, arg1, ...)`.
//! The number of positional args is validated against the form's `{}` count **at compile time**.

mod code;
mod construct;

pub use code::ErrorCode;

use std::fmt::{self, Debug, Display, Formatter};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// Anything that can be a lazy error argument: `Display`, thread-safe, and owned. A blanket impl
/// covers every qualifying type, so call sites pass values directly (`u64`, `String`, `&'static str`,
/// a wrapped `io::Error`, …). For `Debug`-only values, wrap them in [`Dbg`].
pub trait ErrorArgs: Display + Send + Sync + 'static {}
impl<T: Display + Send + Sync + 'static> ErrorArgs for T {}

/// The heap-resident payload of a [`NetworkError`]. Public so `NetworkError`'s `Deref` exposes
/// `err.code`; `origin`/`args` stay crate-private (use the accessors).
#[derive(Clone)]
pub struct NetworkErrorInner {
    /// The stable error code (also selects the message template).
    pub code: ErrorCode,
    /// The call-site `"file:line"` where the error was raised.
    pub(crate) origin: &'static str,
    /// The positional format arguments (`None` when the form has no `{}`).
    pub(crate) args: Option<Arc<[Box<dyn ErrorArgs>]>>,
}

/// The single error type used across the entire Citadel workspace.
///
/// Pointer-sized (8 bytes): the payload is boxed so `Result<T, NetworkError>` stays lean on the
/// common `Ok` path. Construct via the [`crate::error!`] macro. `Deref`s to [`NetworkErrorInner`], so
/// `err.code` works directly.
#[derive(Clone)]
pub struct NetworkError(Box<NetworkErrorInner>);

impl Deref for NetworkError {
    type Target = NetworkErrorInner;
    fn deref(&self) -> &NetworkErrorInner {
        &self.0
    }
}

impl DerefMut for NetworkError {
    fn deref_mut(&mut self) -> &mut NetworkErrorInner {
        &mut self.0
    }
}

impl NetworkError {
    /// Build an error from its parts. Prefer the [`crate::error!`] macro, which captures `origin`
    /// and validates the argument count at compile time. `args[i]` fills the i-th `{}` in the form.
    pub fn from_parts(
        code: ErrorCode,
        origin: &'static str,
        args: Vec<Box<dyn ErrorArgs>>,
    ) -> Self {
        debug_assert_eq!(
            args.len(),
            code.placeholder_count(),
            "error code {code:?} expects {} argument(s) but got {}",
            code.placeholder_count(),
            args.len(),
        );
        let args = if args.is_empty() {
            None
        } else {
            Some(Arc::from(args))
        };
        Self(Box::new(NetworkErrorInner { code, origin, args }))
    }

    /// The stable error code.
    pub fn code(&self) -> ErrorCode {
        self.0.code
    }

    /// The stable numeric error code (the [`ErrorCode`] `#[repr(u16)]` discriminant).
    pub fn code_u16(&self) -> u16 {
        self.0.code.as_u16()
    }

    /// The call-site `"file:line"` where this error was raised.
    pub fn error_source(&self) -> &'static str {
        self.0.origin
    }

    /// Consume into the full rendered message.
    pub fn into_string(self) -> String {
        self.to_string()
    }
}

impl Display for NetworkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let template = self.0.code.raw_string();
        match &self.0.args {
            None => f.write_str(template),
            Some(args) => render(template, args, f),
        }
    }
}

/// Substitute the positional `args` into `template`'s `{}` placeholders (in order), honoring `{{`/`}}`
/// escapes. Only `template` is scanned, so an argument whose own `Display` contains `{}` is never
/// re-interpreted.
fn render(template: &str, args: &[Box<dyn ErrorArgs>], f: &mut Formatter<'_>) -> fmt::Result {
    let bytes = template.as_bytes();
    let mut i = 0;
    let mut run_start = 0;
    let mut arg_idx = 0;
    while i < bytes.len() {
        let two = |a: u8| i + 1 < bytes.len() && bytes[i + 1] == a;
        match bytes[i] {
            b'{' if two(b'{') => {
                f.write_str(&template[run_start..i])?;
                f.write_str("{")?;
                i += 2;
                run_start = i;
            }
            b'{' if two(b'}') => {
                f.write_str(&template[run_start..i])?;
                if let Some(arg) = args.get(arg_idx) {
                    write!(f, "{arg}")?;
                    arg_idx += 1;
                } else {
                    f.write_str("{}")?;
                }
                i += 2;
                run_start = i;
            }
            b'}' if two(b'}') => {
                f.write_str(&template[run_start..i])?;
                f.write_str("}")?;
                i += 2;
                run_start = i;
            }
            _ => i += 1,
        }
    }
    f.write_str(&template[run_start..])
}

impl Debug for NetworkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // Embed the rendered message + origin so `{err:?}` logs stay useful.
        write!(
            f,
            "NetworkError {{ code: {:?} ({}), origin: {:?}, message: {:?} }}",
            self.0.code,
            self.0.code.as_u16(),
            self.0.origin,
            // `self` renders via Display; capture it as a string for the {:?} field.
            self.to_string(),
        )
    }
}

impl std::error::Error for NetworkError {}

/// Errors compare equal iff they carry the same [`ErrorCode`] (arguments and origin are ignored).
impl PartialEq for NetworkError {
    fn eq(&self, other: &Self) -> bool {
        self.0.code == other.0.code
    }
}
impl Eq for NetworkError {}
impl std::hash::Hash for NetworkError {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.code.hash(state);
    }
}

/// Wrap a `Debug`-only value so it can be passed as an [`ErrorArgs`] (renders via `{:?}`).
pub struct Dbg<T>(pub T);
impl<T: Debug> Display for Dbg<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

// --- conversions (used by `?`). These record the conversion site as the origin. ---

impl From<std::io::Error> for NetworkError {
    fn from(err: std::io::Error) -> Self {
        Self::from_parts(
            ErrorCode::Io,
            concat!(file!(), ":", line!()),
            vec![Box::new(err.to_string())],
        )
    }
}

#[allow(clippy::needless_pass_by_value)]
impl<T> From<crate::tokio::sync::mpsc::error::SendError<T>> for NetworkError {
    fn from(err: crate::tokio::sync::mpsc::error::SendError<T>) -> Self {
        Self::from_parts(
            ErrorCode::ChannelSend,
            concat!(file!(), ":", line!()),
            vec![Box::new(err.to_string())],
        )
    }
}

impl From<NetworkError> for std::io::Error {
    fn from(err: NetworkError) -> Self {
        std::io::Error::other(err.into_string())
    }
}

// --- the `error!` macro family (exported at the crate root) ---

/// Counts macro arguments at compile time (maps each token tree to `()`); internal.
#[macro_export]
#[doc(hidden)]
macro_rules! __count_unit {
    ($($t:tt)*) => {
        ()
    };
}

/// Construct a [`NetworkError`] from a registry [`ErrorCode`] and its positional arguments.
///
/// `error!(ErrorCode::Variant, arg0, arg1, ...)`. The argument count is validated against the form's
/// `{}` placeholder count **at compile time**, and the call-site `file:line` is captured as the
/// error's origin.
///
/// Passing the wrong number of arguments fails to compile:
/// ```compile_fail
/// use citadel_io::{error, ErrorCode};
/// // `Generic`'s form is "{}" (one placeholder) but zero arguments are passed.
/// let _ = error!(ErrorCode::Generic);
/// ```
#[macro_export]
macro_rules! error {
    ($code:expr $(, $arg:expr)* $(,)?) => {
        $crate::error_inner!(
            $code,
            ::core::concat!(::core::file!(), ":", ::core::line!())
            $(, $arg)*
        )
    };
}

/// Inner half of [`error!`]: receives the already-captured origin so `file!()`/`line!()` resolve to
/// the outer call site. Not intended for direct use.
#[macro_export]
#[doc(hidden)]
macro_rules! error_inner {
    ($code:expr, $origin:expr $(, $arg:expr)* $(,)?) => {{
        const __CITADEL_ERR_N: usize = <[()]>::len(&[ $( $crate::__count_unit!($arg) ),* ]);
        const _: () = ::core::assert!(
            $code.placeholder_count() == __CITADEL_ERR_N,
            "error!: number of arguments does not match the number of placeholders in the form string",
        );
        $crate::error::NetworkError::from_parts(
            $code,
            $origin,
            ::std::vec![
                $( ::std::boxed::Box::new($arg) as ::std::boxed::Box<dyn $crate::error::ErrorArgs> ),*
            ],
        )
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_minimal() {
        assert_eq!(core::mem::size_of::<ErrorCode>(), 2, "ErrorCode must stay 2 bytes");
        assert_eq!(
            core::mem::size_of::<NetworkError>(),
            8,
            "NetworkError must be pointer-sized",
        );
        assert_eq!(
            core::mem::size_of::<Result<(), NetworkError>>(),
            8,
            "Result<(), NetworkError> must stay pointer-sized via the Box niche",
        );
    }

    #[test]
    fn display_no_args_and_one_arg() {
        let bare = error!(ErrorCode::ProperShutdown);
        assert_eq!(bare.to_string(), "The session was shut down properly");
        assert_eq!(bare.code(), ErrorCode::ProperShutdown);

        let one = error!(ErrorCode::Generic, "boom");
        assert_eq!(one.to_string(), "boom");
    }

    #[test]
    fn display_substitution_and_escapes() {
        // multi-arg substitution + an arg whose own Display contains "{}" (must NOT be re-scanned).
        let e = error!(ErrorCode::AccountClientExists, 42u64);
        assert_eq!(e.to_string(), "Client account already exists: 42");

        let weird = error!(ErrorCode::Generic, "literal {} braces");
        assert_eq!(weird.to_string(), "literal {} braces");
    }

    #[test]
    fn eq_is_code_only() {
        let a = error!(ErrorCode::Generic, "one");
        let b = error!(ErrorCode::Generic, "two");
        let c = error!(ErrorCode::Socket, "one");
        assert_eq!(a, b, "same code compares equal regardless of args");
        assert_ne!(a, c);
    }

    #[test]
    fn origin_is_recorded() {
        let e = error!(ErrorCode::Generic, "x");
        assert!(
            e.error_source().contains("mod.rs"),
            "origin should be this file's path, got {:?}",
            e.error_source(),
        );
    }

    #[test]
    fn dbg_wrapper_renders_debug() {
        let e = error!(ErrorCode::Generic, Dbg(vec![1, 2, 3]));
        assert_eq!(e.to_string(), "[1, 2, 3]");
    }
}
