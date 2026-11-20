//! An error that crossed the wire as its stable code and its rendered message, rebuilt with that
//! code on the side that reads it, so a caller can match on the code rather than the text.

use super::{ErrorArgs, ErrorCode, NetworkError};

impl NetworkError {
    /// The error a peer reported as `code` with `message`. The message's arguments are read back
    /// out of the code's template, so the error renders exactly as `message`. A code this build
    /// does not know, or a message its template cannot have produced, is a `Generic` error with
    /// the message: the text is never lost.
    pub fn from_wire(code: u16, message: String) -> Self {
        match ErrorCode::from_u16(code).and_then(|code| arguments_of(code, &message)) {
            Some((code, args)) => {
                NetworkError::from_parts(code, concat!(file!(), ":", line!()), args)
            }
            None => crate::error!(ErrorCode::Generic, message),
        }
    }
}

/// `message`'s arguments under `code`'s template, if the template produced it.
fn arguments_of(code: ErrorCode, message: &str) -> Option<(ErrorCode, Vec<Box<dyn ErrorArgs>>)> {
    let template = code.raw_string();
    if template.contains("{{") || template.contains("}}") {
        return None;
    }
    let mut literals = template.split("{}");
    let mut rest = message.strip_prefix(literals.next()?)?;
    let mut args: Vec<Box<dyn ErrorArgs>> = Vec::new();
    let literals: Vec<&str> = literals.collect();
    for (i, literal) in literals.iter().enumerate() {
        let end = if i + 1 == literals.len() {
            rest.strip_suffix(literal).map(str::len)?
        } else {
            rest.find(literal)?
        };
        args.push(Box::new(rest[..end].to_string()));
        rest = &rest[end + literal.len()..];
    }
    (rest.is_empty() && args.len() == code.placeholder_count()).then_some((code, args))
}

#[cfg(test)]
mod tests {
    use crate::{error, ErrorCode, NetworkError};

    fn round_trip(err: NetworkError) -> NetworkError {
        NetworkError::from_wire(err.code_u16(), err.to_string())
    }

    #[test]
    fn a_reported_error_keeps_its_code_and_its_text() {
        for err in [
            error!(ErrorCode::PqSignInFailed),
            error!(ErrorCode::PqSignInMalformed, "a device label"),
            error!(ErrorCode::Timeout, "the login deadline (20s)"),
        ] {
            let read = round_trip(err.clone());
            assert_eq!(read.code(), err.code());
            assert_eq!(read.to_string(), err.to_string());
        }
    }

    #[test]
    fn an_unknown_code_or_a_foreign_message_is_generic_with_the_text() {
        let unknown = NetworkError::from_wire(u16::MAX, "from a newer peer".into());
        assert_eq!(unknown.code(), ErrorCode::Generic);
        assert_eq!(unknown.to_string(), "from a newer peer");
        let code = ErrorCode::PqSignInFailed.as_u16();
        let foreign = NetworkError::from_wire(code, "not this code's text".into());
        assert_eq!(foreign.code(), ErrorCode::Generic);
        assert_eq!(foreign.to_string(), "not this code's text");
    }
}
