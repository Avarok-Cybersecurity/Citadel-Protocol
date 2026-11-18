//! Reading an IP-echo service's answer without letting the service decide how much is read.
//!
//! The answer is one textual address. A body longer than [`MAX_IP_RESPONSE_BYTES`] cannot be
//! one, so reading stops there, whatever the service declares or keeps sending.

use crate::IpRetrieveError;

/// The longest answer read from an IP-echo service. A textual IPv6 address is at most 45 bytes
/// (with an embedded IPv4 part); the rest leaves room for the whitespace and line endings some
/// services add.
pub const MAX_IP_RESPONSE_BYTES: usize = 256;

/// Appends `chunk` to `body`, or fails once the total would pass [`MAX_IP_RESPONSE_BYTES`].
fn append_capped(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), IpRetrieveError> {
    if body.len() + chunk.len() > MAX_IP_RESPONSE_BYTES {
        return Err(too_long());
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn too_long() -> IpRetrieveError {
    IpRetrieveError::ip_retrieve(format!(
        "the IP service's answer is longer than {MAX_IP_RESPONSE_BYTES} bytes"
    ))
}

/// Fails when the response declares a body longer than [`MAX_IP_RESPONSE_BYTES`].
fn refuse_declared_length(declared: Option<u64>) -> Result<(), IpRetrieveError> {
    match declared {
        Some(len) if len > MAX_IP_RESPONSE_BYTES as u64 => Err(too_long()),
        _ => Ok(()),
    }
}

fn into_text(body: Vec<u8>) -> Result<String, IpRetrieveError> {
    String::from_utf8(body).map_err(|err| IpRetrieveError::ip_retrieve(err.to_string()))
}

fn http_error(err: reqwest::Error) -> IpRetrieveError {
    IpRetrieveError::ip_retrieve(err.to_string())
}

/// The response body as text. Reading stops at the first chunk that would take it past
/// [`MAX_IP_RESPONSE_BYTES`].
#[cfg(not(target_family = "wasm"))]
pub(crate) async fn read_capped(mut resp: reqwest::Response) -> Result<String, IpRetrieveError> {
    refuse_declared_length(resp.content_length())?;
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(http_error)? {
        append_capped(&mut body, &chunk)?;
    }
    into_text(body)
}

/// The response body as text. The browser's fetch reads the body; a declared length past
/// [`MAX_IP_RESPONSE_BYTES`] is refused before it does, and any longer body after.
#[cfg(target_family = "wasm")]
pub(crate) async fn read_capped(resp: reqwest::Response) -> Result<String, IpRetrieveError> {
    refuse_declared_length(resp.content_length())?;
    let mut body = Vec::new();
    append_capped(&mut body, &resp.bytes().await.map_err(http_error)?)?;
    into_text(body)
}

#[cfg(test)]
mod tests {
    use super::{append_capped, MAX_IP_RESPONSE_BYTES};

    #[test]
    fn a_body_up_to_the_bound_is_kept() {
        let mut body = Vec::new();
        append_capped(&mut body, &[b'1'; MAX_IP_RESPONSE_BYTES - 1]).unwrap();
        append_capped(&mut body, b"1").unwrap();
        assert_eq!(body.len(), MAX_IP_RESPONSE_BYTES);
    }

    #[test]
    fn a_body_past_the_bound_is_refused() {
        let mut body = Vec::new();
        append_capped(&mut body, &[b'1'; MAX_IP_RESPONSE_BYTES]).unwrap();
        assert!(append_capped(&mut body, b"1").is_err());
        assert_eq!(body.len(), MAX_IP_RESPONSE_BYTES);
    }
}
