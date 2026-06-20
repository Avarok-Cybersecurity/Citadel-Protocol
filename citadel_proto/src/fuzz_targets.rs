//! Public fuzz entry points — compiled **only** under `--features fuzzing`.
//!
//! The protocol's parse/validate functions live in the private `proto` module (`pub(crate)`), so an
//! out-of-tree AFL harness crate cannot reach them. Rather than widen the real API, this module exposes
//! thin `pub fn(&[u8])` wrappers behind the `fuzzing` feature. Each wrapper drives one untrusted-input
//! boundary (network/disk bytes → parse/deserialize/validate) and simply discards the result; the fuzzer
//! is looking for panics, hangs, and OOM, not return values. Off by default → zero effect on real builds.

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::proto::packet::{HdpHeader, HdpPacket, HeaderObfuscator};
use crate::proto::validation;
use bytes::BytesMut;
use citadel_types::crypto::HeaderObfuscatorSettings;
use zerocopy::Ref;

/// Zero-copy HDP header parse over arbitrary inbound bytes (`Ref::new_from_prefix`). Catches
/// short-packet / alignment / bounds issues at the very first parse step.
pub fn hdp_header_parse(data: &[u8]) {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let packet = HdpPacket::new_recv(BytesMut::from(data), addr, 0);
    let _ = packet.parse();
}

/// Header-obfuscator deobfuscation: the first 16 bytes are an untrusted cipher key, then a wrapping
/// XOR/sub cipher runs over the header region. Fuzzes the key-load + cipher arithmetic.
pub fn header_obfuscator(data: &[u8]) {
    // Server side, enabled (no pre-shared key) so the first packet's key is taken from `data`.
    let obfuscator = HeaderObfuscator::new(true, HeaderObfuscatorSettings::Enabled);
    let mut buf = BytesMut::from(data);
    let _ = obfuscator.on_packet_received(&mut buf);
}

/// Group-header bincode deserialization + `GroupReceiverConfig::validate()` — the canonical DoS target
/// (a malformed config can demand huge allocations; `validate()` is the only guard).
pub fn group_header_validate(data: &[u8]) {
    let _ = validation::group::validate_header(&BytesMut::from(data));
}

/// Zero-trust group CGKA artifact deserialization: the relay forwards `Commit`/`Welcome`/`KeyPackage`/
/// `AppCiphertext` bytes verbatim, so the group coordinator parses fully untrusted input here. Fuzzes
/// the serde parse boundary for panics, hangs, and OOM (a malformed length could over-allocate).
pub fn group_cgka_parse(data: &[u8]) {
    use citadel_treekem::{AppCiphertext, Commit, KeyPackage, Welcome};
    use citadel_user::serialization::SyncIO;
    let _ = Commit::deserialize_from_vector(data);
    let _ = Welcome::deserialize_from_vector(data);
    let _ = KeyPackage::deserialize_from_vector(data);
    let _ = AppCiphertext::deserialize_from_vector(data);
}

/// File / RE-VFS packet bincode deserialization (untrusted file paths + metadata). The header argument
/// is unused by these validators, so a zeroed valid-length header suffices.
pub fn file_packet_deser(data: &[u8]) {
    let header_bytes = [0u8; HDP_HEADER_BYTE_LEN];
    if let Some(header) = Ref::<&[u8], HdpHeader>::new(&header_bytes[..]) {
        let _ = validation::file::validate_file_header(&header, data);
        let _ = validation::file::validate_revfs_pull(&header, data);
        let _ = validation::file::validate_revfs_delete(&header, data);
        let _ = validation::file::validate_file_header_ack(&header, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Edge-input smoke test: every target must tolerate degenerate inputs without panicking. This is
    /// the AFL contract, exercised here without the AFL runtime (which only the `fuzz/` crate links).
    #[test]
    fn targets_never_panic_on_edge_inputs() {
        let inputs: Vec<Vec<u8>> = vec![
            vec![],                             // empty
            vec![0u8],                          // 1 byte
            vec![0xFFu8; 15],                   // shorter than the 16-byte obfuscator key
            vec![0xABu8; HDP_HEADER_BYTE_LEN],  // exactly one header length
            vec![0u8; HDP_HEADER_BYTE_LEN - 1], // one short of a header
            (0u8..=255).collect(),              // 256 ramp
            vec![0x7Fu8; 4096],                 // large
        ];
        for data in &inputs {
            hdp_header_parse(data);
            header_obfuscator(data);
            group_header_validate(data);
            file_packet_deser(data);
        }
    }
}
