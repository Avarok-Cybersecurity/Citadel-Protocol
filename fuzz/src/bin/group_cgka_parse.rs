//! AFL harness: zero-trust group CGKA artifact deserialization (Commit/Welcome/KeyPackage/AppCiphertext).
use afl::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        citadel_proto::fuzz_targets::group_cgka_parse(data);
    });
}
