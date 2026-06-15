//! AFL harness: header-obfuscator deobfuscation (untrusted cipher key + wrapping arithmetic).
use afl::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        citadel_proto::fuzz_targets::header_obfuscator(data);
    });
}
