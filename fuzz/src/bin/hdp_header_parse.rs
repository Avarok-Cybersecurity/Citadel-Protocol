//! AFL harness: zero-copy HDP header parse over arbitrary inbound bytes.
use afl::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        citadel_proto::fuzz_targets::hdp_header_parse(data);
    });
}
