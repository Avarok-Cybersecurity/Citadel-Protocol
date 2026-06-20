//! AFL harness: group-header bincode deserialization + GroupReceiverConfig DoS validation.
use afl::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        citadel_proto::fuzz_targets::group_header_validate(data);
    });
}
