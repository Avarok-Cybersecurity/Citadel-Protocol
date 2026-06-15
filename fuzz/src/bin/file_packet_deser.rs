//! AFL harness: file / RE-VFS packet bincode deserialization (untrusted paths + metadata).
use afl::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        citadel_proto::fuzz_targets::file_packet_deser(data);
    });
}
