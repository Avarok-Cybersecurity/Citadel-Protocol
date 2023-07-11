/// For efficient writing to data
pub mod partitioned_sec_buffer;
///
pub mod sec_bytes;
/// For packets
pub mod sec_packet;

pub(crate) fn const_time_compare(this: &[u8], other: &[u8]) -> bool {
    let mut count = 0;
    let this_len = this.len();

    // Only loop this_len times to prevent length-adjustment attacks that may leak
    // the length of the secret
    for idx in 0..this_len {
        let val_this = this.get(idx);
        let val_other = other.get(idx);
        match (val_this, val_other) {
            (Some(a), Some(b)) => count += (a == b) as usize,
            _ => {
                // Black box to not optimize away this branch
                let _ = std::hint::black_box(count);
            }
        }
    }

    count == this.len() && count == other.len()
}
