use crate::crypto::{CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SigAlgorithm};
use crate::errors::Error;
use std::fmt::Formatter;
use std::write;

pub(crate) mod mem;

pub fn print_tick(
    f: &mut Formatter<'_>,
    relative_group_id: usize,
    total_groups: usize,
    transfer_rate: f32,
) -> std::fmt::Result {
    if can_print_progress(relative_group_id, total_groups) {
        write!(
            f,
            " ({}% @ {} MB/s) ",
            get_progress_percent(relative_group_id, total_groups),
            transfer_rate
        )
    } else {
        write!(f, "...")
    }
}

/// There are two boundaries when this returns false: when the relative group ID == 0 (first) || == total_groups -1 (last)
/// Then, there are intermediate points in a cycle when this returns false
fn can_print_progress(relative_group_id: usize, total_groups: usize) -> bool {
    if relative_group_id != 0 && relative_group_id != total_groups.saturating_sub(1) {
        // suppose the total # of groups is n. We want to print out only every v% complete (where 0 < v < 1)
        // Let floor(n * v) = k. Thus every k relative_group_id's, a print out occurs.
        // Thus, if r = the current relative group id, then print-out when:
        // [r mod k == 0] <==> [r mod floor(n*v) == 0]
        // if total_groups < v, then each time a print-out occurs (except end points, per above condition)
        const V: f32 = 0.1;
        relative_group_id % (total_groups as f32 * V).ceil() as usize == 0
    } else {
        false
    }
}

fn get_progress_percent(relative_group_id: usize, total_groups: usize) -> f32 {
    100f32 * (relative_group_id as f32 / total_groups as f32)
}

pub fn const_time_compare(this: &[u8], other: &[u8]) -> bool {
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

pub fn validate_crypto_params(params: &CryptoParameters) -> Result<(), Error> {
    let uses_kyber_kem = params.kem_algorithm == KemAlgorithm::Kyber;
    if params.encryption_algorithm == EncryptionAlgorithm::Kyber && !uses_kyber_kem {
        return Err(Error::Generic(
            "Invalid crypto parameter combination. Kyber encryption must be paired with Kyber KEM",
        ));
    }

    if params.encryption_algorithm == EncryptionAlgorithm::Kyber
        && params.sig_algorithm == SigAlgorithm::None
    {
        return Err(Error::Generic(
            "A post-quantum signature scheme must be selected when using Kyber encryption",
        ));
    }

    // NOTE: it's okay to have a sig scheme defined with no Kyber. That just means every packet gets non-repudiation endowed onto its security

    Ok(())
}
