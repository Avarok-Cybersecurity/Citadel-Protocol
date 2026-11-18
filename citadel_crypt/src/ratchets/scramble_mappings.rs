//! The scramble mappings an entropy bank carries arrive from the counterpart of a key exchange
//! (and from storage), and every packet's port pair and wave position is derived from them. They
//! are accepted only as two permutations of `0..DRILL_RANGE`, side by side, so the packet math that
//! divides by their count and looks a sequence up in them always has a full, duplicate-free table.

use crate::ratchets::entropy_bank::DRILL_RANGE;
use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

/// Why `mappings` is not a valid table, or `None` when it is one.
pub(crate) fn invalid_reason(mappings: &[(u16, u16)]) -> Option<String> {
    if mappings.len() != DRILL_RANGE {
        return Some(format!(
            "{} pairs where {DRILL_RANGE} are required",
            mappings.len()
        ));
    }
    let mut seen_in = [false; DRILL_RANGE];
    let mut seen_out = [false; DRILL_RANGE];
    for &(port_in, port_out) in mappings {
        for (port, seen) in [(port_in, &mut seen_in), (port_out, &mut seen_out)] {
            match seen.get_mut(port as usize) {
                Some(slot) if !*slot => *slot = true,
                _ => {
                    return Some(format!(
                        "port {port} is outside 0..{DRILL_RANGE} or repeated"
                    ))
                }
            }
        }
    }
    None
}

/// `deserialize_with` for an entropy bank's mappings: the table is refused unless it is valid.
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<Vec<(u16, u16)>>, D::Error> {
    let mappings = Zeroizing::new(Vec::<(u16, u16)>::deserialize(deserializer)?);
    match invalid_reason(&mappings) {
        None => Ok(mappings),
        Some(reason) => Err(serde::de::Error::custom(citadel_io::error!(
            citadel_io::ErrorCode::EntropyBankMappingsInvalid,
            reason
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::invalid_reason;
    use crate::misc::create_port_mapping;
    use crate::ratchets::entropy_bank::DRILL_RANGE;

    #[test]
    fn a_generated_table_is_valid() {
        assert_eq!(invalid_reason(&create_port_mapping()), None);
    }

    #[test]
    fn short_long_out_of_range_and_repeated_tables_are_invalid() {
        let valid = create_port_mapping();
        assert!(invalid_reason(&[]).is_some());
        assert!(invalid_reason(&valid[1..]).is_some());
        let mut long = valid.clone();
        long.push((0, 0));
        assert!(invalid_reason(&long).is_some());
        let mut out_of_range = valid.clone();
        out_of_range[0].0 = DRILL_RANGE as u16;
        assert!(invalid_reason(&out_of_range).is_some());
        let mut repeated = valid.clone();
        repeated[0].1 = repeated[1].1;
        assert!(invalid_reason(&repeated).is_some());
    }
}
