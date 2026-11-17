//! The default Argon2 profile is the same in every build and meets the floor: parameters stored
//! with an account outlive the binary that chose them.
use citadel_crypt::argon::argon_container::{
    ArgonDefaultServerSettings, ArgonSettings, ARGON_FLOOR_LANES, ARGON_FLOOR_MEM_COST,
    ARGON_FLOOR_TIME_COST,
};

#[test]
fn the_default_profile_meets_the_floor() {
    assert!(ArgonSettings::default().meets_floor());
    assert!(ArgonSettings::from(ArgonDefaultServerSettings::default()).meets_floor());
}

#[test]
fn the_floor_is_inclusive_and_each_parameter_counts() {
    let with = |lanes, hash_length, mem_cost, time_cost| {
        ArgonSettings::new_gen_salt(vec![], lanes, hash_length, mem_cost, time_cost, vec![])
            .meets_floor()
    };
    let (l, m, t) = (
        ARGON_FLOOR_LANES,
        ARGON_FLOOR_MEM_COST,
        ARGON_FLOOR_TIME_COST,
    );
    assert!(with(l, 32, m, t));
    assert!(!with(l - 1, 32, m, t));
    assert!(!with(l, 31, m, t));
    assert!(!with(l, 32, m - 1, t));
    assert!(!with(l, 32, m, t - 1));
}
