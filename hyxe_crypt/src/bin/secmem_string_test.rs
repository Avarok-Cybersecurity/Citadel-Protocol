#![cfg(not(coverage))]

use hyxe_crypt::prelude::SecString;

#[allow(dead_code)]
fn main() {
    let mut val = SecString::new();
    assert_eq!(val.len(), 0);
    val.push('h');
    val.push('e');
    //val.clear();
    let mut basic = val.clone();
    assert_eq!(val.len(), 2);
    assert_eq!(basic.len(), 2);
    assert_eq!(basic.as_str(), "he");

    basic.push('y');
    assert_ne!(val.as_str(), basic.as_str());

    let retrieved = basic.into_buffer();
    let serde = bincode2::serialize(&retrieved).unwrap();
    let retrieved = bincode2::deserialize::<SecString>(&serde)
        .unwrap()
        .into_buffer();
    // at this point, basic should have dropped, but the memory should not have been zeroed out
    assert_eq!(retrieved, "hey");
}
