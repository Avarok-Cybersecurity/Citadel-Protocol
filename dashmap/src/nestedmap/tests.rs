use super::*;
use rayon::prelude::*;

#[test]
fn insert_then_assert_st() {
    let map = NestedMap::default();

    for i in 0..1024_i32 {
        map.insert(i, i * 7);
    }

    for i in 0..1024_i32 {
        assert_eq!(i * 7, *map.get(&i).unwrap());
    }
}

#[test]
fn insert_rayon() {
    const INSV: u64 = 518;
    let map = NestedMap::default();

    (0..100000).into_par_iter().for_each(|i| {
        map.insert(i, INSV);
    });
}

#[test]
fn len() {
    let map = NestedMap::default();

    for i in 0..1024_i32 {
        map.insert(i, i);
    }

    assert_eq!(map.len(), 1024);
}

#[test]
fn is_empty() {
    let map: NestedMap<i32, i32> = NestedMap::default();

    assert_eq!(map.is_empty(), true);
}

#[test]
fn iter_count_fold() {
    let map = NestedMap::default();

    for i in 0..1024_i32 {
        map.insert(i, i);
    }

    for r in map.iter() {
        assert!(*r >= 0 && *r < 1024);
    }

    assert_eq!(map.iter().count(), 1024);
}

#[test]
fn intoiter() {
    let map = NestedMap::default();

    for i in 0..1024_i32 {
        map.insert(i, i);
    }

    for r in &map {
        assert!(*r >= 0 && *r < 1024);
    }

    assert_eq!(map.iter().count(), 1024);
}

#[test]
fn ref_drop_exist() {
    let map = NestedMap::default();

    map.insert("wokeblox", 492_i32);
    let r = map.get(&"wokeblox").unwrap();
    map.remove(&"wokeblox");
    assert_eq!(*r, 492_i32);
}
