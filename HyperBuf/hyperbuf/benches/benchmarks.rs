#![feature(repeat_generic_slice, async_await)]
/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

#[macro_use]
extern crate criterion;

use bytes::{Buf, BufMut, BytesMut};
use criterion::{Criterion, ParameterizedBenchmark};

use hyperbuf::prelude::*;

use std::collections::HashMap;

type val_type_hashmap = u16;
type val_type_vec = u8;

fn vec(len: usize, slice: &[val_type_vec]) {
    let cap = len/slice.len();
    let mut mem0 = Vec::with_capacity(cap);
    let mem = &mut mem0;
    unsafe {
        mem.set_len(cap);
        for idx in 0..(cap) {
            //mem[idx] = idx as val_type;
            mem[idx] = idx;
        }
    }
}

fn raw_array(len: usize, slice: &[val_type_vec]) {
    let cap = len/slice.len();
    let mut mem0 = [0 as u8; 100];
    let mem = &mut mem0;
        for idx in 0..(cap) {
            //mem[idx] = idx as val_type;
            mem[idx] = idx as u8;
        }
}

fn hyper_vec(len: usize, slice: &[val_type_vec]) {
    let mut mem0 = HyperVec::new(len);
    let mem = &mut mem0;

    for idx in 0..(len/slice.len()) as isize {
        //mem.put_val_type(idx as val_type);
        mem[idx] = idx as val_type_vec;
    }
}

fn bytes_mut(len: usize, slice: &[val_type_vec]) {
    let mut mem0 = BytesMut::with_capacity(len);
    let mem = &mut mem0;
    unsafe {mem.set_len(len/slice.len())}
    for idx in 0..(len/slice.len()) {
        mem[idx] = idx as val_type_vec;
    }
}

fn hashmap(len: usize, slice: &[val_type_hashmap]) {
    let mut mem0 = HashMap::<usize, val_type_hashmap>::default();
    let mem = &mut mem0;
    for idx in 0..(len/slice.len()) {
        mem.insert(idx, idx as val_type_hashmap);
    }
}


///Main function
fn criterion_benchmark(c: &mut Criterion) {
    let slice = (0..100).collect::<Vec<u8>>();
    let slice = slice.as_ref();
    let slice = unsafe { std::mem::transmute::<&[val_type_vec], &'static [val_type_vec]>(slice) };

    c.bench(
        "Vec benches",
        ParameterizedBenchmark::new("std vec", move |b, i| b.iter(|| vec(*i as usize, slice)), vec![100])
            .with_function("HyperVec", move |b, i| b.iter(|| hyper_vec(*i as usize, slice)))
            .with_function("BytesMut", move |b, i| b.iter(|| bytes_mut(*i as usize, slice)))
    );


  /*
    c.bench(
        "Hashmaps",
        ParameterizedBenchmark::new("std hashmap", move |b, i| b.iter(|| hashmap(*i as usize, slice)), vec![120])
            .with_function("DashMap", move |b, i| b.iter(|| dashmap(*i as usize, slice))),
    );
*/
    /*
    c.bench(
        "Lock speeds",
        ParameterizedBenchmark::new("ParkingLot::RwLock", move |b, i| b.iter(parkinglot_mutex), vec![0])
            .with_function("HyperLock", move |b, i| b.iter(hyperlock)),
    );*/

}

/*
fn hyperlock() {
    let my_x: u16 = 100;
    let mut wrapper = HyperVec::wrap(my_x);
    let mut wrapper = &mut wrapper;
    for x in 0..u16::max_value() {
        let writer = wrapper.cast_mut::<u16>().unwrap();
        block_on(writer.visit( None, |r: Option<&WriteVisitor<u16>>| {
            let write = r.unwrap();
            *write.get().unwrap() = x;
            None
        }));

        let reader = wrapper.cast::<u16>().unwrap();
        block_on(reader.try_visit( |r| {
            let read = r.unwrap();
            let r = read.get().unwrap();
            assert_eq!(&x, r);
        }));
    }
}

use parking_lot::RwLock;
use std::sync::Mutex;
use hypervec::impls::Castable;

fn parkinglot_mutex() {
    let my_x: u16 = 100;
    let mut wrapper = RwLock::new(my_x);
    for x in 0..u16::max_value() {
        block_on((async {
            *wrapper.write() = x;
        }));

        block_on((async {
            assert_eq!(*wrapper.read(), x);
        }));

    }
}
*/
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);