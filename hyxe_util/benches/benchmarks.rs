/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

#[macro_use]
extern crate criterion;
extern crate lazy_static;

use std::borrow::BorrowMut;

use criterion::{Bencher, black_box, Criterion};

use hyxe_util::prelude::*;

fn base64_auto(len: usize, c: &mut Criterion) {
    let ref_vec = {
        let mut tmp = Vec::<u8>::new();
        tmp.resize(len, 10);
        tmp
    };

    c.bench_function("Base64 auto", move |b| b.iter(|| {
        let mut vec = BytesMut::with_capacity(len * 10);
        let mut ret_vec = BytesMut::with_capacity(len * 10);

        vec.resize(len * 10, 10);
        ret_vec.resize(len * 10, 0);

        let bytes_encoded = base64::encode_config_slice(&ref_vec, base64::STANDARD, &mut vec[..len * 10]);

        vec.truncate(bytes_encoded);

        let bytes_decoded = base64::decode_config_bytes_auto(&mut vec, base64::STANDARD).unwrap();

        //vec.truncate() is done implicitly inside the custom decode function

        assert_eq!(bytes_decoded, len);
        assert_eq!(vec, ref_vec);
    }));
}


fn base64_non_auto(len: usize, c: &mut Criterion) {
    let len = 10;
    let ref_vec = {
        let mut tmp = Vec::<u8>::new();
        tmp.resize(len, 10);
        tmp
    };

    c.bench_function("Base64 non-auto", move |b| b.iter(|| {
        let mut vec = Vec::<u8>::with_capacity(len * 10);
        let mut ret_vec = Vec::<u8>::with_capacity(len * 10);

        vec.resize(len * 10, 10);
        ret_vec.resize(len * 10, 0);

        let bytes_encoded = base64::encode_config_slice(&ref_vec, base64::STANDARD, &mut vec);

        vec.truncate(bytes_encoded);

        let bytes_decoded = base64::decode_config_slice(&vec, base64::STANDARD, &mut ret_vec[0..len * 10]).unwrap();

        ret_vec.truncate(bytes_decoded);

        assert_eq!(bytes_decoded, len);
        assert_eq!(ret_vec, ref_vec);
    }));
}

///Main function
fn criterion_benchmark(c: &mut Criterion) {
    //c.bench_function("fib 20", |b| b.iter(|| fibonacci(black_box(20))));
    let number_of_tests = 5;
    let lens_to_test = &[3, 5, 10, 50, 100, 500, 1000, 5000, 10000];

    for test_num in 0..number_of_tests {
        for len in lens_to_test {
            println!("[------------------------ Will test {} bytes (test no {}) ------------------------]", len, test_num);
            base64_auto(*len, c);
            base64_non_auto(*len, c);
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);