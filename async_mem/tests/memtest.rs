#![feature(fundamental, mem_take, async_await, generators, generator_trait, try_trait, arbitrary_self_types, proc_macro_hygiene)]

/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */


#[macro_use]
extern crate hyxe_derive;
#[macro_use]
extern crate hyxe_util;

use futures::executor::{ThreadPool, block_on};

use async_mem::hyperobject::HyperObject;
use hyxe_util::temporal::temporal::RelativeTimeStamp;




const empty: u8 = 0b00000000;
const empty2: u8 = 0b00000011;
const empty3: u8 = 0b00011100;
const empty4: u8 = 0b11100000;

const empty5: u8 = 0b11110000;
const empty6: u8 = 0b00001111;


#[inline]
fn pack4_4(first: u8, second: u8) -> u8 {
    (first << 4) | second
}

#[inline]
fn unpack4_4(byte: u8) -> [u8; 2] { [(byte & empty5) >> 4, byte & empty6] }

#[inline]
fn pack3_3_2(first: u8, second: u8, two_bit: u8) -> u8 {
    ((((first << 3) | second) << 2) | two_bit)
}

#[inline]
fn unpack3_3_2(byte: u8) -> [u8; 3] {
    [(byte & empty4) >> 5, (byte & empty3) >> 2, byte & empty2]
}

#[test]
fn memtest() {
    //ThreadPool::new().unwrap().run(test());
    success!("yo");
    let mut start = RelativeTimeStamp::now();
    let i = [0, 1, 2] as [u8; 3];
    let i2 = [10, 12] as [u8; 2];

    let mut packed = pack3_3_2(i[0], i[1], i[2]);
    println!("val: 0b{:08b}", packed);
    let ret = unpack3_3_2(packed);
    println!("unpacked: {:#?}", ret);
    assert_eq!(i, ret);

    let mut packed = pack4_4(i2[0], i2[1]);
    println!("val: 0b{:08b}", packed);
    let ret = unpack4_4(packed);
    println!("unpacked: {:#?}", ret);
    assert_eq!(i2, ret);

    hyxe_util::success!("Runtime: {}", start);
}

#[test]
#[runtime(limit = 10)]
fn hyxe_object() {
    for x in 0..1_000_000_0 {
        pack3_3_2(0, 0, 0);
    }
}

#[test]
#[runtime]
fn hyper_object() {
    let mut m = vec!();
    for x in 0..1_000_000_0 {
        m.push(HyperObject::control(x));
    }
}

#[test]
fn test_hyperobject() {
    ThreadPool::new().unwrap().run(async {
        unsafe {
            let evos = "YOLO SWAG";
            let mut obj = HyperObject::control(evos).unwrap();
            obj.replace("YOLO,", "GO");
            let mut m = &mut *obj;
            m = &mut "yolooo";
            assert_eq!(obj.remove_inner(Some("MMMM")), Some(evos));
            *obj = "GGG";

            let mut ve = Vec::new();
            for n in 0..1000 {
                let mut ob = obj.replicate().await;
                ve.push(ob);
            }
        }
    });
}

#[test]
fn mutex_test() {
    let my_x: u16 = 100;
    let mut wrapper = RwLock:new(my_x);
    for x in 0..u16::max_value() {
        wrapper.lock().and_then(|r| {
            *r = x;
        });
    }
}
