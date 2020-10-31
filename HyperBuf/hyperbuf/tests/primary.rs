#![feature(async_await, slice_from_raw_parts)]
/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution. 
 */

#[macro_use]
extern crate hyperbuf_derive;

use std::mem::size_of_val;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use async_std::task::block_on;

use bytes::{BigEndian, ByteOrder, LittleEndian};
use bytes::BufMut;
use parking_lot::Mutex;

use hyperbuf::prelude::{ReadVisitor, WriteVisitor};

use hyperbuf::prelude::*;
use std::fmt::{Display, Formatter, Error};
use std::marker::PhantomData;
use std::borrow::BorrowMut;
use std::collections::HashMap;
use hyperbuf::Txx;

fn print_all(txx: &Txx) {
    let ptr = txx as *const Txx as *const u8;
    let size = std::mem::size_of::<Txx>();

    for x in 0..(size as isize) {
        println!("TXX_VAL {}", unsafe { *ptr.offset(x) });
    }
}

#[test]
fn vectors_iter() {
    let i0 = Txx::new(0);
    let i1 = Txx::new(1);
    let i2 = Txx::new(10);

    let items = &[i0, i1, i2];
    for x in 0..10 {
        vectors(items, x);
    }
}

fn vectors(items: &[Txx;3], idx: usize){
    let file_pos = "C:\\Users\\tbrau\\test.h";

    let mut wrapper = HyperVec::wrap(items);

    println!("{}", wrapper);
    let wrapper_ref = unsafe { wrapper.upgrade_ref() };

    let mut read = wrapper_ref.cast::<Txx>().unwrap();

    block_on(read.visit(|mut read| {
        let m = read.read_array().unwrap();
        let mut i = 0;
        let v1 = &m[0];
        let v2 = &m[1];
        let v3 = &m[2];

        Ok((Some(Box::new(*v3)), read))
    })).unwrap();

}

#[test]
fn public_display_of_action() {
    // Load some random data into a struct
    let i0 = Txx::new(0);
    let i1 = Txx::new(1);
    let i2 = Txx::new(10);


    let items = [i0, i1, i2];
    // Wrap around the array
    let mut wrapper = HyperVec::wrap(&items);

    // For demonstration purposes, we'll count the bytes in the structures
    let mut byte_count = 0;
    for item in &items {
        byte_count += std::mem::size_of_val(item);
    }

    let wrapper = &mut wrapper;

    println!("Byte count (u8s): {}", byte_count);
    let reader = wrapper.cast::<u8>().unwrap();
    let writer = wrapper.cast_mut::<Txx>().unwrap();

    rayon::scope(move |sc| {
        sc.spawn(move |sc2| {
            block_on(reader.visit(|mut reader| {
                let bytes = reader.read_array().unwrap();
                //thread::sleep(Duration::from_millis(50));
                println!("READ: {}", bytes[0]);
                Ok((None, reader))
            })).unwrap();
        });

        sc.spawn(move |sc2| {
            block_on(writer.visit(Some(4 * std::mem::size_of::<Txx>()), move |mut writer| {
                // DO NOT BLOCK HEREIN
                let objects: &mut [Txx] = writer.write_array().unwrap();
                assert_eq!(objects.len(), items.len());

                writer.append(Txx::new(100));
                writer.append_all(&items);

                let objects: &mut [Txx] = writer.write_array().unwrap();
                assert_eq!(items.len()*2 + 1, objects.len());

                let bytes = writer.write_bytes().unwrap(); // I can declare the initial WriteVisitor to have type Txx, but it is not necessarily bound to that alone!
                // Below, we return the number of bytes written as well as the passing of ownership of the WriteVisitor instance
                Ok((writer.bytes_written(), writer))
            })).unwrap();
        });

    });
}

#[test]
fn test_dynamic_memory() {
    let my_x: u16 = 100;
    let wrapper = Mutex::new(my_x);
    for x in 0..u16::max_value() {
        let _ = block_on(async {
            *wrapper.lock() = x;
        });

        let _ = block_on(async {
            assert_eq!(*wrapper.lock(), x);
        });
    }
}