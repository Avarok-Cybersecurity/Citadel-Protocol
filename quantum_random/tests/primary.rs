/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use futures::executor::block_on;
use quantum_random::prelude::*;

#[test]
fn fetch() {
    let number_to_get = 10240;
    match block_on(next_u8s(number_to_get)) {
        Ok(vals) => {
            for val in vals.iter().enumerate() {
                println!("[{}]: {}", val.0, val.1);
            }
            assert_eq!(vals.len(), number_to_get);
        },
        Err(err) => {
            println!("Error");
        }
    }
}