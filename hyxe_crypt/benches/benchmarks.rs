/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

#[macro_use]
extern crate criterion;

use criterion::{Criterion, ParameterizedBenchmark, Benchmark};

pub const original_text: &'static [u8] = b"Hello World! This is a test";

pub use hyxe_crypt::simd::*;
pub use std::time::Instant;
pub use packed_simd::u8x4;
pub use std::ops::DerefMut;

pub use hyxe_crypt::prelude::*;
pub use futures::executor::block_on;
pub use zerocopy::AsBytes;
use std::pin::Pin;

fn enc_low_std() {
    unsafe { drill.as_ref().unwrap().encrypt_to_vec(original_text, 1, SecurityLevel::LOW).unwrap(); }
}

fn enc_low_par() {
    unsafe { drill.as_ref().unwrap().par_encrypt_to_vec(original_text, 1, SecurityLevel::LOW).unwrap(); }
}

fn enc_med_std() {
    unsafe { drill.as_ref().unwrap().encrypt_to_vec(original_text, 1, SecurityLevel::MEDIUM).unwrap(); }
}

fn enc_med_par() {
    unsafe { drill.as_ref().unwrap().par_encrypt_to_vec(original_text, 1, SecurityLevel::MEDIUM).unwrap(); }
}

fn enc_high_std() {
    unsafe { drill.as_ref().unwrap().encrypt_to_vec(original_text, 1, SecurityLevel::HIGH).unwrap(); }
}

fn enc_high_par() {
    unsafe { drill.as_ref().unwrap().par_encrypt_to_vec(original_text, 1, SecurityLevel::HIGH).unwrap(); }
}

fn enc_ultra_std() {
    unsafe { drill.as_ref().unwrap().encrypt_to_vec(original_text, 1, SecurityLevel::ULTRA).unwrap(); }
}

fn enc_ultra_par() {
    unsafe { drill.as_ref().unwrap().par_encrypt_to_vec(original_text, 1, SecurityLevel::ULTRA).unwrap(); }
}

fn enc_divine_std() {
    unsafe { drill.as_ref().unwrap().encrypt_to_vec(original_text, 1, SecurityLevel::DIVINE).unwrap(); }
}

fn enc_divine_par() {
    unsafe { drill.as_ref().unwrap().par_encrypt_to_vec(original_text, 1, SecurityLevel::DIVINE).unwrap(); }
}

static mut encrypted_message_low: Vec<u8> = Vec::new();
static mut encrypted_message_med: Vec<u8> = Vec::new();
static mut encrypted_message_high: Vec<u8> = Vec::new();
static mut encrypted_message_ultra: Vec<u8> = Vec::new();
static mut encrypted_message_divine: Vec<u8> = Vec::new();

fn dec_low_std() {
    unsafe { drill.as_ref().unwrap().decrypt_to_vec(encrypted_message_low.as_slice(), 1, SecurityLevel::LOW).unwrap(); }
}

fn dec_low_par() {
    unsafe { drill.as_ref().unwrap().par_decrypt_to_vec(encrypted_message_low.as_slice(), 1, SecurityLevel::LOW).unwrap(); }
}

fn dec_med_std() {
    unsafe { drill.as_ref().unwrap().decrypt_to_vec(encrypted_message_med.as_slice(), 1, SecurityLevel::MEDIUM).unwrap(); }
}

fn dec_med_par() {
    unsafe { drill.as_ref().unwrap().par_decrypt_to_vec(encrypted_message_med.as_slice(), 1, SecurityLevel::MEDIUM).unwrap(); }
}

fn dec_high_std() {
    unsafe { drill.as_ref().unwrap().decrypt_to_vec(encrypted_message_high.as_slice(), 1, SecurityLevel::HIGH).unwrap(); }
}

fn dec_high_par() {
    unsafe { drill.as_ref().unwrap().par_decrypt_to_vec(encrypted_message_high.as_slice(), 1, SecurityLevel::HIGH).unwrap(); }
}

fn dec_ultra_std() {
    unsafe { drill.as_ref().unwrap().decrypt_to_vec(encrypted_message_ultra.as_slice(), 1, SecurityLevel::ULTRA).unwrap(); }
}

fn dec_ultra_par() {
    unsafe { drill.as_ref().unwrap().par_decrypt_to_vec(encrypted_message_ultra.as_slice(), 1, SecurityLevel::ULTRA).unwrap(); }
}

fn dec_divine_std() {
    unsafe { drill.as_ref().unwrap().decrypt_to_vec(encrypted_message_divine.as_slice(), 1, SecurityLevel::DIVINE).unwrap(); }
}

fn dec_divine_par() {
    unsafe { drill.as_ref().unwrap().par_decrypt_to_vec(encrypted_message_divine.as_slice(), 1, SecurityLevel::DIVINE).unwrap(); }
}

static mut drill: Option<Drill> = None;

///Main function
fn criterion_benchmark(c: &mut Criterion) {
    unsafe {
        let drill0 = block_on(async {
            Drill::new(101, 0).await
        }).unwrap();

        encrypted_message_low = drill0.encrypt_to_vec(original_text, 1, SecurityLevel::LOW).unwrap();
        encrypted_message_med = drill0.encrypt_to_vec(original_text, 1, SecurityLevel::MEDIUM).unwrap();
        encrypted_message_high = drill0.encrypt_to_vec(original_text, 1, SecurityLevel::HIGH).unwrap();
        encrypted_message_ultra = drill0.encrypt_to_vec(original_text, 1, SecurityLevel::ULTRA).unwrap();
        encrypted_message_divine = drill0.encrypt_to_vec(original_text, 1, SecurityLevel::DIVINE).unwrap();
        drill = Some(drill0);
    }

    c.bench(
        "Encryption benches",
        Benchmark::new("enc_low_std", |b| b.iter(|| enc_low_std()))
            .with_function("enc_low_par", |b| b.iter(|| enc_low_par()))
            .with_function("enc_med_std", |b| b.iter(|| enc_med_std()))
            .with_function("enc_med_par", |b| b.iter(|| enc_med_par()))
            .with_function("enc_high_std", |b| b.iter(|| enc_high_std()))
            .with_function("enc_high_par", |b| b.iter(|| enc_high_par()))
            .with_function("enc_ultra_std", |b| b.iter(|| enc_ultra_std()))
            .with_function("enc_ultra_par", |b| b.iter(|| enc_ultra_par()))
            .with_function("enc_divine_std", |b| b.iter(|| enc_divine_std()))
            .with_function("enc_divine_par", |b| b.iter(|| enc_divine_par())),
    );

    c.bench(
        "Decryption benches",
        Benchmark::new("dec_low_std", |b| b.iter(|| dec_low_std()))
            .with_function("dec_low_par", |b| b.iter(|| dec_low_par()))
            .with_function("dec_med_std", |b| b.iter(|| dec_med_std()))
            .with_function("dec_med_par", |b| b.iter(|| dec_med_par()))
            .with_function("dec_high_std", |b| b.iter(|| dec_high_std()))
            .with_function("dec_high_par", |b| b.iter(|| dec_high_par()))
            .with_function("dec_ultra_std", |b| b.iter(|| dec_ultra_std()))
            .with_function("dec_ultra_par", |b| b.iter(|| dec_ultra_par()))
            .with_function("dec_divine_std", |b| b.iter(|| dec_divine_std()))
            .with_function("dec_divine_par", |b| b.iter(|| dec_divine_par())),
    );
}
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);