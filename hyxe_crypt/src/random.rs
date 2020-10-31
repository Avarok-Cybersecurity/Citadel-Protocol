use crate::drill::{Drill, E_OF_X_START_INDEX};
use crate::misc::get_indices;
use rand::prelude::ThreadRng;

/// Trait for allowing unsigned or unsigned into to be generated. The drill serves as the pool, as well as any entropy bank (TODO: Entropy bank)
/// The input `drill_part` refers to the slice of memory inside the drill, but NOT the entire drill piece!
pub trait HyperRandom {
    /// Returns a hyper random number.
    ///
    /// Panics if `index_limit` is greater than or equal to E_OF_X_START_INDEX.
    fn random(&self, index_limit: u8) -> u8;
    /// Fills an array. Panics if `index_limit` is greater than or equal to E_OF_X_START_INDEX.
    fn fill_array(&self, array: &mut [u8], index_limit: u8);

    /// This allows adding a value so long as `input0` + `input1` is less than 2* `limit`.
    /// Adds `input1` to `input0`, and upon overflow of `limit`, wraps back to zero and
    /// adds the remainder.
    ///
    /// Panics if the the number of wraps requires is more than 1
    #[inline]
    fn wrapping_add(input0: usize, input1: usize, limit: usize) -> usize {
        assert!(input0 <= limit && input1 <= limit);
        if input0 + input1 >= limit {
            ((input1 as isize) - (input0 as isize)).abs() as usize
        } else {
            input0 + input1
        }
    }
}

impl HyperRandom for Drill {
    #[inline]
    fn random(&self, index_limit: u8) -> u8 {
        let (outer, inner) = get_indices(index_limit, &mut ThreadRng::default());
        let mut val: u8 = 0;
        let drill_part = self.get_low();
        for idx in 0..E_OF_X_START_INDEX {
            val ^= drill_part[outer[idx]][inner[idx]];
        }
        val
    }

    #[inline]
    fn fill_array(&self, array: &mut [u8], index_limit: u8) {
        let mut rng = &mut ThreadRng::default();
        let drill_part = self.get_low();
        let mut amt_left = array.len();
        let mut idx_insert = 0;
        while amt_left != 0 {
            let (outer, inner) = get_indices(index_limit, &mut rng);
            for idx in 0..index_limit as usize {
                array[idx_insert] ^= drill_part[outer[idx]][inner[idx]];
                idx_insert += 1;
            }
            amt_left -= 1;
        }
    }
}
