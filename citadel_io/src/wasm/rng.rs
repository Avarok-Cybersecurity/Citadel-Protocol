use rand::{CryptoRng, Error, RngCore};

#[derive(Default)]
pub struct WasmRng;

impl RngCore for WasmRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_be_bytes(random_array::<4>())
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_be_bytes(random_array::<8>())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).unwrap();
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::getrandom(dest).map_err(|err| Error::from(err.code()))
    }
}

impl CryptoRng for WasmRng {}

fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).unwrap();
    bytes
}
