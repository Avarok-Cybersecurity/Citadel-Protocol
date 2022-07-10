#![cfg(not(coverage))]
use hyxe_crypt::prelude::SecBuffer;

#[allow(dead_code)]
fn main() {
    let buf = SecBuffer::from("Hello, world!");
    let serde = bincode2::serialize(&buf).unwrap();
    std::mem::drop(buf);
    let buf = bincode2::deserialize::<SecBuffer>(&serde).unwrap();

    assert_eq!(buf.as_ref(), b"Hello, world!");
    let cloned = buf.clone();
    let ptr = cloned.as_ref().as_ptr();
    let len = cloned.as_ref().len();
    let ptr_slice = unsafe { std::slice::from_raw_parts(ptr, len) };

    assert_eq!(cloned.as_ref(), ptr_slice);
    let retrieved = buf.into_buffer();

    assert_eq!(&*retrieved, b"Hello, world!");
}
