/// In this crate, I give an iterator for each [DrillType] as well as each [SecurityLevel] in order to reduce the number of JMP/JE assembly calls
pub(crate) mod async_decryptors {
    use crate::drill::{E_OF_X_START_INDEX, PORT_RANGE};
    use std::pin::Pin;
    use futures::Stream;
    use std::task::Context;
    use crate::prelude::Drill;
    use futures::task::Poll;

    /// input order: encrypted bytes, drill reference, chunk size, j_rand, cursor index
    pub(crate) struct DrillStandardAsyncDecryptorLow<'a>(pub &'a [u8], pub &'a [[u8; PORT_RANGE]; E_OF_X_START_INDEX], pub usize, pub u8, pub usize);

    impl<'a> Stream for DrillStandardAsyncDecryptorLow<'a> {
        type Item = u8;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let arr_pos = self.4 * self.2; //cursor times chunk size
            if arr_pos == self.0.len() {
                Poll::Ready(None)
            } else {
                let range = arr_pos..(arr_pos+self.2);
                let j_rand = self.3;
                let cursor = self.4;
                let sub_drill = self.1;
                let encrypted_bytes = &self.0[range];
                let ret = Drill::decrypt_1byte_chunk(sub_drill, cursor % PORT_RANGE, j_rand, encrypted_bytes);
                self.4 += 1;
                Poll::Ready(Some(ret))
            }
        }
    }

    /// input order: encrypted bytes, drill reference, chunk size, j_rand, cursor index
    pub(crate) struct DrillStandardAsyncDecryptorMedium<'a>(pub &'a [u8], pub &'a [[u16; PORT_RANGE]; E_OF_X_START_INDEX], pub usize, pub u16, pub usize);

    impl<'a> Stream for DrillStandardAsyncDecryptorMedium<'a> {
        type Item = u8;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let arr_pos = self.4 * self.2; //cursor times chunk size
            if arr_pos == self.0.len() {
                Poll::Ready(None)
            } else {
                let range = arr_pos..(arr_pos+self.2);
                let j_rand = self.3;
                let cursor = self.4;
                let sub_drill = self.1;
                let encrypted_bytes = &self.0[range];
                let ret = Drill::decrypt_2byte_chunk(sub_drill, cursor % PORT_RANGE, j_rand, encrypted_bytes);
                self.4 += 1;
                Poll::Ready(Some(ret))
            }
        }
    }

    /// input order: encrypted bytes, drill reference, chunk size, j_rand, cursor index
    pub(crate) struct DrillStandardAsyncDecryptorHigh<'a>(pub &'a [u8], pub &'a [[u32; PORT_RANGE]; E_OF_X_START_INDEX], pub usize, pub u32, pub usize);

    impl<'a> Stream for DrillStandardAsyncDecryptorHigh<'a> {
        type Item = u8;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let arr_pos = self.4 * self.2; //cursor times chunk size
            if arr_pos == self.0.len() {
                Poll::Ready(None)
            } else {
                let range = arr_pos..(arr_pos+self.2);
                let j_rand = self.3;
                let cursor = self.4;
                let sub_drill = self.1;
                let encrypted_bytes = &self.0[range];
                let ret = Drill::decrypt_4byte_chunk(sub_drill, cursor % PORT_RANGE, j_rand, encrypted_bytes);
                self.4 += 1;
                Poll::Ready(Some(ret))
            }
        }
    }

    /// input order: encrypted bytes, drill reference, chunk size, j_rand, cursor index
    pub(crate) struct DrillStandardAsyncDecryptorUltra<'a>(pub &'a [u8], pub &'a [[u64; PORT_RANGE]; E_OF_X_START_INDEX], pub usize, pub u64, pub usize);

    impl<'a> Stream for DrillStandardAsyncDecryptorUltra<'a> {
        type Item = u8;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let arr_pos = self.4 * self.2; //cursor times chunk size
            if arr_pos == self.0.len() {
                Poll::Ready(None)
            } else {
                let range = arr_pos..(arr_pos+self.2);
                let j_rand = self.3;
                let cursor = self.4;
                let sub_drill = self.1;
                let encrypted_bytes = &self.0[range];
                let ret = Drill::decrypt_8byte_chunk(sub_drill, cursor % PORT_RANGE, j_rand, encrypted_bytes);
                self.4 += 1;
                Poll::Ready(Some(ret))
            }
        }
    }

    /// input order: encrypted bytes, drill reference, chunk size, j_rand, cursor index
    pub(crate) struct DrillStandardAsyncDecryptorDivine<'a>(pub &'a [u8], pub &'a [[u128; PORT_RANGE]; E_OF_X_START_INDEX], pub usize, pub u128, pub usize);

    impl<'a> Stream for DrillStandardAsyncDecryptorDivine<'a> {
        type Item = u8;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let arr_pos = self.4 * self.2; //cursor times chunk size
            if arr_pos == self.0.len() {
                Poll::Ready(None)
            } else {
                let range = arr_pos..(arr_pos+self.2);
                let j_rand = self.3;
                let cursor = self.4;
                let sub_drill = self.1;
                let encrypted_bytes = &self.0[range];
                let ret = Drill::decrypt_16byte_chunk(sub_drill, cursor % PORT_RANGE, j_rand, encrypted_bytes);
                self.4 += 1;
                Poll::Ready(Some(ret))
            }
        }
    }
}