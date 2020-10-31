pub(crate) mod async_encryptors {
    use crate::drill::{E_OF_X_START_INDEX, PORT_RANGE, DrillEndian};
    use std::pin::Pin;
    use futures::Stream;
    use std::task::Context;
    use byteorder::ByteOrder;
    use crate::prelude::Drill;
    use futures::task::Poll;

    /// Order: unencrypted bytes, subdrill reference, j_rand, internal cursor
    pub(crate) struct DrillStandardAsyncEncryptorLow<'a>(pub &'a [u8], pub &'a [[u8; PORT_RANGE]; E_OF_X_START_INDEX], pub u8, pub usize);

    impl<'a> Stream for DrillStandardAsyncEncryptorLow<'a> {
        type Item = ([u8; 1], usize);

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let cursor = self.3;
            let input = self.0;
            if cursor != input.len() {
                let subdrill = self.1;
                let ret = Drill::encrypt_u8_to_u8(input[cursor], subdrill, self.2, cursor % PORT_RANGE);
                self.3 += 1;
                Poll::Ready(Some(([ret], cursor)))
            } else {
                Poll::Ready(None)
            }
        }
    }

    /// Order: unencrypted bytes, subdrill reference, j_rand, internal cursor
    pub(crate) struct DrillStandardAsyncEncryptorMedium<'a>(pub &'a [u8], pub &'a [[u16; PORT_RANGE]; E_OF_X_START_INDEX], pub u16, pub usize);

    impl<'a> Stream for DrillStandardAsyncEncryptorMedium<'a> {
        type Item = ([u8; 2], usize);

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let cursor = self.3;
            let input = self.0;
            if cursor != input.len() {
                let subdrill = self.1;
                let mut ret: [u8; 2] = [0; 2];
                DrillEndian::write_u16(&mut ret,Drill::encrypt_u8_to_u16(input[cursor], subdrill, self.2, cursor % PORT_RANGE));
                self.3 += 1;
                Poll::Ready(Some((ret, cursor)))
            } else {
                Poll::Ready(None)
            }
        }
    }

    /// Order: unencrypted bytes, subdrill reference, j_rand, internal cursor
    pub(crate) struct DrillStandardAsyncEncryptorHigh<'a>(pub &'a [u8], pub &'a [[u32; PORT_RANGE]; E_OF_X_START_INDEX], pub u32, pub usize);

    impl<'a> Stream for DrillStandardAsyncEncryptorHigh<'a> {
        type Item = ([u8; 4], usize);

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let cursor = self.3;
            let input = self.0;
            if cursor != input.len() {
                let subdrill = self.1;
                let mut ret: [u8; 4] = [0; 4];
                DrillEndian::write_u32(&mut ret,Drill::encrypt_u8_to_u32(input[cursor], subdrill, self.2, cursor % PORT_RANGE));
                self.3 += 1;
                Poll::Ready(Some((ret, cursor)))
            } else {
                Poll::Ready(None)
            }
        }
    }

    /// Order: unencrypted bytes, subdrill reference, j_rand, internal cursor
    pub(crate) struct DrillStandardAsyncEncryptorUltra<'a>(pub &'a [u8], pub &'a [[u64; PORT_RANGE]; E_OF_X_START_INDEX], pub u64, pub usize);

    impl<'a> Stream for DrillStandardAsyncEncryptorUltra<'a> {
        type Item = ([u8; 8], usize);

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let cursor = self.3;
            let input = self.0;
            if cursor != input.len() {
                let subdrill = self.1;
                let mut ret: [u8; 8] = [0; 8];
                DrillEndian::write_u64(&mut ret,Drill::encrypt_u8_to_u64(input[cursor], subdrill, self.2, cursor % PORT_RANGE));
                self.3 += 1;
                Poll::Ready(Some((ret, cursor)))
            } else {
                Poll::Ready(None)
            }
        }
    }

    /// Order: unencrypted bytes, subdrill reference, j_rand, internal cursor
    pub(crate) struct DrillStandardAsyncEncryptorDivine<'a>(pub &'a [u8], pub &'a [[u128; PORT_RANGE]; E_OF_X_START_INDEX], pub u128, pub usize);

    impl<'a> Stream for DrillStandardAsyncEncryptorDivine<'a> {
        type Item = ([u8; 16], usize);

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<Option<Self::Item>> {
            let cursor = self.3;
            let input = self.0;
            if cursor != input.len() {
                let subdrill = self.1;
                let mut ret: [u8; 16] = [0; 16];
                DrillEndian::write_u128(&mut ret,Drill::encrypt_u8_to_u128(input[cursor], subdrill, self.2, cursor % PORT_RANGE));
                self.3 += 1;
                Poll::Ready(Some((ret, cursor)))
            } else {
                Poll::Ready(None)
            }
        }
    }
}