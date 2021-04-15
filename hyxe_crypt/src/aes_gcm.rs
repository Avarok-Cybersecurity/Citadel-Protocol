use futures::Future;
use futures::task::{Context, Poll};
use std::pin::Pin;
use crate::prelude::{Drill, PostQuantumContainer, CryptError};

/// holds the the drill (0), the post quantum container (1), the nonce version (2), as well as the input bytes to be encrypted (3)
pub struct AesGcmEncryptor<'a, T: AsRef<[u8]> + 'a>(pub &'a Drill, pub &'a PostQuantumContainer, pub usize, pub T);

impl<'a, T: AsRef<[u8]> + 'a> Future for AesGcmEncryptor<'a, T> {
    type Output = Result<Vec<u8>, CryptError<String>>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let drill = self.0;
        Poll::Ready(drill.aes_gcm_encrypt(self.2, self.1, self.3.as_ref()))
    }
}

/// holds the the drill (0), the post quantum container (1), the nonce version (2), as well as the input bytes to be encrypted (3)
pub struct AesGcmDecryptor<'a, T: AsRef<[u8]> + 'a>(pub &'a Drill, pub &'a PostQuantumContainer, pub usize, pub T);

impl<'a, T: AsRef<[u8]> + 'a> Future for AesGcmDecryptor<'a, T> {
    type Output = Result<Vec<u8>, CryptError<String>>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let drill = self.0;
        Poll::Ready(drill.aes_gcm_decrypt(self.2, self.1, self.3.as_ref()))
    }
}