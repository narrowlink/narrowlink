pub use async_tools::{AsyncToStream, StreamToAsync};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
use std::{
    pin::Pin,
    task::{ready, Poll},
};

mod async_tools;
pub mod error;
pub mod event;
pub mod p2p;
pub mod transport;
pub mod ws;
use error::NetworkError;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub trait AsyncSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T> AsyncSocket for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub trait UniversalStream<S, E>:
    Stream<Item = Result<S, E>> + Sink<S, Error = E> + Unpin + Send + 'static
{
}
impl<S, E, T> UniversalStream<S, E> for T where
    T: Stream<Item = Result<S, E>> + Sink<S, Error = E> + Unpin + Send + 'static
{
}

pub async fn stream_forward(
    left: impl UniversalStream<Vec<u8>, NetworkError>,
    right: impl UniversalStream<Vec<u8>, NetworkError>,
) -> Result<(), NetworkError> {
    let (mut left_tx, mut left_rx) = left.split();
    let (mut right_tx, mut right_rx) = right.split();

    loop {
        tokio::select! {
            res = left_rx.next() => {
                match res{
                    Some(v)=>right_tx.send(v?).await?,
                    None=>{
                        let _ = left_tx.close().await;
                        let _ = right_tx.close().await;
                        return Ok(())
                    }
                };
            },
            res = right_rx.next() => {
                match res{
                    Some(v)=>left_tx.send(v?).await?,
                    None=>{
                        let _ = left_tx.close().await;
                        let _ = right_tx.close().await;
                        return Ok(())
                    }
                };
            },
        }
    }
}

pub async fn async_forward(
    left: impl AsyncSocket,
    right: impl AsyncSocket,
) -> Result<(), NetworkError> {
    let (mut left_rx, mut left_tx) = tokio::io::split(left);
    let (mut right_rx, mut right_tx) = tokio::io::split(right);
    loop {
        tokio::select! {
            res = tokio::io::copy(&mut left_rx, &mut right_tx) => {
                if res? == 0 {
                    let _ = left_tx.shutdown().await;
                    let _ = right_tx.shutdown().await;
                    return Ok(())
                }
            },
            res = tokio::io::copy(&mut right_rx, &mut left_tx) => {
                if res? == 0 {
                    let _ = left_tx.shutdown().await;
                    let _ = right_tx.shutdown().await;
                    return Ok(())
                }
            },
        }
    }
}

const MAX_ENCRYPTED_LEN: usize = 65536 + 16 + 2; // 16 is the size of the tag + 2 is the size of the length
pub struct AsyncSocketCrypt {
    inner: Box<dyn AsyncSocket>,
    cipher: XChaCha20Poly1305,
    nonce: [u8; 24],
    encrypted_receive_buf: Option<(Vec<u8>, u16)>, // encrypted, expected_len
    plaintext_receive_buf: Option<Vec<u8>>,
    send_buf: Option<(Vec<u8>, u16)>, // encrypted, original_len
}

impl AsyncSocketCrypt {
    pub async fn new(key: [u8; 32], nonce: [u8; 24], inner: Box<dyn AsyncSocket>) -> Self {
        let cipher = XChaCha20Poly1305::new(&key.into());
        Self {
            inner,
            cipher,
            nonce,
            encrypted_receive_buf: None,
            plaintext_receive_buf: None,
            send_buf: None,
        }
    }
}

impl AsyncRead for AsyncSocketCrypt {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if let Some(mut plaintext_buf) = self.plaintext_receive_buf.take() {
                if plaintext_buf.len() > buf.remaining() {
                    if buf.remaining() == 0 {
                        self.plaintext_receive_buf = Some(plaintext_buf);
                        return Poll::Pending;
                    }
                    let remaining = plaintext_buf.split_off(buf.remaining());
                    buf.put_slice(&plaintext_buf);
                    self.plaintext_receive_buf = Some(remaining);
                    return Poll::Ready(Ok(()));
                } else {
                    buf.put_slice(&plaintext_buf);
                    return Poll::Ready(Ok(()));
                }
            }
            if let Some((mut encrypted_receive_buf, expected_len)) =
                self.encrypted_receive_buf.take()
            {
                if encrypted_receive_buf.len() >= expected_len as usize {
                    let remaining = encrypted_receive_buf.split_off(expected_len as usize);

                    if !remaining.is_empty() {
                        if remaining.len() == 1 {
                            self.encrypted_receive_buf = Some((remaining, 0));
                        } else {
                            let expected_len = u16::from_be_bytes([remaining[0], remaining[1]]);
                            self.encrypted_receive_buf =
                                Some((remaining[2..].to_vec(), expected_len));
                        }
                    }

                    self.plaintext_receive_buf = Some(
                        self.cipher
                            .decrypt(&self.nonce.into(), encrypted_receive_buf.as_slice())
                            .map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                            })?,
                    );

                    continue;
                } else {
                    self.encrypted_receive_buf = Some((encrypted_receive_buf, expected_len));
                }
            }

            let mut tmp_buf = vec![0; buf.capacity()];
            let mut tmp_buf_reader = tokio::io::ReadBuf::new(&mut tmp_buf);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf_reader)?);
            let tmp_buf = tmp_buf_reader.filled();
            if tmp_buf.is_empty() {
                return Poll::Ready(Ok(()));
            };
            if let Some((mut encrypted_buf, mut expected_len)) = self.encrypted_receive_buf.take() {
                if expected_len == 0 {
                    expected_len = u16::from_be_bytes([encrypted_buf[0], tmp_buf[0]]);
                    encrypted_buf.clear();
                }
                if tmp_buf.len() == 1 {
                    return Poll::Pending;
                }
                if tmp_buf.len() >= expected_len as usize - encrypted_buf.len() {
                    encrypted_buf
                        .extend_from_slice(&tmp_buf[..expected_len as usize - encrypted_buf.len()]);
                    self.plaintext_receive_buf = Some(
                        self.cipher
                            .decrypt(&self.nonce.into(), encrypted_buf.as_slice())
                            .map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                            })?,
                    );
                    return Poll::Ready(Ok(()));
                } else {
                    encrypted_buf.extend_from_slice(tmp_buf);
                    self.encrypted_receive_buf = Some((encrypted_buf, expected_len));
                    continue;
                    // return Poll::Pending;
                }
            } else {
                if tmp_buf.len() == 1 {
                    self.encrypted_receive_buf = Some((tmp_buf.to_vec(), 0));
                } else {
                    let expected_len = u16::from_be_bytes([tmp_buf[0], tmp_buf[1]]);
                    if tmp_buf.len() as u16 >= expected_len + 2 {
                        self.plaintext_receive_buf = Some(
                            self.cipher
                                .decrypt(&self.nonce.into(), &tmp_buf[2..expected_len as usize + 2])
                                .map_err(|e| {
                                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                                })?,
                        );
                        if tmp_buf.len() as u16 > expected_len + 2 {
                            let rest = tmp_buf[expected_len as usize + 2..].to_vec();
                            if rest.len() == 1 {
                                self.encrypted_receive_buf = Some((rest, 0));
                            } else {
                                let expected_len = u16::from_be_bytes([rest[0], rest[1]]);
                                self.encrypted_receive_buf =
                                    Some((rest[2..].to_vec(), expected_len));
                            }
                        }
                    } else {
                        self.encrypted_receive_buf = Some((tmp_buf[2..].to_vec(), expected_len));
                    }
                }
                continue;
            }
        }
    }
}

impl AsyncWrite for AsyncSocketCrypt {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        loop {
            if let Some((mut send_buf, original_len)) = self.send_buf.take() {
                match Pin::new(&mut self.inner).poll_write(cx, send_buf.as_ref())? {
                    Poll::Ready(n) => {
                        if n == send_buf.len() {
                            return Poll::Ready(Ok(original_len as usize));
                        } else {
                            self.send_buf = Some((send_buf.split_off(n), original_len));
                        }
                    }
                    Poll::Pending => {
                        self.send_buf = Some((send_buf, original_len));
                        return Poll::Pending;
                    }
                }
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let buf: &[u8] = if buf.len() > MAX_ENCRYPTED_LEN {
                &buf[..MAX_ENCRYPTED_LEN]
            } else {
                buf
            };
            let original_len = buf.len() as u16;
            let encrypted = self
                .cipher
                .encrypt(&self.nonce.into(), buf)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            self.send_buf = Some((
                [
                    (encrypted.len() as u16).to_be_bytes().as_slice(),
                    &encrypted,
                ]
                .concat(),
                original_len,
            ));
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
