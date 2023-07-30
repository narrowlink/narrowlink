use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{error::NetworkError, AsyncSocket, UniversalStream};
use futures_util::{Future, Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct AsyncToStream {
    socket: Box<dyn AsyncSocket>,
    buffer: Option<(usize, Vec<u8>)>,
}

impl AsyncToStream {
    pub fn new(socket: impl AsyncSocket) -> Self {
        Self {
            socket: Box::new(socket),
            buffer: None,
        }
    }
}

impl Stream for AsyncToStream {
    type Item = Result<Vec<u8>, NetworkError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut buf = [0u8; 65536];
        let mut buffer = ReadBuf::new(&mut buf);
        match Pin::new(&mut self.socket).poll_read(cx, &mut buffer)? {
            Poll::Ready(_) => {
                if buffer.filled().is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(buffer.filled().to_vec())))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Vec<u8>> for AsyncToStream {
    type Error = NetworkError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some((mut len, buffer)) = self.buffer.take() {
            loop {
                len = match Pin::new(&mut self.socket).poll_write(cx, &buffer)? {
                    Poll::Ready(written) => written,
                    Poll::Pending => return Poll::Pending,
                };
                if len == buffer.len() {
                    break;
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.buffer = Some((0, item));
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let _ = Pin::new(&mut self).poll_ready(cx)?;
        Pin::new(&mut self.socket)
            .poll_flush(cx)
            .map_err(|e| e.into())
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let _ = Pin::new(&mut self).poll_ready(cx)?;
        Pin::new(&mut self.socket)
            .poll_shutdown(cx)
            .map_err(|e| e.into())
    }
}

pub struct StreamToAsync {
    stream: Box<dyn UniversalStream<Vec<u8>, NetworkError>>,
    remaining_bytes: Option<Vec<u8>>,
}
impl StreamToAsync {
    pub fn new(socket: impl UniversalStream<Vec<u8>, NetworkError>) -> Self {
        Self {
            stream: Box::new(socket),
            remaining_bytes: None,
        }
    }
}
impl AsyncRead for StreamToAsync {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if let Some(mut remaining_buf) = self.remaining_bytes.take() {
                if buf.remaining() < remaining_buf.len() {
                    self.remaining_bytes = Some(remaining_buf.split_off(buf.remaining()));
                    buf.put_slice(&remaining_buf);
                } else {
                    buf.put_slice(&remaining_buf);
                    self.remaining_bytes = None;
                }
                return Poll::Ready(Ok(()));
            }

            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(d))) => {
                    self.remaining_bytes = Some(d);
                    continue;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )))
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            };
        }
    }
}

impl AsyncWrite for StreamToAsync {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match Pin::new(&mut self.stream.send(buf.to_vec()))
            .poll(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
        {
            Poll::Ready(_) => Poll::Ready(Ok(buf.len())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.stream
            .poll_flush_unpin(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.stream
            .poll_close_unpin(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))
    }
}
