use std::{pin::Pin, task::{Context, Poll}};

use tokio::io::{AsyncRead, AsyncWrite};

pub struct InputStream {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
}

impl Default for InputStream {
    fn default() -> Self {
        InputStream {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
        }
    }
}

impl AsyncRead for InputStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stdin).poll_read(ctx, buf)
    }
}

impl AsyncWrite for InputStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stdout).poll_write(ctx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stdout).poll_flush(ctx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stdout).poll_shutdown(ctx)
    }
}
