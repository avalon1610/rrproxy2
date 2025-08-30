use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct PreBuffered<S> {
    buffer: hyper::body::Bytes,
    pos: usize,
    inner: S,
}

impl<S> PreBuffered<S> {
    pub(crate) fn new(buffer: hyper::body::Bytes, inner: S) -> Self {
        PreBuffered {
            buffer,
            pos: 0,
            inner,
        }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buffer.len()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PreBuffered<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        if !me.is_empty() {
            let remaining = &me.buffer[me.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            if to_copy > 0 {
                buf.put_slice(&remaining[..to_copy]);
                me.pos += to_copy;
            }

            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PreBuffered<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
