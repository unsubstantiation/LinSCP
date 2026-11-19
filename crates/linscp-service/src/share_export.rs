//! Bounded sink for Android's private outgoing-share downloads.
//!
//! Server metadata is not a trustworthy size limit. Enforce the limit on the
//! bytes actually written as well, so a lying or changing server cannot fill
//! the device while preparing a share.
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::io::AsyncWrite;

pub const MAX_EXPORT_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_EXPORT_FILES: usize = 32;

pub struct LimitedWriter<W> {
    inner: W,
    remaining: u64,
}

impl<W> LimitedWriter<W> {
    pub fn new(inner: W, remaining: u64) -> Self { Self { inner, remaining } }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for LimitedWriter<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() { return Poll::Ready(Ok(0)); }
        if self.remaining == 0 {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "Shared files exceed the 512 MiB limit")));
        }
        let allowed = (self.remaining.min(buf.len() as u64)) as usize;
        match Pin::new(&mut self.inner).poll_write(cx, &buf[..allowed]) {
            Poll::Ready(Ok(written)) => {
                self.remaining -= written as u64;
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::LimitedWriter;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn writer_rejects_excess_without_writing_it() {
        let mut bytes = Vec::new();
        let mut writer = LimitedWriter::new(&mut bytes, 3);
        assert!(writer.write_all(b"abcd").await.is_err());
        drop(writer);
        assert_eq!(bytes, b"abc");
    }

    #[tokio::test]
    async fn writer_allows_empty_and_exact_limit() {
        let mut bytes = Vec::new();
        let mut writer = LimitedWriter::new(&mut bytes, 3);
        writer.write_all(b"abc").await.unwrap();
        writer.write_all(b"").await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);
        assert_eq!(bytes, b"abc");
    }
}
