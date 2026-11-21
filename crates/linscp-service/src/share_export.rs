//! Bounded sink for Android's private outgoing-share downloads.
//!
//! Server metadata is not a trustworthy size limit. Enforce the limit on the
//! bytes actually written as well, so a lying or changing server cannot fill
//! the device while preparing a share.
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;

pub const MAX_EXPORT_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_EXPORT_FILES: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct ShareExportStatus {
    pub active: bool,
    pub cancelled: bool,
    pub files_done: usize,
    pub files_total: usize,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub current_file: String,
    pub error: Option<String>,
}

pub struct LimitedWriter<W> {
    inner: W,
    remaining: u64,
    cancel: Option<Arc<AtomicBool>>,
    progress_bytes: Option<Arc<AtomicU64>>,
}

impl<W> LimitedWriter<W> {
    pub fn new(inner: W, remaining: u64) -> Self {
        Self {
            inner,
            remaining,
            cancel: None,
            progress_bytes: None,
        }
    }

    pub fn with_tracking(
        inner: W,
        remaining: u64,
        cancel: Arc<AtomicBool>,
        progress_bytes: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            remaining,
            cancel: Some(cancel),
            progress_bytes: Some(progress_bytes),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for LimitedWriter<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if let Some(ref c) = self.cancel {
            if c.load(Ordering::Acquire) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Share export cancelled by user.",
                )));
            }
        }
        if buf.is_empty() { return Poll::Ready(Ok(0)); }
        if self.remaining == 0 {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "Shared files exceed the 512 MiB limit")));
        }
        let allowed = (self.remaining.min(buf.len() as u64)) as usize;
        match Pin::new(&mut self.inner).poll_write(cx, &buf[..allowed]) {
            Poll::Ready(Ok(written)) => {
                self.remaining -= written as u64;
                if let Some(ref counter) = self.progress_bytes {
                    counter.fetch_add(written as u64, Ordering::Release);
                }
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
