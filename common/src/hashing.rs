use ring::digest::{Context, Digest, SHA256, SHA384, SHA512};
use std::{io::Read, pin::Pin, task::Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tracing::instrument;

pub struct HashingRead<R> {
    inner: R,
    contexts: Contexts,
}

pub struct Contexts {
    sha512: Context,
    sha384: Context,
    sha256: Context,
    size: u64,
}

impl Contexts {
    pub fn new() -> Self {
        Self {
            sha512: Context::new(&SHA512),
            sha384: Context::new(&SHA384),
            sha256: Context::new(&SHA256),
            size: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.sha512.update(data);
        self.sha384.update(data);
        self.sha256.update(data);
        self.size += data.len() as u64;
    }

    pub fn digests(&self) -> Digests {
        Digests {
            sha512: self.sha512.clone().finish(),
            sha384: self.sha384.clone().finish(),
            sha256: self.sha256.clone().finish(),
            size: self.size,
        }
    }

    pub fn finish(self) -> Digests {
        Digests {
            sha512: self.sha512.finish(),
            sha384: self.sha384.finish(),
            sha256: self.sha256.finish(),
            size: self.size,
        }
    }
}

impl Default for Contexts {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Digests {
    pub sha512: Digest,
    pub sha384: Digest,
    pub sha256: Digest,
    pub size: u64,
}

impl Digests {
    #[instrument(skip_all, fields(len=data.as_ref().len()))]
    pub fn digest(data: impl AsRef<[u8]>) -> Self {
        let mut contexts = Contexts::new();
        contexts.update(data.as_ref());
        contexts.finish()
    }
}

impl<R> HashingRead<R> {
    /// Creates a HashingRead that uses SHA-512, SHA-384, and SHA-256
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            contexts: Contexts::new(),
        }
    }
}

impl<R> HashingRead<R> {
    /// Returns the current digests of the **data read so far**
    pub fn digests(&self) -> Digests {
        self.contexts.digests()
    }
}

impl<R: Read> HashingRead<R> {
    /// Finishes reading all data from the inner reader and returns the digests
    /// Takes ownership of self to prevent misuse
    pub fn finish(mut self) -> std::io::Result<Digests> {
        self.read_to_end(&mut Vec::new())?;
        Ok(self.contexts.finish())
    }
}

impl<R: Read> Read for HashingRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.inner.read(buf)?;
        self.contexts.update(&buf[0..len]);
        Ok(len)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for HashingRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        let pre_len = buf.filled().len();

        let pinned = Pin::new(&mut this.inner);
        let poll = pinned.poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &poll {
            let filled = &buf.filled()[pre_len..];
            this.contexts.update(filled);
        }

        poll
    }
}

#[cfg(test)]
mod test {
    use super::HashingRead;
    use rand::Rng;
    use ring::digest::{SHA256, SHA384, SHA512, digest};
    use std::io::Read;

    fn rand_bytes() -> [u8; 1024] {
        let mut buf = [0u8; 1024];
        rand::rng().fill_bytes(&mut buf);
        buf
    }

    /// HashingRead should read data correctly
    #[test]
    fn read() {
        let data = rand_bytes();
        let mut reader = HashingRead::new(data.as_slice());
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    /// HashingRead should consume the reader entirely and return the correct hash when finish() is called
    #[test]
    fn reader_finish() {
        let data = rand_bytes();
        let reader = HashingRead::new(data.as_slice());
        let digests = reader.finish().unwrap(); // This should !!! consume the reader entirely !!! and return the digest
        assert_eq!(digest(&SHA256, &data).as_ref(), digests.sha256.as_ref());
        assert_eq!(digest(&SHA384, &data).as_ref(), digests.sha384.as_ref());
        assert_eq!(digest(&SHA512, &data).as_ref(), digests.sha512.as_ref());
    }

    /// HashingRead should return the correct hash of the data read so far when hash() is called
    #[test]
    fn intermediate_digests() {
        let data = rand_bytes();
        let mut reader = HashingRead::new(data.as_ref());
        let mut buf = Vec::new();
        let bytes_read = reader.read(&mut buf).unwrap();
        let digests = reader.digests();

        let data_read = &data[0..bytes_read];
        assert_eq!(digest(&SHA256, data_read).as_ref(), digests.sha256.as_ref());
        assert_eq!(digest(&SHA384, data_read).as_ref(), digests.sha384.as_ref());
        assert_eq!(digest(&SHA512, data_read).as_ref(), digests.sha512.as_ref());
    }
}
