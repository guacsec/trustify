use async_compression::tokio::bufread;
use async_compression::tokio::write::ZstdEncoder;
use std::fmt::{Display, Formatter};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};

#[derive(
    Copy, Clone, Eq, PartialEq, Default, Debug, strum::EnumIter, strum::EnumString, clap::ValueEnum,
)]
pub enum Compression {
    #[default]
    #[strum(ascii_case_insensitive)]
    None,
    #[strum(ascii_case_insensitive)]
    Zstd,
}

impl Display for Compression {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Compression::None => f.write_str("none"),
            Compression::Zstd => f.write_str("zstd"),
        }
    }
}

impl From<Compression> for String {
    fn from(value: Compression) -> Self {
        value.to_string()
    }
}

impl Compression {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Zstd => "zstd",
        }
    }

    pub fn content_encoding(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
        }
    }

    pub async fn compress<R>(&self, r: R) -> Box<dyn AsyncRead + Unpin>
    where
        R: AsyncBufRead + Unpin + 'static,
    {
        match self {
            Self::None => Box::new(r),
            Self::Zstd => Box::new(bufread::ZstdEncoder::new(r)),
        }
    }

    /// Write content, compressed.
    pub async fn write<R, W>(&self, r: &mut R, mut w: &mut W) -> io::Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        /// [io::copy] and [`AsyncWriteExt::shutdown`]
        ///
        /// As we take ownership of the output stream, ensure that we shut down it, writing
        /// remaining content.
        async fn copy_shutdown(
            r: &mut (impl AsyncRead + Unpin),
            mut w: &mut (impl AsyncWrite + Unpin),
        ) -> io::Result<u64> {
            let result = io::copy(r, &mut w).await?;
            w.shutdown().await?;
            Ok(result)
        }

        match self {
            Self::None => copy_shutdown(r, &mut w).await,
            Self::Zstd => copy_shutdown(r, &mut ZstdEncoder::new(&mut w)).await,
        }
    }

    /// Create a reader, decompressing on the fly
    pub fn reader<R>(&self, r: R) -> DecompressionReader<R>
    where
        R: AsyncRead,
    {
        let r = BufReader::new(r);
        match self {
            Self::None => DecompressionReader {
                inner: InnerDecompression::None(r),
            },
            Self::Zstd => DecompressionReader {
                inner: InnerDecompression::Zstd(bufread::ZstdDecoder::new(r)),
            },
        }
    }
}

enum InnerDecompression<R>
where
    R: AsyncRead,
{
    None(BufReader<R>),
    Zstd(bufread::ZstdDecoder<BufReader<R>>),
}

pub struct DecompressionReader<R>
where
    R: AsyncRead,
{
    inner: InnerDecompression<R>,
}

impl<R> AsyncRead for DecompressionReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            InnerDecompression::None(r) => Pin::new(r).poll_read(cx, buf),
            InnerDecompression::Zstd(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn compression_from_str() {
        assert_eq!(Ok(Compression::None), Compression::from_str("none"));
        assert_eq!(Ok(Compression::None), Compression::from_str("None"));
        assert_eq!(Ok(Compression::None), Compression::from_str("NONE"));
        assert_eq!(Ok(Compression::Zstd), Compression::from_str("zstd"));
        assert_eq!(Ok(Compression::Zstd), Compression::from_str("Zstd"));
        assert_eq!(Ok(Compression::Zstd), Compression::from_str("ZSTD"));
    }
}
