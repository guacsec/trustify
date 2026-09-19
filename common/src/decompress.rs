use actix_web::http::header;
use anyhow::anyhow;
use async_compression::tokio::bufread::{GzipDecoder, LzmaDecoder};
use bytes::Bytes;
use std::{io::Read, path::Path, pin::Pin};
use tokio::{
    io::{AsyncRead, BufReader},
    runtime::Handle,
    task::JoinError,
};
use tracing::instrument;
use walker_common::compression::{Compression, DecompressionOptions, Detector};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown compression type")]
    UnknownType,
    #[error(transparent)]
    Detector(anyhow::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("payload too large")]
    PayloadTooLarge,
}

/// Take some bytes, and an optional content-type header and decompress, if required.
///
/// If a content type is present, then it is expected to indicate its compression type by appending
/// it using and extension to the subtype, like `+bz2`. If that's not present, or no content-type
/// is present altogether, then it will try detecting it based on some magic bytes.
///
/// If no magic bytes could be detected, it will assume the content is not compressed.
///
/// **NOTE:** Depending on the size of the payload, this method might take some time. In an async
/// context, it might be necessary to run this as a blocking function, or use [`decompress_async`]
/// instead.
#[instrument(skip(bytes), fields(bytes_len=bytes.len()), err(level=tracing::Level::INFO))]
fn decompress(bytes: Bytes, compression: Compression, limit: usize) -> Result<Bytes, Error> {
    // decompress (or not)

    compression
        .decompress_with(bytes, &DecompressionOptions::default().limit(limit))
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::WriteZero => Error::PayloadTooLarge,
            _ => Error::from(err),
        })
}

/// An async version of [`decompress`].
#[instrument(skip(bytes), fields(bytes_len=bytes.len()), err(level=tracing::Level::INFO))]
pub async fn decompress_async(
    bytes: Bytes,
    content_type: Option<header::ContentType>,
    limit: usize,
) -> Result<Result<Bytes, Error>, JoinError> {
    let compression = match detect(content_type, &bytes) {
        Err(err) => return Ok(Err(err)),
        Ok(compression) => compression,
    };

    match compression {
        Compression::None => Ok(Ok(bytes)),
        compression => {
            // only spawn thread when necessary
            Handle::current()
                .spawn_blocking(move || decompress(bytes, compression, limit))
                .await
        }
    }
}

fn detect(content_type: Option<header::ContentType>, bytes: &[u8]) -> Result<Compression, Error> {
    let content_type = content_type.as_ref().map(|ct| ct.as_ref());

    // check what the user has declared

    let declared = content_type.map(|content_type| {
        if content_type.ends_with("+bzip2") {
            Compression::Bzip2
        } else if content_type.ends_with("+xz") {
            Compression::Xz
        } else if content_type.ends_with("+gzip") {
            Compression::Gzip
        } else {
            // The user provided a type, and it doesn't indicate a supported compression type,
            // So we just accept the payload as-is.
            Compression::None
        }
    });

    // otherwise, try to auto-detect

    Ok(match declared {
        Some(declared) => declared,
        None => {
            let detector = Detector::default();
            detector
                .detect(bytes)
                .map_err(|err| Error::Detector(anyhow!("{err}")))?
        }
    })
}

/// Take a file, return a wrapped [`AsyncRead`], and wrap that with the required compression decoder.
pub async fn decompress_async_read(
    path: impl AsRef<Path>,
) -> anyhow::Result<Pin<Box<dyn AsyncRead + Send>>> {
    let path = path.as_ref();
    let source = tokio::fs::File::open(path).await?;
    let source = BufReader::new(source);

    Ok(match path.extension().and_then(|ext| ext.to_str()) {
        Some("xz") => Box::pin(LzmaDecoder::new(source)),
        Some("gz") => Box::pin(GzipDecoder::new(source)),
        // Anything else could be .sql, .tar, or an unsupported compression format.
        // In that case, the following code would fail to understand the compressed content.
        None | Some(_) => Box::pin(source),
    })
}

/// Take a file, return a wrapped [`Read`], and wrap that with the required compression decoder.
pub fn decompress_read(path: impl AsRef<Path>) -> anyhow::Result<Box<dyn Read + Send>> {
    let path = path.as_ref();
    let source = std::fs::File::open(path)?;
    let source = std::io::BufReader::new(source);

    Ok(match path.extension().and_then(|ext| ext.to_str()) {
        Some("xz") => Box::new(lzma_rust2::XzReader::new(source, false)),
        Some("gz") => Box::new(flate2::read::GzDecoder::new(source)),
        // Anything else could be .sql, .tar, or an unsupported compression format.
        // In that case, the following code would fail to understand the compressed content.
        None | Some(_) => Box::new(source),
    })
}

#[cfg(test)]
mod test {
    use crate::decompress::decompress_async;
    use actix_web::http::header::ContentType;
    use test_log::test;
    use trustify_test_context::document_bytes_raw;

    #[test(tokio::test)]
    async fn decompress_none() -> anyhow::Result<()> {
        let bytes = decompress_async(
            document_bytes_raw("ubi9-9.2-755.1697625012.json").await?,
            None,
            0,
        )
        .await??;

        // should decode as JSON

        let _json: serde_json::Value = serde_json::from_slice(&bytes)?;

        // done

        Ok(())
    }

    #[test(tokio::test)]
    async fn decompress_xz() -> anyhow::Result<()> {
        let bytes = decompress_async(
            document_bytes_raw("openshift-container-storage-4.8.z.json.xz").await?,
            None,
            0,
        )
        .await??;

        // should decode as JSON

        let _json: serde_json::Value = serde_json::from_slice(&bytes)?;

        // done

        Ok(())
    }

    #[test(tokio::test)]
    async fn decompress_xz_with_invalid_type() -> anyhow::Result<()> {
        let bytes = decompress_async(
            document_bytes_raw("openshift-container-storage-4.8.z.json.xz").await?,
            Some(ContentType::json()),
            0,
        )
        .await??;

        // should decode as JSON

        let result = serde_json::from_slice::<serde_json::Value>(&bytes);

        // must be an error, as we try to decode a xz encoded payload as JSON.

        assert!(result.is_err());

        // done

        Ok(())
    }

    #[test(tokio::test)]
    async fn decompress_xz_with_invalid_type_2() -> anyhow::Result<()> {
        let result = decompress_async(
            document_bytes_raw("openshift-container-storage-4.8.z.json.xz").await?,
            Some(ContentType("application/json+bzip2".parse().unwrap())),
            0,
        )
        .await?;

        // must be an error, as we indicated bzip2, but provided xz

        assert!(result.is_err());

        // done

        Ok(())
    }

    #[test(tokio::test)]
    async fn decompress_xz_with_correct_type() -> anyhow::Result<()> {
        let bytes = decompress_async(
            document_bytes_raw("openshift-container-storage-4.8.z.json.xz").await?,
            Some(ContentType("application/json+xz".parse().unwrap())),
            0,
        )
        .await??;

        // should decode as JSON

        let _json: serde_json::Value = serde_json::from_slice(&bytes)?;

        // done

        Ok(())
    }
}
