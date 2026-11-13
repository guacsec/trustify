#![cfg(test)]

use crate::service::{Compression, StorageBackend, StorageKey};
use bytes::BytesMut;
use futures::TryStreamExt;
use rand::RngExt;
use std::time::Duration;
use tokio::{io::AsyncReadExt, time::timeout};
use trustify_common::id::Id;

pub async fn test_store_read_and_delete<B: StorageBackend>(backend: B) {
    test_store_read_and_delete_with_data(&backend, &b"Hello World"[..]).await
}

/// Use random content in various sizes
pub async fn test_store_read_and_delete_rng<B: StorageBackend>(backend: B) {
    for i in 1..1024 {
        let i = i * 1024 + rand::rng().random_range(0..=100);
        test_store_read_and_delete_with_zeroes(&backend, i).await;
    }
}

/// Test with the number of bytes, all zeroes
pub async fn test_store_read_and_delete_with_zeroes<B: StorageBackend>(
    backend: &B,
    number_of_bytes: usize,
) {
    test_store_read_and_delete_with_data(backend, &vec![0u8; number_of_bytes]).await
}

/// Test with the provided data
async fn test_store_read_and_delete_with_data<B: StorageBackend>(backend: &B, content: &[u8]) {
    tracing::info!(size = content.len(), "testing");

    let digest = timeout(Duration::from_mins(1), backend.store(content))
        .await
        .unwrap_or_else(|_| panic!("store timed out - size: {}", content.len()))
        .expect("store must succeed");

    tracing::info!(size = content.len(), "stored");

    let read = timeout(Duration::from_mins(1), async {
        let stream = backend
            .retrieve(digest.key())
            .await
            .expect("retrieve must succeed")
            .expect("must be found");

        tracing::info!(size = content.len(), "opened");

        stream.try_collect::<BytesMut>().await.unwrap()
    })
    .await
    .unwrap_or_else(|_| panic!("read timed out - size: {}", content.len()));

    tracing::info!(size = content.len(), "read");

    assert_eq!(read.as_ref(), content);

    backend
        .delete(digest.key())
        .await
        .expect("delete must succeed");
    assert!(backend.retrieve(digest.key()).await.unwrap().is_none());
    backend
        .delete(digest.key())
        .await
        .expect("delete should be idempotent");
}

pub async fn test_read_not_found<B: StorageBackend>(backend: B) {
    const DIGEST: &str = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

    let stream = backend
        .retrieve(StorageKey::try_from(Id::Sha256(DIGEST.to_string())).unwrap())
        .await
        .expect("retrieve must succeed");

    assert!(stream.is_none());
}

pub async fn test_retrieve_encoded<B: StorageBackend>(backend: B, stored: Compression) {
    let content = b"Hello World";
    let result = backend.store(&content[..]).await.unwrap();

    for accepted in [&[][..], &[Compression::Zstd][..], &[Compression::None][..]] {
        let retrieved = backend
            .retrieve_encoded(result.key(), accepted)
            .await
            .unwrap()
            .unwrap();
        let expected = if accepted.contains(&stored) {
            stored
        } else {
            Compression::None
        };
        assert_eq!(retrieved.compression, expected);

        let bytes = retrieved.stream.try_collect::<BytesMut>().await.unwrap();
        let mut decoded = Vec::new();
        retrieved
            .compression
            .reader(bytes.as_ref())
            .read_to_end(&mut decoded)
            .await
            .unwrap();
        assert_eq!(decoded, content);
    }

    backend.delete(result.key()).await.unwrap();
    assert!(
        backend
            .retrieve_encoded(result.key(), &[Compression::Zstd])
            .await
            .unwrap()
            .is_none()
    );
}

mod default_retrieve_encoded {
    use super::*;
    use crate::service::{StorageResult, StoreError};
    use bytes::Bytes;
    use futures::{Stream, future, stream};
    use rstest::rstest;
    use std::{cell::Cell, future::Future, io};
    use tokio::io::AsyncRead;

    #[derive(Clone, Copy)]
    enum Source {
        Content,
        Missing,
        BackendError,
        StreamError,
    }

    // Implements only the original methods. Cell also ensures the default does
    // not impose a new Sync bound on existing backends.
    struct LegacyBackend {
        source: Source,
        retrieves: Cell<usize>,
    }

    impl StorageBackend for LegacyBackend {
        type Error = io::Error;

        fn store<S>(
            &self,
            _stream: S,
        ) -> impl Future<Output = Result<StorageResult, StoreError<Self::Error>>> + Send
        where
            S: AsyncRead + Unpin + Send,
        {
            future::ready(Err(StoreError::Backend(io::Error::other(
                "read-only legacy backend",
            ))))
        }

        fn retrieve(
            &self,
            _key: StorageKey,
        ) -> impl Future<
            Output = Result<
                Option<impl Stream<Item = Result<Bytes, Self::Error>> + use<>>,
                Self::Error,
            >,
        > + Send {
            self.retrieves.set(self.retrieves.get() + 1);
            let result = match self.source {
                Source::Content => Ok(Some(vec![Ok(Bytes::from_static(b"legacy content"))])),
                Source::Missing => Ok(None),
                Source::BackendError => Err(io::Error::other("backend error")),
                Source::StreamError => Ok(Some(vec![Err(io::Error::other("stream error"))])),
            };
            future::ready(result.map(|chunks| chunks.map(stream::iter)))
        }

        async fn delete(&self, _key: StorageKey) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[rstest]
    #[case::content(Source::Content)]
    #[case::missing(Source::Missing)]
    #[case::backend_error(Source::BackendError)]
    #[case::stream_error(Source::StreamError)]
    #[test_log::test(tokio::test)]
    async fn legacy_backend(
        #[case] source: Source,
        #[values(&[][..], &[Compression::Zstd][..], &[Compression::None][..])]
        accepted: &[Compression],
    ) -> anyhow::Result<()> {
        let backend = LegacyBackend {
            source,
            retrieves: Cell::new(0),
        };
        let retrieved = backend
            .retrieve_encoded(StorageKey::from_sha256(&"0".repeat(64)), accepted)
            .await;
        assert_eq!(backend.retrieves.get(), 1);

        match source {
            Source::Missing => assert!(retrieved?.is_none()),
            Source::BackendError => {
                assert!(matches!(retrieved, Err(error) if error.to_string() == "backend error"))
            }
            Source::Content | Source::StreamError => {
                let content = retrieved?.unwrap();
                assert_eq!(content.compression, Compression::None);
                let bytes = content.stream.try_collect::<BytesMut>().await;
                match source {
                    Source::Content => assert_eq!(bytes?.as_ref(), b"legacy content"),
                    _ => {
                        assert!(matches!(bytes, Err(error) if error.to_string() == "stream error"))
                    }
                }
            }
        }
        Ok(())
    }
}
