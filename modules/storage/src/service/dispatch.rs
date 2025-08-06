use self::s3::S3Backend;

use super::*;
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};

/// A common backend, dispatching to the ones we support.
///
/// This is required due to the "can't turn into object" problem, which we encounter for this trait
/// (due to using async traits and function level type arguments). The only alternative would be
/// to propagate the specific type up to the root level. However, that would also mean that actix
/// handlers would be required to know about that full type to extract it as application
/// data.
#[derive(Clone, Debug)]
pub enum DispatchBackend {
    Filesystem(FileSystemBackend),
    S3(S3Backend),
}

impl StorageBackend for DispatchBackend {
    type Error = anyhow::Error;

    async fn store<S>(&self, stream: S) -> Result<StorageResult, StoreError<Self::Error>>
    where
        S: AsyncRead + Unpin + Send,
    {
        match self {
            Self::Filesystem(backend) => backend.store(stream).await.map_err(Self::map_err),
            Self::S3(backend) => backend.store(stream).await.map_err(Self::map_err),
        }
    }

    async fn retrieve(
        &self,
        key: StorageKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>> + use<>>, Self::Error>
    where
        Self: Sized,
    {
        match self {
            Self::Filesystem(backend) => backend
                .retrieve(key)
                .await
                .map(|stream| stream.map(|stream| stream.map_err(anyhow::Error::from).boxed()))
                .map_err(anyhow::Error::from),
            Self::S3(backend) => backend
                .retrieve(key)
                .await
                .map(|stream| stream.map(|stream| stream.map_err(anyhow::Error::from).boxed()))
                .map_err(anyhow::Error::from),
        }
    }

    async fn delete(&self, key: StorageKey) -> Result<(), Self::Error> {
        match self {
            Self::Filesystem(backend) => backend.delete(key).await.map_err(anyhow::Error::from),
            Self::S3(backend) => backend.delete(key).await.map_err(anyhow::Error::from),
        }
    }
}

impl DispatchBackend {
    /// convert any backend error to [`anyhow::Error`].
    fn map_err<B>(error: StoreError<B>) -> StoreError<anyhow::Error>
    where
        B: std::error::Error + Send + Sync + 'static,
    {
        match error {
            StoreError::Stream(err) => StoreError::Stream(err),
            StoreError::Backend(err) => StoreError::Backend(anyhow::Error::from(err)),
        }
    }
}

impl From<FileSystemBackend> for DispatchBackend {
    fn from(value: FileSystemBackend) -> Self {
        Self::Filesystem(value)
    }
}

impl From<S3Backend> for DispatchBackend {
    fn from(value: S3Backend) -> Self {
        Self::S3(value)
    }
}
