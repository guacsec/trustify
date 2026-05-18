pub mod dispatch;
pub mod fs;
pub mod s3;

mod test;

mod compression;
mod temp;

pub use compression::Compression;

use crate::service::fs::FileSystemBackend;
use bytes::Bytes;
use futures::Stream;
use hex::ToHex;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use tokio::io::AsyncRead;
use trustify_common::hashing::Digests;
use trustify_common::id::Id;

#[derive(Debug, thiserror::Error)]
pub enum StoreError<B: Debug> {
    #[error("stream error: {0}")]
    Stream(#[from] std::io::Error),
    #[error("backend error: {0}")]
    Backend(#[source] B),
}

#[derive(Debug, thiserror::Error)]
pub enum DeleteManyError<E> {
    /// The whole operation failed
    #[error("{0}")]
    Generic(E),
    /// Individual delete errors
    #[error("individual delete errors: {0}")]
    Individual(HashMap<StorageKey, E>),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorageKey(String);

impl StorageKey {
    /// Create a storage key from the digest.
    ///
    /// The digest must be SHA256 (without "sha256:" prefix) and user must
    /// ensure this (for simplicity we omitted checks here).
    pub fn from_sha256(digest: &str) -> Self {
        Self(digest.into())
    }
}

impl Display for StorageKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<StorageKey> for String {
    fn from(value: StorageKey) -> Self {
        value.0
    }
}

#[derive(Copy, Clone, Debug, thiserror::Error)]
pub enum StorageKeyError {
    #[error("Storage key must be of type SHA256")]
    WrongType,
}

impl TryFrom<Id> for StorageKey {
    type Error = StorageKeyError;

    fn try_from(value: Id) -> Result<Self, Self::Error> {
        match value {
            Id::Sha256(digest) => Ok(StorageKey(digest)),
            _ => Err(StorageKeyError::WrongType),
        }
    }
}

impl TryFrom<Vec<Id>> for StorageKey {
    type Error = StorageKeyError;

    fn try_from(value: Vec<Id>) -> Result<Self, Self::Error> {
        for id in value {
            if let Ok(id) = id.try_into() {
                return Ok(id);
            }
        }

        Err(StorageKeyError::WrongType)
    }
}

#[derive(Clone, Debug)]
pub struct StorageResult {
    pub digests: Digests,
}

impl StorageResult {
    pub fn key(&self) -> StorageKey {
        StorageKey(self.digests.sha256.encode_hex())
    }
}

pub trait StorageBackend {
    type Error: Debug + Display;

    /// Store the content from a stream
    fn store<S>(
        &self,
        stream: S,
    ) -> impl Future<Output = Result<StorageResult, StoreError<Self::Error>>> + Send
    where
        S: AsyncRead + Unpin + Send;

    /// Retrieve the content as an async reader
    fn retrieve(
        &self,
        key: StorageKey,
    ) -> impl Future<
        Output = Result<
            Option<impl Stream<Item = Result<Bytes, Self::Error>> + Send + use<Self>>,
            Self::Error,
        >,
    > + Send;

    /// Delete the stored content.
    ///
    /// This operation MUST be idempotent: deleting a non-existent key should succeed
    /// (i.e., return `Ok(())`) and not result in an error. This ensures consistent
    /// behavior across all backends.
    fn delete(&self, key: StorageKey) -> impl Future<Output = Result<(), Self::Error>>;

    /// Batch variant of `delete`, with the same requirements.
    fn delete_many(
        &self,
        keys: &[StorageKey],
    ) -> impl Future<Output = Result<(), DeleteManyError<Self::Error>>> {
        async move {
            // Default implementation: delete blobs one by one (can be overridden in
            // implementations for particular backends).
            let mut whats_wrong = HashMap::new();

            for key in keys {
                // Do not stop on the first error---instead, accumulate all errors
                // into one and return it when we are done (we do not want one faulty
                // request to stop the entire deletion process)
                if let Err(e) = self.delete(key.clone()).await {
                    whats_wrong.insert(key.clone(), e);
                }
            }
            match whats_wrong.is_empty() {
                true => Ok(()),
                false => Err(DeleteManyError::Individual(whats_wrong)),
            }
        }
    }
}
