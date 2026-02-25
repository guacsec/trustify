#![cfg(test)]

use crate::service::{StorageBackend, StorageKey};
use bytes::BytesMut;
use futures::TryStreamExt;
use rand::RngExt;
use std::time::Duration;
use tokio::time::timeout;
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
        .expect(&format!("store timed out - size: {}", content.len()))
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
    .expect(&format!("read timed out - size: {}", content.len()));

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
