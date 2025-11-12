#![cfg(test)]

use crate::service::{StorageBackend, StorageKey};
use bytes::BytesMut;
use futures::TryStreamExt;
use rand::Rng;
use trustify_common::id::Id;

pub async fn test_store_read_and_delete<B: StorageBackend>(backend: B) {
    const DIGEST: &str = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

    let digest = backend
        .store(&b"Hello World"[..])
        .await
        .expect("store must succeed");

    assert_eq!(digest.key().to_string(), DIGEST);

    let stream = backend
        .retrieve(digest.key())
        .await
        .expect("retrieve must succeed")
        .expect("must be found");

    let content = stream.try_collect::<BytesMut>().await.unwrap();

    assert_eq!(content.as_ref(), b"Hello World");

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

/// Use random content in various sizes
pub async fn test_store_read_and_delete_rng<B: StorageBackend>(backend: B) {
    for i in 1..1024 {
        let i = i * 1024 + rand::rng().random_range(0..=100);
        let content = vec![0u8; i];

        let digest = backend
            .store(content.as_slice())
            .await
            .expect("store must succeed");

        let stream = backend
            .retrieve(digest.key())
            .await
            .expect("retrieve must succeed")
            .expect("must be found");

        let read = stream.try_collect::<BytesMut>().await.unwrap();

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
}

pub async fn test_read_not_found<B: StorageBackend>(backend: B) {
    const DIGEST: &str = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

    let stream = backend
        .retrieve(StorageKey::try_from(Id::Sha256(DIGEST.to_string())).unwrap())
        .await
        .expect("retrieve must succeed");

    assert!(stream.is_none());
}
