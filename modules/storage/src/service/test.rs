#![cfg(test)]

use crate::service::{StorageBackend, StorageKey};
use bytes::BytesMut;
use futures::TryStreamExt;
use trustify_common::id::Id;

pub async fn test_store_and_read<B: StorageBackend>(backend: B) {
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
}

pub async fn test_read_not_found<B: StorageBackend>(backend: B) {
    const DIGEST: &str = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

    let stream = backend
        .retrieve(StorageKey::try_from(Id::Sha256(DIGEST.to_string())).unwrap())
        .await
        .expect("retrieve must succeed");

    assert!(stream.is_none());
}
