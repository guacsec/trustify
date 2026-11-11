use super::{accepts_stored_zstd, download};
use crate::sbom::service::SbomService;
use actix_http::{encoding::Decoder, error::PayloadError};
use actix_web::{
    HttpMessage,
    http::{
        StatusCode,
        header::{self, AcceptEncoding, ContentEncoding},
    },
    test::{self, TestRequest},
    web,
};
use futures::{TryStreamExt, stream};
use rstest::rstest;
use sha2::{Digest, Sha256};
use test_context::test_context;
use tokio::{fs, io::AsyncReadExt};
use trustify_common::db::{ReadOnly, pagination_cache::PaginationCache};
use trustify_infrastructure::app::{AppOptions, new_app};
use trustify_module_ingestor::service::IngestorService;
use trustify_module_storage::service::{
    Compression, StorageBackend, StorageKey, fs::FileSystemBackend,
};
use trustify_test_context::{TrustifyContext, document_bytes};

fn mark_stored_zstd(stored: &mut Vec<u8>) {
    // Keep the document first: the storage decoder reads a single zstd frame.
    stored.extend_from_slice(b"\x50\x2a\x4d\x18\x08\x00\x00\x00raw-byte");
}

#[test_log::test(tokio::test)]
async fn stored_zstd_marker_round_trip() -> anyhow::Result<()> {
    let bytes = b"stored SBOM document";
    let mut stored = Vec::new();
    Compression::Zstd
        .write(&mut bytes.as_slice(), &mut stored)
        .await?;
    mark_stored_zstd(&mut stored);

    let mut decoded = Vec::new();
    Compression::Zstd
        .reader(stored.as_slice())
        .read_to_end(&mut decoded)
        .await?;
    assert_eq!(decoded, bytes);

    let decoded = Decoder::new(
        stream::iter([Ok::<_, PayloadError>(web::Bytes::from(stored))]),
        ContentEncoding::Zstd,
    )
    .try_collect::<Vec<_>>()
    .await?;
    assert_eq!(decoded.concat(), bytes);
    Ok(())
}

#[test_log::test]
fn stored_zstd_negotiation() {
    for (accept, expected) in [
        ("zstd", true),
        ("br, gzip, zstd", true),
        ("br;q=1, zstd;q=0.1", true),
        ("*", true),
        ("*;q=0.5", true),
        ("identity;q=0, *", true),
        ("zstd, *;q=0", true),
        ("identity;q=1, zstd;q=1", true),
        ("identity;q=1, zstd;q=0.5", false),
        ("identity;q=1, *;q=0.5", false),
        ("zstd;q=0, *", false),
        ("*;q=0", false),
        ("gzip", false),
        ("identity", false),
        ("", false),
    ] {
        let request = TestRequest::get()
            .insert_header((header::ACCEPT_ENCODING, accept))
            .to_http_request();
        let accept = request.get_header::<AcceptEncoding>().unwrap();
        assert_eq!(accepts_stored_zstd(&accept), expected, "{accept:?}");
    }
}

#[test_context(TrustifyContext)]
#[rstest]
#[case::uncompressed(Compression::None)]
#[case::zstd(Compression::Zstd)]
#[test_log::test(actix_web::test)]
async fn download_stored_sbom(
    ctx: &mut TrustifyContext,
    #[case] compression: Compression,
) -> anyhow::Result<()> {
    const FILE: &str = "cyclonedx/application.cdx.json";
    let (storage, directory) = FileSystemBackend::for_test_with(compression).await?;
    ctx.0.storage = storage;
    // Share this backend with ingestion and the HTTP handler so the test uses
    // the real stored document rather than a pre-encoded mock response.
    ctx.0.ingestor = IngestorService::new(ctx.graph.clone(), ctx.storage.clone(), None);
    let bytes = document_bytes(FILE).await?;
    let result = ctx.ingest_document(FILE).await?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let mut path = directory
        .path()
        .join("content")
        .join(&digest[..2])
        .join(&digest[2..4])
        .join(&digest);
    path.set_extension(compression.extension());
    let mut stored = fs::read(&path).await?;
    if compression == Compression::Zstd {
        // A valid zstd skippable frame survives only byte-for-byte pass-through.
        // Decompression/recompression would discard this marker even if both
        // encoders happened to produce identical compressed payloads.
        mark_stored_zstd(&mut stored);
        fs::write(&path, &stored).await?;
    }

    let app = test::init_service(
        new_app(AppOptions::default())
            .app_data(web::Data::new(ReadOnly::new(ctx.db.clone())))
            .app_data(web::Data::new(
                SbomService::new(PaginationCache::for_test()),
            ))
            .app_data(web::Data::new(ctx.ingestor.clone()))
            .service(web::scope("/api").service(download)),
    )
    .await;

    for key in [
        format!("urn:uuid:{}", result.id),
        format!("sha256:{digest}"),
    ] {
        for (accept, fallback, passthrough) in [
            (None, None, false),
            (Some(""), None, false),
            (Some("identity"), None, false),
            (Some("gzip"), Some(ContentEncoding::Gzip), false),
            (Some("br"), Some(ContentEncoding::Brotli), false),
            (Some("deflate"), Some(ContentEncoding::Deflate), false),
            (Some("zstd"), Some(ContentEncoding::Zstd), true),
            (Some("gzip, br, zstd"), Some(ContentEncoding::Zstd), true),
            (
                Some("br;q=1, zstd;q=0.1"),
                Some(ContentEncoding::Brotli),
                true,
            ),
            (Some("*"), Some(ContentEncoding::Zstd), true),
            (Some("zstd, *;q=0"), Some(ContentEncoding::Zstd), true),
            (
                Some("br, zstd;q=0, *"),
                Some(ContentEncoding::Brotli),
                false,
            ),
            (Some("identity;q=1, zstd;q=0.5"), None, false),
        ] {
            let passthrough = passthrough && compression == Compression::Zstd;
            let encoding = if passthrough {
                Some(ContentEncoding::Zstd)
            } else {
                fallback
            };
            let mut request = TestRequest::get().uri(&format!("/api/v3/sbom/{key}/download"));
            if let Some(accept) = accept {
                request = request.insert_header((header::ACCEPT_ENCODING, accept));
            }
            let response = test::call_service(&app, request.to_request()).await;
            assert_eq!(response.status(), StatusCode::OK, "{key}: {accept:?}");
            assert_eq!(
                response.headers().get(header::CONTENT_ENCODING),
                encoding.map(ContentEncoding::to_header_value).as_ref(),
                "{key}: {accept:?}"
            );
            assert!(response.headers().get_all(header::VARY).any(|value| {
                value
                    .to_str()
                    .is_ok_and(|value| value.eq_ignore_ascii_case("accept-encoding"))
            }));
            let body = test::read_body(response).await;
            if passthrough {
                assert_eq!(body.as_ref(), stored, "{key}: {accept:?}");
            }
            let decoded = Decoder::new(
                stream::iter([Ok::<_, PayloadError>(body)]),
                encoding.unwrap_or(ContentEncoding::Identity),
            )
            .try_collect::<Vec<_>>()
            .await?;
            assert_eq!(decoded.concat(), bytes.as_ref(), "{key}: {accept:?}");
        }
    }

    let response = test::call_service(
        &app,
        TestRequest::get()
            .uri(&format!("/api/v3/sbom/sha256:{digest}/download"))
            .insert_header((header::ACCEPT_ENCODING, "identity;q=0, *;q=0"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);

    ctx.storage.delete(StorageKey::from_sha256(&digest)).await?;
    let response = test::call_service(
        &app,
        TestRequest::get()
            .uri(&format!("/api/v3/sbom/sha256:{digest}/download"))
            .insert_header((header::ACCEPT_ENCODING, "zstd"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
    Ok(())
}
