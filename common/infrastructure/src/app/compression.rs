//! Prefer zstd for dynamic API responses without changing static-asset negotiation.

use actix_http::encoding::Encoder;
use actix_web::{
    Error, HttpMessage,
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::header::{self, AcceptEncoding, ContentEncoding, Encoding, Preference, Quality},
    middleware::Next,
    mime,
};

/// Runs inside Actix's `Compress` middleware, which retains responsibility for
/// fallback encodings, unacceptable requests, and static assets. A response
/// encoded here has `Content-Encoding` set, so `Compress` passes it through.
pub(super) async fn prefer_zstd<B: MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<Encoder<B>, B>>, Error> {
    let prefer_zstd = (req.path() == "/api" || req.path().starts_with("/api/"))
        && req
            .get_header::<AcceptEncoding>()
            .is_some_and(|accept| prefers_zstd(&accept));

    let response = next.call(req).await?;
    Ok(response.map_body(|head, body| {
        if prefer_zstd
            && !head.headers.contains_key(header::CONTENT_ENCODING)
            && compressible(head.headers.get(header::CONTENT_TYPE))
        {
            EitherBody::left(Encoder::response(ContentEncoding::Zstd, head, body))
        } else {
            EitherBody::right(body)
        }
    }))
}

fn prefers_zstd(accept: &AcceptEncoding) -> bool {
    let wildcard_quality = accept
        .0
        .iter()
        .filter(|item| matches!(item.item, Preference::Any))
        .map(|item| item.quality)
        .max();
    // Explicit entries override the wildcard, including an explicit q=0.
    let quality = |encoding| {
        accept
            .0
            .iter()
            .filter(|item| matches!(&item.item, Preference::Specific(value) if value == &encoding))
            .map(|item| item.quality)
            .max()
            .or(wildcard_quality)
    };
    let Some(zstd_quality) = quality(Encoding::zstd()) else {
        return false;
    };

    // Prefer zstd only at the highest acceptable quality. Like Actix, treat
    // implicit identity as a fallback, not an explicit client preference.
    zstd_quality > Quality::ZERO
        && [
            Encoding::identity(),
            Encoding::brotli(),
            Encoding::gzip(),
            Encoding::deflate(),
        ]
        .into_iter()
        .filter_map(quality)
        .all(|other_quality| zstd_quality >= other_quality)
}

/// Match Actix's default content-type exclusions before encoding a response.
fn compressible(content_type: Option<&header::HeaderValue>) -> bool {
    match content_type
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok())
    {
        Some(mime) if mime.type_() == mime::IMAGE => mime.subtype() == mime::SVG,
        Some(mime) if mime.type_() == mime::VIDEO => false,
        _ => true,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::app::{AppOptions, new_app};
    use actix_http::{ResponseHead, encoding::Decoder, error::PayloadError};
    use actix_web::{
        HttpRequest, HttpResponse,
        body::to_bytes,
        http::StatusCode,
        test,
        web::{self, Bytes},
    };
    use futures::{TryStreamExt, stream};

    const PAYLOAD: &str = r#"{"items":[{"name":"openssl","version":"3.2.2"}],"total":1}"#;

    #[actix_web::test]
    async fn dynamic_encoding_negotiation() -> anyhow::Result<()> {
        let app = test::init_service(new_app(AppOptions::default()).route(
            "/api/test",
            web::get().to(|| async {
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(PAYLOAD)
            }),
        ))
        .await;

        for (accept, expected) in [
            (Some("gzip, deflate, br, zstd"), Some(ContentEncoding::Zstd)),
            (Some("br, zstd"), Some(ContentEncoding::Zstd)),
            (Some("br;q=0.5, zstd;q=0.5"), Some(ContentEncoding::Zstd)),
            (Some("*"), Some(ContentEncoding::Zstd)),
            (Some("*;q=0.5"), Some(ContentEncoding::Zstd)),
            (Some("br, *"), Some(ContentEncoding::Zstd)),
            (Some("br;q=0.5, *;q=0.5"), Some(ContentEncoding::Zstd)),
            (Some("br;q=0.5, *;q=0.8"), Some(ContentEncoding::Zstd)),
            (Some("zstd, *;q=0"), Some(ContentEncoding::Zstd)),
            (Some("zstd;q=0, *"), None),
            (Some("br, zstd;q=0, *"), Some(ContentEncoding::Brotli)),
            (Some("br;q=1, *;q=0.5"), Some(ContentEncoding::Brotli)),
            (Some("gzip;q=1, *;q=0.5"), Some(ContentEncoding::Gzip)),
            (Some("identity;q=1, *;q=0.5"), None),
            (Some("zstd"), Some(ContentEncoding::Zstd)),
            (Some("gzip"), Some(ContentEncoding::Gzip)),
            (Some("br"), Some(ContentEncoding::Brotli)),
            (Some("deflate"), Some(ContentEncoding::Deflate)),
            (Some("gzip;q=1, zstd;q=0.5"), Some(ContentEncoding::Gzip)),
            (Some("br;q=1, zstd;q=0.5"), Some(ContentEncoding::Brotli)),
            (Some("br, zstd;q=0"), Some(ContentEncoding::Brotli)),
            (Some("gzip, zstd;q=0"), Some(ContentEncoding::Gzip)),
            (Some("identity;q=1, zstd;q=0.5"), None),
            (Some("identity"), None),
            (Some(""), None),
            (None, None),
        ] {
            let mut request = test::TestRequest::get().uri("/api/test");
            if let Some(accept) = accept {
                request = request.insert_header((header::ACCEPT_ENCODING, accept));
            }
            let response = test::call_service(&app, request.to_request()).await;
            assert_eq!(response.status(), StatusCode::OK, "{accept:?}");
            assert_eq!(
                response.headers().get(header::CONTENT_ENCODING),
                expected.map(ContentEncoding::to_header_value).as_ref(),
                "{accept:?}"
            );
            if expected.is_some() {
                assert!(response.headers().get_all(header::VARY).any(|value| {
                    value
                        .to_str()
                        .is_ok_and(|value| value.eq_ignore_ascii_case("accept-encoding"))
                }));
            }
            let bytes = test::read_body(response).await;
            let chunks = Decoder::new(
                stream::iter([Ok::<_, PayloadError>(bytes)]),
                expected.unwrap_or(ContentEncoding::Identity),
            )
            .try_collect::<Vec<_>>()
            .await?;
            assert_eq!(chunks.concat(), PAYLOAD.as_bytes(), "{accept:?}");
        }

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/test")
                .insert_header((header::ACCEPT_ENCODING, "identity;q=0, *;q=0"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        Ok(())
    }

    #[actix_web::test]
    async fn static_assets_keep_default_negotiation() {
        let app = test::init_service(new_app(AppOptions::default()).default_service(
            web::get().to(|| async {
                HttpResponse::Ok()
                    .content_type("text/javascript")
                    .body(PAYLOAD)
            }),
        ))
        .await;
        for path in ["/assets/test.js", "/console/test.js", "/api-assets.js"] {
            for (accept, expected) in [
                ("gzip, br, zstd", Some(ContentEncoding::Brotli)),
                ("zstd", Some(ContentEncoding::Zstd)),
                ("*", None),
                ("br, *", Some(ContentEncoding::Brotli)),
            ] {
                let response = test::call_service(
                    &app,
                    test::TestRequest::get()
                        .uri(path)
                        .insert_header((header::ACCEPT_ENCODING, accept))
                        .to_request(),
                )
                .await;
                assert_eq!(
                    response.headers().get(header::CONTENT_ENCODING),
                    expected.map(ContentEncoding::to_header_value).as_ref(),
                    "{path}: {accept}"
                );
            }
        }
    }

    #[actix_web::test]
    async fn precompressed_zstd_is_passed_through_when_acceptable() -> anyhow::Result<()> {
        let encoded = to_bytes(Encoder::response(
            ContentEncoding::Zstd,
            &mut ResponseHead::new(StatusCode::OK),
            Bytes::from_static(PAYLOAD.as_bytes()),
        ))
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let asset = encoded.clone();
        let app = test::init_service(new_app(AppOptions::default()).default_service(
            web::get().to(move |req: HttpRequest| {
                let asset = asset.clone();
                async move {
                    let supported = [Encoding::zstd(), Encoding::identity()];
                    let encoding = req
                        .get_header::<AcceptEncoding>()
                        .and_then(|accept| accept.negotiate(supported.iter()));
                    let mut response = HttpResponse::Ok();
                    response
                        .content_type("text/javascript")
                        .insert_header((header::VARY, "Accept-Encoding"));
                    if encoding == Some(Encoding::zstd()) {
                        response
                            .insert_header((header::CONTENT_ENCODING, "zstd"))
                            .body(asset)
                    } else {
                        response.body(PAYLOAD)
                    }
                }
            }),
        ))
        .await;
        for path in ["/assets/test.js", "/api/precompressed"] {
            for accept in ["zstd", "br, gzip, zstd", "br;q=1, zstd;q=0.1"] {
                let response = test::call_service(
                    &app,
                    test::TestRequest::get()
                        .uri(path)
                        .insert_header((header::ACCEPT_ENCODING, accept))
                        .to_request(),
                )
                .await;
                assert_eq!(
                    response.headers().get(header::CONTENT_ENCODING),
                    Some(&header::HeaderValue::from_static("zstd"))
                );
                assert_eq!(
                    response.headers().get_all(header::VARY).collect::<Vec<_>>(),
                    vec![&header::HeaderValue::from_static("Accept-Encoding")]
                );
                assert_eq!(test::read_body(response).await, encoded);
            }
            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(path)
                    .insert_header((header::ACCEPT_ENCODING, "identity, zstd;q=0"))
                    .to_request(),
            )
            .await;
            assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
            assert_eq!(test::read_body(response).await, PAYLOAD);
        }
        Ok(())
    }

    #[actix_web::test]
    async fn streamed_downloads_prefer_zstd() -> anyhow::Result<()> {
        let app = test::init_service(new_app(AppOptions::default()).route(
            "/api/v3/sbom/test/download",
            web::get().to(|| async {
                HttpResponse::Ok().streaming(stream::iter([
                    Ok::<_, Error>(Bytes::from_static(b"hello ")),
                    Ok(Bytes::from_static(b"world")),
                ]))
            }),
        ))
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/v3/sbom/test/download")
                .insert_header((header::ACCEPT_ENCODING, "gzip, br, zstd"))
                .to_request(),
        )
        .await;
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING),
            Some(&header::HeaderValue::from_static("zstd"))
        );
        let chunks = Decoder::new(
            stream::iter([Ok::<_, PayloadError>(test::read_body(response).await)]),
            ContentEncoding::Zstd,
        )
        .try_collect::<Vec<_>>()
        .await?;
        assert_eq!(chunks.concat(), b"hello world");
        Ok(())
    }

    #[actix_web::test]
    async fn compression_exclusions_are_preserved() {
        for (status, content_type, payload) in [
            (StatusCode::OK, "image/png", PAYLOAD),
            (StatusCode::OK, "video/mp4", PAYLOAD),
            (StatusCode::OK, "application/json", ""),
            (StatusCode::NO_CONTENT, "application/json", ""),
            (StatusCode::PARTIAL_CONTENT, "application/json", PAYLOAD),
        ] {
            let app = test::init_service(new_app(AppOptions::default()).route(
                "/api/test",
                web::get().to(move || async move {
                    HttpResponse::build(status)
                        .content_type(content_type)
                        .body(payload)
                }),
            ))
            .await;
            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/api/test")
                    .insert_header((header::ACCEPT_ENCODING, "br, zstd"))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), status);
            assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
            assert_eq!(test::read_body(response).await, payload);
        }
    }
}
