#[path = "common.rs"]
mod common;

use actix_http::StatusCode;
use actix_web::test::TestRequest;
use common::caller_with;
use std::io::{Cursor, Write};
use test_context::test_context;
use test_log::test;
use trustify_module_ingestor::endpoints::Config;
use trustify_test_context::{TrustifyContext, call::CallService, document_bytes_raw};
use zip::write::FileOptions;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_bomb_dataset(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller_with(
        ctx,
        Config {
            dataset_entry_limit: 1024 * 1024,
        },
    )
    .await?;

    let mut data = vec![];
    let mut dataset = zip::write::ZipWriter::new(Cursor::new(&mut data));
    dataset.add_directory("spdx", FileOptions::<()>::default())?;
    dataset.start_file("spdx/bomb.bz2", FileOptions::<()>::default())?;
    dataset.write_all(&document_bytes_raw("bomb.bz2").await?)?;
    dataset.finish()?;

    let request = TestRequest::post()
        .uri("/api/v3/dataset")
        .set_payload(data)
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    Ok(())
}
