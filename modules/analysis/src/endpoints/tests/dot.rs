use crate::test::caller;
use actix_http::Request;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn render_dot(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let sbom = sbom.id;

    // Ensure child has an ancestor that includes it
    let uri = format!("/api/v2/analysis/sbom/{sbom}/render.dot");
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: String = String::from_utf8(app.call_and_read_body(request).await.into())?;
    log::debug!("{response}");

    assert_eq!(
        response,
        r#"
digraph {
"SPDXRef-DOCUMENT" [label="SPDXRef-DOCUMENT"]
"SPDXRef-A" [label="A / 1: SPDXRef-A"]
"SPDXRef-B" [label="B / 1: SPDXRef-B"]
"SPDXRef-AA" [label="AA / 1: SPDXRef-AA"]
"SPDXRef-BB" [label="BB / 1: SPDXRef-BB"]
"SPDXRef-CC" [label="CC / 1: SPDXRef-CC"]
"SPDXRef-DD" [label="DD / 1: SPDXRef-DD"]
"SPDXRef-EE" [label="EE / 1: SPDXRef-EE"]
"SPDXRef-FF" [label="FF / 1: SPDXRef-FF"]
"SPDXRef-A" -> "SPDXRef-B" [label="Contains"]
"SPDXRef-AA" -> "SPDXRef-BB" [label="Contains"]
"SPDXRef-BB" -> "SPDXRef-CC" [label="Contains"]
"SPDXRef-BB" -> "SPDXRef-DD" [label="Contains"]
"SPDXRef-DD" -> "SPDXRef-FF" [label="Contains"]
"SPDXRef-DOCUMENT" -> "SPDXRef-A" [label="Describes"]
"SPDXRef-DOCUMENT" -> "SPDXRef-EE" [label="Undefined"]

}
"#
    );

    Ok(())
}

/// A test for an existing SBOM, but an unknown renderer.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn render_unsupported_ext(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let sbom = sbom.id;

    // Ensure child has an ancestor that includes it
    let uri = format!("/api/v2/analysis/sbom/{sbom}/render.foo");
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;

    assert_eq!(415, response.response().status());

    Ok(())
}
