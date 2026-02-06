#![allow(clippy::expect_used)]

use roxmltree::Document;
use std::io::Read;
use test_context::test_context;
use test_log::test;
use trustify_common::{hashing::HashingRead, model::Paginated};
use trustify_entity::labels::Labels;
use trustify_module_fundamental::weakness::service::WeaknessService;
use trustify_module_ingestor::service::weakness::CweCatalogLoader;
use trustify_test_context::{TrustifyContext, document_read};
use zip::ZipArchive;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const TOTAL_ITEMS_FOUND: u64 = 964;

    let loader = CweCatalogLoader::new();
    let service = WeaknessService::new(ctx.db.clone());

    // extract document from zip file

    let zip = document_read("cwec_latest.xml.zip")?;

    let mut archive = ZipArchive::new(zip)?;

    let entry = archive.by_index(0)?;

    let mut hashing = HashingRead::new(entry);
    let mut xml = String::new();
    hashing.read_to_string(&mut xml)?;
    let digests = hashing.finish()?;

    // load

    let doc = Document::parse(&xml)?;
    ctx.db
        .transaction(async |tx| loader.load(Labels::default(), &doc, &digests, tx).await)
        .await?;

    // fetch data

    let all = service
        .list_weaknesses(
            Default::default(),
            Paginated {
                offset: 0,
                limit: 10,
            },
        )
        .await?;

    assert_eq!(TOTAL_ITEMS_FOUND, all.total);

    let w = service
        .get_weakness("CWE-1004")
        .await?
        .expect("must be found");

    assert_eq!(
        w.head.description.as_deref(),
        Some(
            "The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag."
        )
    );

    // now update (poor man's XML update)

    let xml = xml.replace("<Description>The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.</Description>", "<Description>Foo Bar Update</Description>");

    // load again

    let doc = Document::parse(&xml)?;
    ctx.db
        .transaction(async |tx| loader.load(Labels::default(), &doc, &digests, tx).await)
        .await?;

    // fetch data again

    let all = service
        .list_weaknesses(
            Default::default(),
            Paginated {
                offset: 0,
                limit: 10,
            },
        )
        .await?;

    // must be the same number of items

    assert_eq!(964, all.total);

    let w = service
        .get_weakness("CWE-1004")
        .await?
        .expect("must be found");

    // but a different description

    assert_eq!(w.head.description.as_deref(), Some("Foo Bar Update"));

    // done

    Ok(())
}
