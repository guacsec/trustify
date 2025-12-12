use crate::{
    config::AnalysisConfig,
    service::{AnalysisService, QueryOptions},
    test::escape_q,
};
use rstest::rstest;
use std::collections::HashSet;
use test_context::test_context;
use trustify_common::db::query::Query;
use trustify_test_context::TrustifyContext;

/// Ensure that the DB logic and the in-memory logic are aligned
#[test_context(TrustifyContext)]
#[rstest]
// There should be not match for PURLs in default fields
#[case(escape_q("pkg:rpm/redhat/A@0.0.0?arch=src"), 0)]
// When asking for PURL, it must be found
#[case(format!("purl~{}", escape_q("pkg:rpm/redhat/A@0.0.0?arch=src")), 1)]
// When asking for PURL, it must be found, even with a partial match
#[case(format!("purl~{}", escape_q("pkg:rpm/redhat/A")), 1)]
// When searching for the PURL type, one entry must be found
#[case("purl:ty=rpm", 1)]
// Same when using the alias, or remove it
#[case("purl:type=rpm", 1)]
// By PURL name should work as well
#[case("purl:name=A", 1)]
// By CPE components, exact match
#[case("cpe:part=a&cpe:vendor=redhat&cpe:version=0.0.0", 1)]
#[test_log::test(tokio::test)]
async fn alignment(
    ctx: &TrustifyContext,
    #[case] q: String,
    #[case] num_sboms: usize,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let q = Query {
        q,
        ..Default::default()
    };

    // identify by DB query logic
    //
    // collect all sboms via a DB filter

    let sboms_a: HashSet<_> = service
        .load_graphs_query(&ctx.db, (&q).into())
        .await?
        .into_iter()
        .map(|r| r.0.to_string())
        .collect();

    // identify by in-memory logic
    //
    // Collect all SBOMs first, then process them via the in-memory implementation of the same
    // Should lead to the same number of results

    let all = service
        .load_graphs_query(&ctx.db, (&Query::default()).into())
        .await?;

    let sboms_b: HashSet<_> = service
        .run_graph_query(&q, QueryOptions::default(), &all, &ctx.db)
        .await?
        .into_iter()
        .map(|node| node.base.sbom_id)
        .collect();

    // compare

    assert_eq!(sboms_a, sboms_b, "Resulting SBOMs must be the same");
    assert_eq!(
        sboms_a.len(),
        num_sboms,
        "Number of matching SBOMs not as expected"
    );

    // done

    Ok(())
}
