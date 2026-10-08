#![recursion_limit = "512"]
#![allow(clippy::expect_used)]

use rstest::rstest;
use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
/// Ingested SBOM should not fail
async fn issue_1492(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let _result = ctx
        .ingest_document("spdx/issues/1492/sbom.spdx.json")
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
/// Ingested SBOM should not fail
async fn cvss_issue_1(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let _result = ctx
        .ingest_document("csaf/issues/cvss_1/ssa-054046.json")
        .await?;

    Ok(())
}

/// What a CSAF document states per purl: (vulnerability, purl, version scheme, low, high, status),
/// and the remediations linked to those: (vulnerability, remediation details, purl).
type PurlStatements = (
    Vec<(
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    )>,
    Vec<(String, String, String)>,
);

async fn purl_statements(
    ctx: &TrustifyContext,
    advisory_id: &str,
) -> anyhow::Result<PurlStatements> {
    let advisory_id = Uuid::parse_str(advisory_id)?;

    let statuses = ctx
        .db
        .query_all(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT ps.vulnerability_id, bp.type || '/' || COALESCE(bp.namespace || '/', '') || bp.name,
       vr.version_scheme_id, vr.low_version, vr.high_version, s.slug
FROM purl_status ps
JOIN base_purl bp ON bp.id = ps.base_purl_id
JOIN version_range vr ON vr.id = ps.version_range_id
JOIN status s ON s.id = ps.status_id
WHERE ps.advisory_id = $1
ORDER BY 1, 2, 6
"#,
            [advisory_id.into()],
        ))
        .await?
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get_by_index(0)?,
                row.try_get_by_index(1)?,
                row.try_get_by_index(2)?,
                row.try_get_by_index(3)?,
                row.try_get_by_index(4)?,
                row.try_get_by_index(5)?,
            ))
        })
        .collect::<Result<Vec<_>, DbErr>>()?;

    let remediations = ctx
        .db
        .query_all(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
SELECT r.vulnerability_id, r.details, bp.type || '/' || COALESCE(bp.namespace || '/', '') || bp.name
FROM remediation r
JOIN remediation_purl_status rps ON rps.remediation_id = r.id
JOIN purl_status ps ON ps.id = rps.purl_status_id
JOIN base_purl bp ON bp.id = ps.base_purl_id
WHERE r.advisory_id = $1
ORDER BY 1, 2, 3
"#,
            [advisory_id.into()],
        ))
        .await?
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get_by_index(0)?,
                row.try_get_by_index(1)?,
                row.try_get_by_index(2)?,
            ))
        })
        .collect::<Result<Vec<_>, DbErr>>()?;

    Ok((statuses, remediations))
}

/// CSAF defines products as branches, in `full_product_names`, or in relationships. Wherever the
/// same products are defined, the stated purl statuses and remediations are the same.
///
/// The `product` and `product_status` rows legitimately differ: branches state vendor, product
/// name and version separately, while a full product name has only one name.
#[test_context(TrustifyContext)]
#[rstest]
#[case::branches("csaf/issues/2740/baseline-branches.json")]
#[case::full_product_names("csaf/issues/2740/variant-full_product_names.json")]
#[test_log::test(tokio::test)]
async fn issue_2740(ctx: &TrustifyContext, #[case] document: &str) -> anyhow::Result<()> {
    let result = ctx.ingest_document(document).await?;

    let statuses = [
        ("CVE-2097-10001", "not_affected"),
        ("CVE-2098-10001", "not_affected"),
        ("CVE-2099-10001", "affected"),
    ]
    .into_iter()
    .flat_map(|(vulnerability, status)| {
        [("product-1", "1.1.1"), ("product-2", "1.1.2")].map(|(name, version)| {
            (
                vulnerability.to_string(),
                format!("generic/example/{name}"),
                "generic".to_string(),
                Some(version.to_string()),
                Some(version.to_string()),
                status.to_string(),
            )
        })
    })
    .collect::<Vec<_>>();
    let remediations = ["product-1", "product-2"]
        .map(|name| {
            (
                "CVE-2099-10001".to_string(),
                "Action 1-1 for every selected product.".to_string(),
                format!("generic/example/{name}"),
            )
        })
        .to_vec();

    assert_eq!(
        purl_statements(ctx, &result.id).await?,
        (statuses, remediations)
    );

    Ok(())
}
