#![recursion_limit = "512"]

use rstest::rstest;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, ModelTrait, QueryFilter, QueryOrder,
    Statement,
};
use serde_json::Value;
use test_context::test_context;
use trustify_entity::{
    advisory, advisory_vulnerability, advisory_vulnerability_upstream, base_purl, purl_status,
    qualified_purl,
    remediation::{self, RemediationCategory},
    status, version_range,
    version_scheme::VersionScheme,
};
use trustify_module_ingestor::service::Format;
use trustify_test_context::{TrustifyContext, document_bytes};
use uuid::Uuid;

// Fixtures are public advisories from https://github.com/project-lightwell/lightwell-osv.
struct LightwellCase {
    id: &'static str,
    upstream: [&'static str; 2],
    purl: &'static str,
    scheme: VersionScheme,
    base: &'static str,
    fixed: &'static str,
    low: Option<&'static str>,
}

#[test_context(TrustifyContext)]
#[rstest]
#[case::maven(LightwellCase {
    id: "RHLW-2026-02416b185203289c",
    upstream: ["CVE-2026-42579", "GHSA-cm33-6792-r9fm"],
    purl: "pkg:maven/io.netty/netty-codec-dns",
    scheme: VersionScheme::Maven,
    base: "4.1.132.Final",
    fixed: "4.1.132.Final-rhlw-00002",
    low: Some("4.1.132.Final"),
})]
#[case::pypi(LightwellCase {
    id: "RHLW-2026-821eaab8409c2a61",
    upstream: ["CVE-2023-36464", "GHSA-4vvm-4w3v-6mr8"],
    purl: "pkg:pypi/pypdf2",
    scheme: VersionScheme::Python,
    base: "3.0.1",
    fixed: "3.0.1+rhlw.1",
    low: None,
})]
#[test_log::test(tokio::test)]
async fn lightwell_native_ranges(
    ctx: &TrustifyContext,
    #[case] case: LightwellCase,
) -> anyhow::Result<()> {
    let bytes = document_bytes(format!("osv/{}.json", case.id)).await?;
    let mut inferred: Value = serde_json::from_slice(&bytes)?;
    for affected in inferred["affected"].as_array_mut().unwrap() {
        affected["package"].as_object_mut().unwrap().remove("purl");
        affected.as_object_mut().unwrap().remove("versions");
    }

    // Keep the source ecosystem unchanged. Without either escape hatch, only native ecosystem
    // resolution can infer the PURL and persist a real ECOSYSTEM interval.
    let mut scoped = inferred.clone();
    scoped["affected"][0]["package"]["purl"] = format!(
        "{}?repository_url=https:%2F%2Fvendor.example%2Frepo",
        case.purl
    )
    .into();
    for (bytes, explicit_versions, scoped_purl) in [
        (bytes.to_vec(), true, false),
        (serde_json::to_vec(&inferred)?, false, false),
        (serde_json::to_vec(&scoped)?, false, true),
    ] {
        let result = ctx
            .ingest_bytes_as(&bytes, Format::Unknown, ("source", "lightwell-test"))
            .await?;
        assert!(!result.duplicate);
        assert_eq!(result.document_id.as_deref(), Some(case.id));
        let advisory_id = Uuid::parse_str(&result.id)?;
        let advisory = advisory::Entity::find_by_id(advisory_id)
            .one(&ctx.db)
            .await?
            .unwrap();
        assert_eq!(advisory.document_id, case.id);
        assert_eq!(advisory.identifier, case.id);

        let vulnerabilities = advisory_vulnerability::Entity::find()
            .filter(advisory_vulnerability::Column::AdvisoryId.eq(advisory_id))
            .all(&ctx.db)
            .await?;
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].vulnerability_id, case.id);
        let upstream = advisory_vulnerability_upstream::Entity::find()
            .filter(advisory_vulnerability_upstream::Column::AdvisoryId.eq(advisory_id))
            .order_by_asc(advisory_vulnerability_upstream::Column::UpstreamId)
            .all(&ctx.db)
            .await?;
        assert_eq!(upstream.len(), 2);
        for (link, expected) in upstream.iter().zip(case.upstream) {
            assert_eq!(link.vulnerability_id, case.id);
            assert_eq!(link.upstream_id, expected);
        }

        let statuses = purl_status::Entity::find()
            .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
            .find_also_related(version_range::Entity)
            .all(&ctx.db)
            .await?;
        assert_eq!(statuses.len(), if explicit_versions { 2 } else { 1 });
        let mut native_ranges = 0;
        for (statement, range) in statuses {
            assert_eq!(statement.vulnerability_id, case.id);
            let purl = statement
                .find_related(base_purl::Entity)
                .one(&ctx.db)
                .await?
                .unwrap();
            assert_eq!(
                format!(
                    "pkg:{}/{}{}",
                    purl.r#type,
                    purl.namespace
                        .map(|ns| format!("{ns}/"))
                        .unwrap_or_default(),
                    purl.name,
                ),
                case.purl,
            );
            let status = statement
                .find_related(status::Entity)
                .one(&ctx.db)
                .await?
                .unwrap();
            assert_eq!(status.slug, "affected");
            let qualified = statement
                .find_related(qualified_purl::Entity)
                .one(&ctx.db)
                .await?
                .unwrap();
            assert_eq!(
                qualified
                    .qualifiers
                    .0
                    .get("repository_url")
                    .map(String::as_str),
                scoped_purl.then_some("https://vendor.example/repo")
            );
            let range = range.unwrap();
            if range.version_scheme_id == VersionScheme::Generic {
                // The unchanged fixture additionally enumerates the vulnerable base version.
                assert!(explicit_versions);
                assert_eq!(range.low_version.as_deref(), Some(case.base));
                assert_eq!(range.high_version.as_deref(), Some(case.base));
                assert_eq!(range.low_inclusive, Some(true));
                assert_eq!(range.high_inclusive, Some(true));
                continue;
            }
            native_ranges += 1;
            assert_eq!(range.version_scheme_id, case.scheme);
            assert_eq!(range.low_version.as_deref(), case.low);
            assert_eq!(range.low_inclusive, Some(case.low.is_some()));
            assert_eq!(range.high_version.as_deref(), Some(case.fixed));
            assert_eq!(range.high_inclusive, Some(false));

            let fixes = statement
                .find_related(remediation::Entity)
                .all(&ctx.db)
                .await?;
            assert_eq!(fixes.len(), 1);
            let fix = &fixes[0];
            assert_eq!(fix.advisory_id, advisory_id);
            assert_eq!(fix.vulnerability_id, case.id);
            assert_eq!(fix.category, RemediationCategory::VendorFix);
            assert_eq!(
                fix.details.as_deref(),
                Some(format!("Fixed in {}", case.fixed).as_str())
            );
            assert_eq!(fix.data, serde_json::json!({"fixed": case.fixed}));

            // Evaluate the actual stored composite, not a reconstructed or effective range.
            let matches = ctx.db.query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT version_matches($1, vr) AS vulnerable, version_matches($2, vr) AS fixed \
                 FROM version_range vr WHERE vr.id = $3",
                [case.base.into(), case.fixed.into(), range.id.into()],
            )).await?.unwrap();
            assert!(matches.try_get::<bool>("", "vulnerable")?);
            assert!(!matches.try_get::<bool>("", "fixed")?);
        }
        assert_eq!(native_ranges, 1);
    }
    Ok(())
}
