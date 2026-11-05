#![recursion_limit = "512"]

use rstest::rstest;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, ModelTrait, QueryFilter, Statement,
};
use serde_json::Value;
use std::collections::HashSet;
use test_context::test_context;
use trustify_entity::{
    advisory, advisory_vulnerability, base_purl, purl_status, status, version_range,
    version_scheme::VersionScheme,
};
use trustify_module_ingestor::service::Format;
use trustify_test_context::{TrustifyContext, document_bytes};
use uuid::Uuid;

// Fixtures are public advisories from https://github.com/project-lightwell/lightwell-osv.
struct LightwellCase {
    id: &'static str,
    /// The `CVE-` entry of `upstream`; release/0.7.z keys vulnerabilities on it.
    cve: &'static str,
    purl: &'static str,
    scheme: VersionScheme,
    base: &'static str,
    fixed: &'static str,
    /// The stored lower bound; release/0.7.z stores `introduced: "0"` as an inclusive "0".
    low: &'static str,
}

/// Verifies that unmodified Lightwell fixtures import and store native-scheme statuses under the
/// upstream CVE (reproducer for TC-7303 on release/0.7.z).
#[test_context(TrustifyContext)]
#[rstest]
#[case::maven(LightwellCase {
    id: "RHLW-2026-02416b185203289c",
    cve: "CVE-2026-42579",
    purl: "pkg:maven/io.netty/netty-codec-dns",
    scheme: VersionScheme::Maven,
    base: "4.1.132.Final",
    fixed: "4.1.132.Final-rhlw-00002",
    low: "4.1.132.Final",
})]
#[case::pypi(LightwellCase {
    id: "RHLW-2026-821eaab8409c2a61",
    cve: "CVE-2023-36464",
    purl: "pkg:pypi/pypdf2",
    scheme: VersionScheme::Python,
    base: "3.0.1",
    fixed: "3.0.1+rhlw.1",
    low: "0",
})]
#[test_log::test(tokio::test)]
async fn lightwell_native_ranges(
    ctx: &TrustifyContext,
    #[case] case: LightwellCase,
) -> anyhow::Result<()> {
    // Given the unmodified fixture, and a variant without the stated PURL and `versions`
    let bytes = document_bytes(format!("osv/{}.json", case.id)).await?;
    let mut inferred: Value = serde_json::from_slice(&bytes)?;
    for affected in inferred["affected"].as_array_mut().unwrap() {
        affected["package"].as_object_mut().unwrap().remove("purl");
        affected.as_object_mut().unwrap().remove("versions");
    }

    // Keep the source ecosystem unchanged. Without either escape hatch, only native ecosystem
    // resolution can infer the PURL and persist a real ECOSYSTEM interval.
    // The scoped/repository variants are not applicable on release/0.7.z: purl_status has no
    // qualified_purl_id, so stored repository qualifiers cannot be asserted.
    let variants = vec![
        (bytes.to_vec(), true),
        (serde_json::to_vec(&inferred)?, false),
    ];
    for (bytes, explicit_versions) in variants {
        // When ingesting the document
        let result = ctx
            .ingest_bytes_as(&bytes, Format::Unknown, ("source", "lightwell-test"))
            .await?;

        // Then it imports without warnings
        assert!(!result.duplicate);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert_eq!(result.document_id.as_deref(), Some(case.id));
        let advisory_id = Uuid::parse_str(&result.id)?;
        let advisory = advisory::Entity::find_by_id(advisory_id)
            .one(&ctx.db)
            .await?
            .unwrap();
        assert_eq!(advisory.document_id, case.id);
        assert_eq!(advisory.identifier, case.id);

        // And the vulnerability is the upstream CVE
        let vulnerabilities = advisory_vulnerability::Entity::find()
            .filter(advisory_vulnerability::Column::AdvisoryId.eq(advisory_id))
            .all(&ctx.db)
            .await?;
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].vulnerability_id, case.cve);
        // Upstream links (advisory_vulnerability_upstream) are not applicable on release/0.7.z.

        // And the statuses use the native scheme
        let statuses = purl_status::Entity::find()
            .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
            .find_also_related(version_range::Entity)
            .all(&ctx.db)
            .await?;
        // Generic affected (from `versions`), native affected and native fixed.
        assert_eq!(statuses.len(), if explicit_versions { 3 } else { 2 });
        let mut native_ranges = 0;
        let mut fixed_statuses = 0;
        for (statement, range) in statuses {
            assert_eq!(statement.vulnerability_id, case.cve);
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
            let status = status::Entity::find_by_id(statement.status_id)
                .one(&ctx.db)
                .await?
                .unwrap();
            let range = range.unwrap();

            if status.slug == "fixed" {
                // release/0.7.z stores a `fixed` status instead of a remediation.
                fixed_statuses += 1;
                assert_eq!(range.version_scheme_id, case.scheme);
                assert_eq!(range.low_version.as_deref(), Some(case.fixed));
                assert_eq!(range.high_version.as_deref(), Some(case.fixed));
                assert_eq!(range.low_inclusive, Some(true));
                assert_eq!(range.high_inclusive, Some(true));
                continue;
            }

            assert_eq!(status.slug, "affected");
            // Qualified PURL repository_url assertions are not applicable on release/0.7.z.
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
            assert_eq!(range.low_version.as_deref(), Some(case.low));
            assert_eq!(range.low_inclusive, Some(true));
            assert_eq!(range.high_version.as_deref(), Some(case.fixed));
            assert_eq!(range.high_inclusive, Some(false));
            // Remediations are not applicable on release/0.7.z.

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
        assert_eq!(fixed_statuses, 1);
    }
    Ok(())
}

/// Verifies that conflicting and unsupported Lightwell entries are warned about and skipped
/// while a valid sibling entry is still stored.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn ambiguous_and_unsupported_entries_warn_without_losing_valid_siblings(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    // Given a valid entry between a repository conflict and an entry without a usable PURL
    let bytes = document_bytes("osv/RHLW-2026-02416b185203289c.json").await?;
    let mut document: Value = serde_json::from_slice(&bytes)?;
    let valid = document["affected"][0].clone();
    let mut conflicting = valid.clone();
    conflicting["package"]["ecosystem"] =
        "Red Hat Lightwell:Maven:https://vendor.example/repo".into();
    conflicting["package"]["purl"] =
        "pkg:maven/io.netty/netty-codec-dns?repository_url=https:%2F%2Fother.example%2Frepo".into();
    document["affected"] = serde_json::json!([
        conflicting,
        valid,
        {"package": {"ecosystem": "Red Hat Lightwell:Debian:12", "name": "openssl"}, "versions": ["1.0"]}
    ]);

    // When ingesting it
    let result = ctx
        .ingest_bytes_as(
            &serde_json::to_vec(&document)?,
            Format::OSV,
            ("source", "lightwell-test"),
        )
        .await?;

    // Then both skipped entries are warned about
    assert!(!result.duplicate);
    assert_eq!(result.warnings.len(), 2, "{:?}", result.warnings);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.starts_with("Conflicting repositories"))
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.starts_with("No usable PURL"))
    );

    // And only the valid sibling is stored: Generic affected, Maven affected and Maven fixed
    let advisory_id = Uuid::parse_str(&result.id)?;
    let statements = purl_status::Entity::find()
        .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
        .find_also_related(base_purl::Entity)
        .all(&ctx.db)
        .await?;
    assert_eq!(statements.len(), 3);
    for (_, package) in statements {
        let package = package.unwrap();
        assert_eq!(package.namespace.as_deref(), Some("io.netty"));
        assert_eq!(package.name, "netty-codec-dns");
    }
    Ok(())
}

/// Verifies that Lightwell PURL warnings are reported once per affected entry, not once per CVE,
/// while statuses are still stored for every CVE.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn lightwell_warnings_are_not_repeated_per_cve(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given a valid entry and a repository conflict, in a record with two upstream CVEs
    let bytes = document_bytes("osv/RHLW-2026-02416b185203289c.json").await?;
    let mut document: Value = serde_json::from_slice(&bytes)?;
    document["upstream"]
        .as_array_mut()
        .unwrap()
        .push("CVE-2026-0003".into());
    let valid = document["affected"][0].clone();
    let mut conflicting = valid.clone();
    conflicting["package"]["ecosystem"] =
        "Red Hat Lightwell:Maven:https://vendor.example/repo".into();
    conflicting["package"]["purl"] =
        "pkg:maven/io.netty/netty-codec-dns?repository_url=https:%2F%2Fother.example%2Frepo".into();
    document["affected"] = serde_json::json!([conflicting, valid]);

    // When ingesting it
    let result = ctx
        .ingest_bytes_as(
            &serde_json::to_vec(&document)?,
            Format::OSV,
            ("source", "lightwell-test"),
        )
        .await?;

    // Then the conflict is warned about once
    assert_eq!(result.warnings.len(), 1, "{:?}", result.warnings);
    assert!(result.warnings[0].starts_with("Conflicting repositories"));

    // And the valid entry is stored for both CVEs
    let statements = purl_status::Entity::find()
        .filter(purl_status::Column::AdvisoryId.eq(Uuid::parse_str(&result.id)?))
        .all(&ctx.db)
        .await?;
    assert_eq!(
        statements
            .iter()
            .map(|statement| statement.vulnerability_id.as_str())
            .collect::<HashSet<_>>(),
        HashSet::from(["CVE-2026-42579", "CVE-2026-0003"])
    );
    // Generic affected, Maven affected and Maven fixed, for each CVE.
    assert_eq!(statements.len(), 6);
    Ok(())
}

/// Verifies that ordinary OSV packages keep both inferred and stated PURL candidates for every
/// version form, without warnings.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn ordinary_purl_candidates_survive_all_version_forms(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    // Given an ordinary npm record whose packages also state a generic PURL
    let cases = [
        (
            "versions",
            serde_json::json!({"versions": ["1.0.0"]}),
            VersionScheme::Generic,
        ),
        (
            "ecosystem",
            serde_json::json!({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}),
            VersionScheme::Npm,
        ),
        (
            "semver",
            serde_json::json!({"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}),
            VersionScheme::Semver,
        ),
        (
            "git",
            serde_json::json!({"ranges": [{"type": "GIT", "repo": "https://example.com/demo.git", "events": [{"introduced": "0"}, {"fixed": "0123456789012345678901234567890123456789"}]}]}),
            VersionScheme::Git,
        ),
    ];
    let affected = cases
        .iter()
        .map(|(name, fields, _)| {
            let mut entry = fields.clone();
            entry["package"] = serde_json::json!({
                "ecosystem": "npm",
                "name": format!("demo-{name}"),
                "purl": format!("pkg:generic/demo-{name}"),
            });
            entry
        })
        .collect::<Vec<_>>();
    // On release/0.7.z, ordinary OSV records need a CVE alias to store statuses.
    let document = serde_json::json!({
        "id": "OSV-2026-identity-compatibility",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2026-0001"],
        "affected": affected,
    });

    // When ingesting it
    let result = ctx
        .ingest_bytes_as(
            &serde_json::to_vec(&document)?,
            Format::OSV,
            ("source", "compatibility-test"),
        )
        .await?;

    // Then both PURL types are stored for every version form, with the expected scheme
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let statements = purl_status::Entity::find()
        .filter(purl_status::Column::AdvisoryId.eq(Uuid::parse_str(&result.id)?))
        .find_also_related(base_purl::Entity)
        .all(&ctx.db)
        .await?;
    // 2 Generic for `versions`, plus 2 PURL types x (affected + fixed) x 3 range forms.
    assert_eq!(statements.len(), 14);
    for (name, _, scheme) in cases {
        let expected_name = format!("demo-{name}");
        let mut types = HashSet::new();
        for (statement, package) in &statements {
            let package = package.as_ref().unwrap();
            if package.name != expected_name {
                continue;
            }
            types.insert(package.r#type.as_str());
            let range = statement
                .find_related(version_range::Entity)
                .one(&ctx.db)
                .await?
                .unwrap();
            assert_eq!(range.version_scheme_id, scheme);
        }
        assert_eq!(types, HashSet::from(["generic", "npm"]));
    }
    Ok(())
}

/// Verifies that Lightwell NuGet stores the ecosystem/name spelling, while ordinary OSV retains
/// both candidates. This is not general case-insensitive matching.
#[test_context(TrustifyContext)]
#[rstest]
#[case::ordinary("NuGet", &["PowerShell", "powershell"])]
#[case::lightwell("Red Hat Lightwell:NuGet", &["PowerShell"])]
#[test_log::test(tokio::test)]
async fn osv_nuget_inferred_spelling_storage(
    ctx: &TrustifyContext,
    #[case] ecosystem: &str,
    #[case] expected_names: &[&str],
    #[values(false, true)] explicit_versions: bool,
) -> anyhow::Result<()> {
    // Given a NuGet package whose stated PURL uses a different spelling
    let mut affected = serde_json::json!({"package": {
        "ecosystem": ecosystem,
        "name": "PowerShell",
        "purl": "pkg:nuget/powershell?repository_url=https:%2F%2Fvendor.example%2Fnuget"
    }});
    if explicit_versions {
        affected["versions"] = serde_json::json!(["1.0.0"]);
    } else {
        affected["ranges"] = serde_json::json!([{
            "type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
        }]);
    }
    let osv = serde_json::json!({
        "id": "OSV-NUGET-SPELLING", "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2026-0002"],
        "affected": [affected]
    });

    // When ingesting it
    let advisory = ctx
        .ingest_bytes_as(
            &serde_json::to_vec(&osv)?,
            Format::OSV,
            ("source", "nuget-test"),
        )
        .await?;

    // Then the stored base PURL names match the expected spellings
    assert!(advisory.warnings.is_empty(), "{:?}", advisory.warnings);
    let stored = purl_status::Entity::find()
        .filter(purl_status::Column::AdvisoryId.eq(Uuid::parse_str(&advisory.id)?))
        .find_also_related(base_purl::Entity)
        .all(&ctx.db)
        .await?;
    assert_eq!(
        stored
            .iter()
            .map(|(_, base)| base.as_ref().unwrap().name.as_str())
            .collect::<HashSet<_>>(),
        expected_names.iter().copied().collect()
    );
    // The qualified_purl assertion and SBOM correlation are not applicable on release/0.7.z.
    Ok(())
}
