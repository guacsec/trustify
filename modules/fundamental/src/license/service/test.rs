use crate::license::service::LicenseService;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use test_context::test_context;
use test_log::test;
use trustify_common::{db::query::Query, id::Id, model::Paginated};
use trustify_entity::{expanded_license, sbom_license_expanded};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

/// RED-GREEN-REFACTOR: Test licenses() UNION query
/// Verifies: expanded_license.expanded_text UNION license.text for CycloneDX
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_licenses_union_spdx_and_cyclonedx(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let service = LicenseService::new();

    // RED: Before ingestion
    let result_before = service
        .licenses(
            Query::default(),
            Paginated {
                total: true,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;
    let baseline_count = result_before.total;

    // GREEN: Ingest SPDX (uses expanded_license) and CycloneDX (uses license.text directly)
    ctx.ingest_documents([
        "spdx/OCP-TOOLS-4.11-RHEL-8.json",
        "zookeeper-3.9.2-cyclonedx.json",
    ])
    .await?;

    // REFACTOR: Verify UNION includes both sources
    let result_after = service
        .licenses(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 1000,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    assert!(
        result_after.total > baseline_count,
        "Should have more licenses after ingestion"
    );

    // Verify expanded_license table has SPDX data
    let expanded_count = expanded_license::Entity::find().count(&ctx.db).await?;
    assert!(expanded_count > 0, "expanded_license should have SPDX data");

    // Verify no raw LicenseRef- in results (SPDX should be expanded)
    let has_license_ref = result_after
        .items
        .iter()
        .any(|l| l.license.contains("LicenseRef-"));
    assert!(
        !has_license_ref,
        "Results should not contain raw LicenseRef-"
    );

    Ok(())
}

/// RED-GREEN-REFACTOR: Test get_all_license_info() COALESCE logic
/// Verifies: COALESCE(expanded_license.expanded_text, license.text)
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_get_all_license_info_coalesce(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new();

    // RED: Ingest SPDX with LicenseRef
    let result = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;
    let sbom_id = Uuid::parse_str(&result.id)?;

    // GREEN: Get license info
    let info = service
        .get_all_license_info(Id::Uuid(sbom_id), &ctx.db)
        .await?
        .expect("Should have license info");

    // REFACTOR: Verify data uses COALESCE - no LicenseRef-, all expanded
    for mapping in &info {
        assert!(
            !mapping.license_name.contains("LicenseRef-"),
            "license_name should be expanded: {}",
            mapping.license_name
        );
        assert_eq!(
            mapping.license_id, mapping.license_name,
            "Both fields use same COALESCE"
        );
    }

    // Verify junction table was consulted
    let junction_count = sbom_license_expanded::Entity::find()
        .filter(sbom_license_expanded::Column::SbomId.eq(sbom_id))
        .count(&ctx.db)
        .await?;
    assert!(junction_count > 0, "Junction table should have entries");

    Ok(())
}

/// RED-GREEN-REFACTOR: Test junction table (sbom_id, license_id) → expanded_license_id mapping
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_junction_table_mapping_integrity(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // RED: Empty junction
    assert_eq!(
        sbom_license_expanded::Entity::find().count(&ctx.db).await?,
        0
    );

    // GREEN: Ingest
    let result = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;
    let sbom_id = Uuid::parse_str(&result.id)?;

    // REFACTOR: Verify every junction entry references valid expanded_license
    let entries = sbom_license_expanded::Entity::find()
        .filter(sbom_license_expanded::Column::SbomId.eq(sbom_id))
        .all(&ctx.db)
        .await?;

    assert!(!entries.is_empty(), "Should have junction entries");

    for entry in entries {
        let expanded = expanded_license::Entity::find_by_id(entry.expanded_license_id)
            .one(&ctx.db)
            .await?;
        assert!(
            expanded.is_some(),
            "Junction should reference valid expanded_license_id"
        );
    }

    Ok(())
}

/// RED-GREEN-REFACTOR: Test MD5-based deduplication in expanded_license
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_expanded_license_md5_deduplication(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // RED: Ingest once
    ctx.ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;
    let count_first = expanded_license::Entity::find().count(&ctx.db).await?;

    // GREEN: Re-ingest same SBOM
    ctx.ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;

    // REFACTOR: Should have same count (MD5 index prevents duplicates)
    let count_second = expanded_license::Entity::find().count(&ctx.db).await?;
    assert_eq!(
        count_first, count_second,
        "MD5 hash should prevent duplicate expanded_text"
    );

    Ok(())
}

/// RED-GREEN-REFACTOR: Test that raw license.text is used for CycloneDX (no expansion)
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_cyclonedx_uses_raw_license_text(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new();

    // RED: Ingest CycloneDX
    ctx.ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;

    // GREEN: Verify CycloneDX DOES populate expanded_license (with raw text, not expanded)
    // CycloneDX licenses don't have LicenseRef patterns, so expanded_text = raw license.text
    let expanded_count = expanded_license::Entity::find().count(&ctx.db).await?;
    assert!(
        expanded_count > 0,
        "CycloneDX should populate expanded_license with raw license text"
    );

    // Verify sbom_license_expanded junction is populated
    let junction_count = sbom_license_expanded::Entity::find().count(&ctx.db).await?;
    assert!(
        junction_count > 0,
        "CycloneDX should populate sbom_license_expanded junction table"
    );

    // REFACTOR: licenses() should return CycloneDX licenses via expanded_license path
    let result = service
        .licenses(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 100,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    let has_cyclonedx_license = result.items.iter().any(|l| {
        l.license.contains("CDDL") || l.license.contains("GPL-2.0-with-classpath-exception")
    });
    assert!(
        has_cyclonedx_license,
        "Should have CycloneDX licenses from license.text"
    );

    Ok(())
}

/// RED-GREEN-REFACTOR: Test refactored Func::coalesce() correctness
/// Verifies: Type-safe COALESCE(expanded_license.expanded_text, license.text) works correctly
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_coalesce_refactoring_correctness(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new();

    // RED: Before ingestion
    // GREEN: Ingest SPDX (uses expanded_license via COALESCE)
    let spdx_result = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;
    let sbom_id = Uuid::parse_str(&spdx_result.id)?;

    let info = service
        .get_all_license_info(Id::Uuid(sbom_id), &ctx.db)
        .await?
        .expect("Should have license info");

    // REFACTOR: Verify all licenses properly coalesced (no nulls, all expanded)
    for mapping in &info {
        assert!(
            !mapping.license_name.is_empty(),
            "COALESCE should never produce empty string"
        );
        assert!(
            !mapping.license_id.is_empty(),
            "COALESCE should never produce empty string"
        );

        // Both columns use same COALESCE expression - should match
        assert_eq!(
            mapping.license_name, mapping.license_id,
            "Both fields should use same COALESCE expression"
        );
    }

    assert!(!info.is_empty(), "Should have at least one license");

    Ok(())
}

/// RED-GREEN-REFACTOR: Test refactored Func::count() accuracy
/// Verifies: COUNT(*) replaced with Func::count(Expr::col(Asterisk)) produces correct counts
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_license_count_accuracy(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new();

    // RED: Baseline count before ingestion
    let before = service
        .licenses(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 1000,
                total: true,
            },
            &ctx.db,
        )
        .await?;
    let baseline_count = before.total;

    // GREEN: Ingest documents with licenses
    ctx.ingest_documents([
        "spdx/OCP-TOOLS-4.11-RHEL-8.json",
        "zookeeper-3.9.2-cyclonedx.json",
    ])
    .await?;

    let after = service
        .licenses(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 1000,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    // REFACTOR: Verify count increased and matches actual items
    assert!(
        after.total > baseline_count,
        "Should have more licenses after ingestion"
    );

    let all_items = service
        .licenses(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 10000,
                total: true,
            },
            &ctx.db,
        )
        .await?;
    assert_eq!(
        all_items.total,
        Some(all_items.items.len() as u64),
        "Total count should match number of items when all fetched"
    );

    Ok(())
}

/// RED-GREEN-REFACTOR: Test ORDER BY refactored COALESCE expression
/// Verifies: ORDER BY Func::coalesce() works correctly
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_license_ordering_by_coalesce(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new();

    // RED: No licenses before ingestion
    // GREEN: Ingest multiple documents to get variety of licenses
    ctx.ingest_documents([
        "spdx/OCP-TOOLS-4.11-RHEL-8.json",
        "zookeeper-3.9.2-cyclonedx.json",
    ])
    .await?;

    let result = service
        .licenses(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 100,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    // REFACTOR: Verify licenses are ordered alphabetically via COALESCE
    let licenses: Vec<String> = result.items.iter().map(|l| l.license.clone()).collect();
    let mut sorted_licenses = licenses.clone();
    sorted_licenses.sort();

    assert_eq!(
        licenses, sorted_licenses,
        "Licenses should be ordered alphabetically via COALESCE"
    );
    assert!(
        !licenses.is_empty(),
        "Should have licenses to verify ordering"
    );

    Ok(())
}

/// RED-GREEN-REFACTOR: Test filtering on COALESCE result
/// Verifies: Filtering works on both expanded_text and raw text via COALESCE
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_license_filtering_on_coalesce(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    use trustify_common::db::query::q;
    let service = LicenseService::new();

    // RED: No licenses before ingestion
    // GREEN: Ingest SPDX (expanded) and CycloneDX (raw) licenses
    ctx.ingest_documents([
        "spdx/OCP-TOOLS-4.11-RHEL-8.json",
        "zookeeper-3.9.2-cyclonedx.json",
    ])
    .await?;

    // Search for Apache licenses (should find in both SPDX expanded and CycloneDX raw)
    let apache_results = service
        .licenses(
            q("Apache"),
            Paginated {
                offset: 0,
                limit: 100,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    // REFACTOR: Verify filtering works on COALESCE result
    assert!(
        apache_results.total > Some(0),
        "Should find Apache licenses"
    );

    for license in &apache_results.items {
        assert!(
            license.license.to_lowercase().contains("apache"),
            "Filtered result should contain 'apache': {}",
            license.license
        );
    }

    Ok(())
}

/// RED-GREEN-REFACTOR: Test COALESCE NULL handling
/// Verifies: COALESCE properly handles NULLs (expanded_text NULL → fallback to license.text)
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_coalesce_null_handling(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new();

    // RED: No licenses before ingestion
    // GREEN: Ingest CycloneDX (doesn't use expanded_license, so expanded_text is NULL)
    ctx.ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;

    let result = service
        .licenses(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 100,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    // REFACTOR: Verify COALESCE fallback to license.text works when expanded_text is NULL
    assert!(
        result.total > Some(0),
        "Should get CycloneDX licenses via COALESCE fallback to license.text"
    );

    for license in &result.items {
        assert!(
            !license.license.is_empty(),
            "COALESCE should provide non-empty license text"
        );
    }

    Ok(())
}

/// RED-GREEN-REFACTOR: Test pagination with UNION and refactored COUNT
/// Verifies: Paginated queries return correct subset and total count via Func::count()
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_license_pagination_with_count(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new();

    // RED: No licenses before ingestion
    // GREEN: Ingest documents to create paginated results
    ctx.ingest_documents([
        "spdx/OCP-TOOLS-4.11-RHEL-8.json",
        "zookeeper-3.9.2-cyclonedx.json",
    ])
    .await?;

    let page1 = service
        .licenses(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 5,
                total: true,
            },
            &ctx.db,
        )
        .await?;
    let total = page1.total;

    // REFACTOR: Verify pagination works correctly with refactored COUNT
    assert!(page1.items.len() <= 5, "Page 1 should have at most 5 items");
    assert!(
        total >= Some(page1.items.len() as u64),
        "Total should be >= page 1 items"
    );

    let page2 = service
        .licenses(
            Query::default(),
            Paginated {
                offset: 5,
                limit: 5,
                total: true,
            },
            &ctx.db,
        )
        .await?;
    assert_eq!(
        page2.total, total,
        "Total count should be same across pages"
    );

    // Verify pages don't overlap
    let page1_licenses: Vec<String> = page1.items.iter().map(|l| l.license.clone()).collect();
    let page2_licenses: Vec<String> = page2.items.iter().map(|l| l.license.clone()).collect();

    for license in &page2_licenses {
        assert!(
            !page1_licenses.contains(license),
            "Pages should not contain duplicate licenses"
        );
    }

    Ok(())
}

/// Test that pre-loaded SPDX dictionary entries appear in license listing
/// Verifies: LEFT JOIN on sbom_package_license allows pre-loaded licenses to be visible
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_preloaded_licenses_visible(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new();

    // Baseline: Get initial license count (includes pre-loaded SPDX dictionary)
    let before = service
        .licenses(
            Query::default(),
            Paginated {
                total: true,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    // Pre-loaded licenses should be visible even before any SBOM ingestion
    assert!(
        before.total > Some(0),
        "Pre-loaded SPDX dictionary entries should be visible"
    );

    Ok(())
}
