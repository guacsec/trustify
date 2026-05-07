use crate::sbom::model::SbomPackage;
use crate::{
    purl::service::PurlService, sbom::model::SbomExternalPackageReference,
    sbom::service::SbomService,
};
use sea_orm::TransactionTrait;
use std::{collections::HashMap, str::FromStr};
use test_context::test_context;
use test_log::test;
use trustify_common::{
    cpe::Cpe,
    db::{
        pagination_cache::PaginationCache,
        query::{Query, q},
    },
    id::Id,
    model::Paginated,
    purl::Purl,
};
use trustify_entity::labels::Labels;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn sbom_details_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let results = ctx
        .ingest_documents([
            "cve/CVE-2024-29025.json",
            "csaf/rhsa-2024-2705.json",
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let id_3_2_12 = results[3].id.clone();

    let details = service
        .fetch_sbom_details(Id::parse_uuid(id_3_2_12)?, Default::default(), &ctx.db)
        .await?;

    assert!(details.is_some());

    let details = details.unwrap();

    log::debug!("{details:#?}");

    let details = service
        .fetch_sbom_details(
            Id::Uuid(details.summary.head.id),
            Default::default(),
            &ctx.db,
        )
        .await?;

    assert!(details.is_some());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn count_sboms(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _ = ctx
        .ingest_documents([
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let neither_purl = Purl::from_str(
        "pkg:maven/io.smallrye/smallrye-graphql@0.0.0.redhat-00000?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
    )?;
    let both_purl = Purl::from_str(
        "pkg:maven/io.smallrye/smallrye-graphql@2.2.3.redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
    )?;
    let one_purl = Purl::from_str(
        "pkg:maven/io.quarkus/quarkus-kubernetes-service-binding-deployment@3.2.12.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
    )?;

    let neither_cpe = Cpe::from_str("cpe:/a:redhat:quarkus:0.0::el8")?;
    let both_cpe = Cpe::from_str("cpe:/a:redhat:quarkus:3.2::el8")?;

    assert_ne!(neither_cpe.uuid(), both_cpe.uuid());

    let counts = service
        .count_related_sboms(
            vec![
                SbomExternalPackageReference::Cpe(&neither_cpe),
                SbomExternalPackageReference::Cpe(&both_cpe),
                SbomExternalPackageReference::Purl(&neither_purl),
                SbomExternalPackageReference::Purl(&both_purl),
                SbomExternalPackageReference::Purl(&one_purl),
            ],
            &ctx.db,
        )
        .await?;

    assert_eq!(counts, vec![0, 2, 0, 2, 1]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn sbom_set_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let results = ctx
        .ingest_documents([
            "cve/CVE-2024-29025.json",
            "csaf/rhsa-2024-2705.json",
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let id_3_2_12 = Id::parse_uuid(&results[3].id)?;

    let mut map = HashMap::new();
    map.insert("label_1".to_string(), "First Label".to_string());
    map.insert("label_2".to_string(), "Second Label".to_string());
    let new_labels = Labels(map);
    service
        .set_labels(id_3_2_12.clone(), new_labels, &ctx.db)
        .await?;

    let details = service
        .fetch_sbom_details(id_3_2_12, Default::default(), &ctx.db)
        .await?;

    assert!(details.is_some());

    let details = details.unwrap();
    assert_eq!(details.summary.head.labels.len(), 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn sbom_update_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let results = ctx
        .ingest_documents([
            "cve/CVE-2024-29025.json",
            "csaf/rhsa-2024-2705.json",
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let id_3_2_12 = Id::parse_uuid(&results[3].id)?;

    let mut map = HashMap::new();
    map.insert("label_1".to_string(), "First Label".to_string());
    map.insert("label_2".to_string(), "Second Label".to_string());
    let new_labels = Labels(map);
    service
        .set_labels(id_3_2_12.clone(), new_labels, &ctx.db)
        .await?;

    let mut update_map = HashMap::new();
    update_map.insert("label_2".to_string(), "Label no 2".to_string());
    update_map.insert("label_3".to_string(), "Third Label".to_string());
    let update_labels = Labels(update_map);
    let update = trustify_entity::labels::Update::new();
    service
        .update_labels(id_3_2_12.clone(), |_| update.apply_to(update_labels))
        .await?;

    let details = service
        .fetch_sbom_details(id_3_2_12, Default::default(), &ctx.db)
        .await?;
    let details = details.unwrap();
    //update only alters values of pre-existing keys - it won't add in an entirely new key/value pair
    assert_eq!(details.summary.head.labels.clone().len(), 2);
    assert_eq!(
        details.summary.head.labels.0.get("label_2"),
        Some("Label no 2".to_string()).as_ref()
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn fetch_sboms_filter_by_license(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let paginated_with_total = Paginated {
        total: true,
        ..Default::default()
    };

    // Ingest SBOMs with license information
    ctx.ingest_document("spdx/mtv-2.6.json").await?;
    ctx.ingest_document("cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-02-24/quay-builder-qemu-rhcos-rhel-8-amd64.json").await?;

    // Test 1: Filter by specific license found in SPDX documents
    let results = service
        .fetch_sboms::<_, SbomPackage>(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"),
            paginated_with_total,
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("License filter results: {results:#?}");
    // Both SBOMs contain packages with this license combination
    assert_eq!(results.total, Some(2));
    assert_eq!(results.items.len(), 2);

    // Test 2: Filter by partial license match
    let results = service
        .fetch_sboms::<_, SbomPackage>(
            q("license~GPLv3+ with exceptions"),
            paginated_with_total,
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Partial license filter results: {results:#?}");
    // Both SBOMs contain packages with 'GPLv3+ with exceptions' license
    assert_eq!(results.total, Some(2));
    assert_eq!(results.items.len(), 2);

    // Test 3: Filter by license found in single SBOMs
    let results = service
        .fetch_sboms::<_, SbomPackage>(
            q("license~OFL"),
            paginated_with_total,
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("OFL license filter results: {results:#?}");
    // Only SPDX SBOMs contain packages with OFL license
    assert_eq!(results.total, Some(1));
    assert_eq!(results.items[0].head.name, "MTV-2.6");

    // Test 3b: Filter by license found in single SBOMs
    let results = service
        .fetch_sboms::<_, SbomPackage>(
            q("license=Apache 2.0"),
            paginated_with_total,
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Apache 2.0 license filter results: {results:#?}");
    // Only CycloneDX SBOM has Apache 2.0
    assert_eq!(results.total, Some(1));
    assert_eq!(
        results.items[0].head.name,
        "quay/quay-builder-qemu-rhcos-rhel8"
    );

    // Test 4: Test OR operation for multiple licenses
    let results = service
        .fetch_sboms::<_, SbomPackage>(
            q("license=OFL|Apache 2.0"),
            paginated_with_total,
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Multiple license OR filter results: {results:#?}");
    // Both SBOMs contain packages with these licenses
    assert_eq!(results.total, Some(2));
    assert_eq!(results.items.len(), 2);

    // Test 5: Negative test - license that doesn't exist
    let results = service
        .fetch_sboms::<_, SbomPackage>(
            q("license=NONEXISTENT_LICENSE"),
            paginated_with_total,
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Nonexistent license filter results: {results:#?}");
    // Should return no SBOMs
    assert_eq!(results.total, Some(0));
    assert!(results.items.is_empty());

    // Test 6: Empty license query
    let results = service
        .fetch_sboms::<_, SbomPackage>(
            q("license="),
            paginated_with_total,
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Empty license query results: {results:#?}");
    // Should return no SBOMs or handle gracefully
    assert_eq!(results.total, Some(0));
    assert!(results.items.is_empty());

    // Test 7: Combine license filter with other filters (should work together)
    let results = service
        .fetch_sboms::<_, SbomPackage>(
            q("license~Apache&name~quay"),
            paginated_with_total,
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Combined license + name filter results: {results:#?}");
    // Should find SBOMs that have both Apache license and name containing "quay"
    // CycloneDX SBOM has Apache license and "quay" in name
    assert_eq!(results.total, Some(1));
    assert_eq!(
        results.items[0].head.name,
        "quay/quay-builder-qemu-rhcos-rhel8"
    );

    // Test 8: Pagination with license filtering
    let results = service
        .fetch_sboms::<_, SbomPackage>(
            q("license~GPL").sort("name:desc"),
            Paginated {
                offset: 0,
                limit: 1,
                total: true,
            },
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Paginated license filter results: {results:#?}");
    // Should return at most 1 item but show total count
    // Both SBOMs contain GPL licenses, but limit to 1
    assert_eq!(results.items.len(), 1);
    assert_eq!(
        results.items[0].head.name,
        "quay/quay-builder-qemu-rhcos-rhel8"
    );
    assert_eq!(results.total, Some(2));

    // Test 8b: Pagination with license filtering and offset > 0
    let results_offset = service
        .fetch_sboms::<_, SbomPackage>(
            q("license~GPL").sort("name:desc"),
            Paginated {
                offset: 1,
                limit: 1,
                total: true,
            },
            Default::default(),
            &ctx.db,
        )
        .await?;
    log::debug!("Paginated license filter results with offset: {results_offset:#?}");
    // Should return the second item and total should still be 2
    assert_eq!(results_offset.items.len(), 1);
    assert_eq!(results_offset.items[0].head.name, "MTV-2.6");
    assert_eq!(results_offset.total, Some(2));

    // Test 9: Verify that SBOMs without license filters still work
    let all_results = service
        .fetch_sboms::<_, SbomPackage>(
            Query::default(),
            paginated_with_total,
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("All SBOMs results: {all_results:#?}");
    // Should return all SBOMs
    assert_eq!(all_results.total, Some(2)); // We ingested exactly 2 SBOMs

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn fetch_sbom_packages_filter_by_license(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let paginated_with_total = Paginated {
        total: true,
        ..Default::default()
    };

    // Ingest an SBOM with license information
    let sbom_id = Uuid::parse_str(&ctx.ingest_document("spdx/mtv-2.6.json").await?.id).unwrap();

    // Test 1: No license filter - should return all packages
    let all_packages = service
        .fetch_sbom_packages(sbom_id, Query::default(), paginated_with_total, &ctx.db)
        .await?;

    log::debug!("All packages count: {:?}", all_packages.total);
    assert_eq!(
        all_packages.total,
        Some(5388),
        "Should have packages in the SBOM"
    );

    // Test 2: Filter by specific license that exists
    let license_filtered = service
        .fetch_sbom_packages(
            sbom_id,
            q("license=GPLv2 AND GPLv2+ AND CC-BY"),
            paginated_with_total,
            &ctx.db,
        )
        .await?;

    log::debug!("License filtered packages: {license_filtered:#?}");
    // Should find packages with this specific license
    // This validates that the license filtering is applied correctly
    assert_eq!(license_filtered.total, Some(14));

    // Test 3: Filter by partial license match
    let partial_license_filtered = service
        .fetch_sbom_packages(sbom_id, q("license~GPL"), paginated_with_total, &ctx.db)
        .await?;

    log::debug!("Partial license filtered packages: {partial_license_filtered:#?}");
    // Should find packages with licenses containing "GPL"
    assert_eq!(partial_license_filtered.total, Some(448));

    // Test 4: Filter by non-existent license
    let no_match = service
        .fetch_sbom_packages(
            sbom_id,
            q("license=NONEXISTENT_LICENSE"),
            paginated_with_total,
            &ctx.db,
        )
        .await?;

    log::debug!("No match packages: {no_match:#?}");
    assert_eq!(
        no_match.total,
        Some(0),
        "Should return no packages for non-existent license"
    );
    assert!(
        no_match.items.is_empty(),
        "Items should be empty for non-existent license"
    );

    // Test 5: Combine license filter with other filters
    let combined_filter = service
        .fetch_sbom_packages(
            sbom_id,
            q("license~GPLv2 AND GPLv2+ AND CC-BY&name~qemu-kvm-"),
            paginated_with_total,
            &ctx.db,
        )
        .await?;

    log::debug!("Combined filter packages: {combined_filter:#?}");
    // Should apply both license and name filters
    assert_eq!(combined_filter.total, Some(11));

    // Test 6: Pagination with license filtering
    if partial_license_filtered.total > Some(1) {
        let paginated = service
            .fetch_sbom_packages(
                sbom_id,
                q("license~GPL"),
                Paginated {
                    offset: 0,
                    limit: 1,
                    total: true,
                },
                &ctx.db,
            )
            .await?;

        log::debug!("Paginated license filtered packages: {paginated:#?}");
        assert_eq!(paginated.items.len(), 1, "Should respect pagination limit");
        assert_eq!(
            paginated.total, partial_license_filtered.total,
            "Total should match full query"
        );
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn delete_sbom_orphaned_purl_test(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let purl_service = PurlService::new(PaginationCache::for_test());
    assert_eq!(
        0,
        purl_service
            .purls(Query::default(), Paginated::default(), &ctx.db)
            .await?
            .items
            .len()
    );

    // ingest an sbom
    let quarkus_sbom = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    // check the expected PURLs have been created
    assert_eq!(
        880,
        purl_service
            .purls(Query::default(), Paginated::default(), &ctx.db)
            .await?
            .items
            .len()
    );

    // ingest another sbom
    let ubi9_sbom = ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;

    // check there are more PURLs
    assert_eq!(
        1490,
        purl_service
            .purls(Query::default(), Paginated::default(), &ctx.db)
            .await?
            .items
            .len()
    );

    let tx = ctx.db.begin().await?;
    let sbom_service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());
    // delete the UBI SBOM
    assert!(sbom_service.delete_sbom(ubi9_sbom.id.parse()?, &tx).await?);
    tx.commit().await?;

    // it should not leave behind orphaned purls
    let result = purl_service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;
    // running the deletion, should have deleted those orphaned purls
    assert_eq!(880, result.items.len());

    // delete the quarkus sbom....
    let tx = ctx.db.begin().await?;
    assert!(
        sbom_service
            .delete_sbom(quarkus_sbom.id.parse()?, &tx)
            .await?
    );
    tx.commit().await?;

    // running the deletion, should have deleted those orphaned purls
    let result = purl_service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(0, result.items.len());
    Ok(())
}

/// Test that verifies the SBOM deletion preserves packages referenced by advisories.
///
/// This test validates the conservative SBOM deletion approach where packages are retained if
/// their base_purl is referenced in purl_status (advisory reference), even after the SBOM that
/// created them is deleted.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn delete_sbom_preserves_advisory_referenced_packages(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    use crate::purl::service::PurlService;

    // Ingest advisory and SBOMs with correlating data (same as sbom_details_status test)
    let results = ctx
        .ingest_documents([
            // this advisory refers to many packages in both the Quarkus SBOMs
            "csaf/rhsa-2024-2705.json",
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
            // this SBOM is totally unrelated with the previous documents
            "ubi9-9.2-755.1697625012.json",
        ])
        .await?;

    let purl_service = PurlService::new(PaginationCache::for_test());

    // Count all PURLs before deletion
    let paginated_with_total = Paginated {
        total: true,
        ..Default::default()
    };
    let packages_before = purl_service
        .purls(Query::default(), paginated_with_total, &ctx.db)
        .await?;
    log::debug!(
        "Total packages before SBOM deletion: {:?}",
        packages_before.total
    );
    assert_eq!(
        packages_before.total,
        Some(2087),
        "Should have packages after ingestion"
    );

    // Delete one of the SBOMs
    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());
    let sbom_uuid = results[1].id.parse().expect("SBOM should have a UUID");
    let tx = ctx.db.begin().await?;
    assert!(
        service.delete_sbom(sbom_uuid, &tx).await?,
        "SBOM should be deleted"
    );
    tx.commit().await?;

    // Count all packages after deletion
    let packages_after = purl_service
        .purls(Query::default(), paginated_with_total, &ctx.db)
        .await?;
    log::debug!(
        "Total packages after SBOM deletion: {:?}",
        packages_before.total
    );
    assert_eq!(
        packages_after.total,
        Some(2083),
        "Should have packages after deletion"
    );

    // The conservative SBOM deletion approach preserves packages if:
    // 1. They are referenced by another SBOM, OR
    // 2. Their base_purl is referenced in purl_status (advisory reference)
    //
    // Since we have TWO overlapping quarkus SBOMs and an advisory that references
    // many of the same packages, the SBOM deletion should only delete a small number of packages:
    // - Packages unique to the deleted SBOM (not in the other SBOM)
    // - AND not referenced by the advisory
    //
    // We verify that MOST packages are preserved (conservative approach).
    let packages_deleted = packages_before.total.expect("total requested")
        - packages_after.total.expect("total requested");
    log::debug!("Qualified PURLs deleted: {}", packages_deleted);

    assert_eq!(packages_deleted, 4, "Should have deleted 4 packages");

    // Delete the other SBOM
    let sbom_uuid = results[2].id.parse().expect("SBOM should have a UUID");
    let tx = ctx.db.begin().await?;
    assert!(
        service.delete_sbom(sbom_uuid, &tx).await?,
        "SBOM should be deleted"
    );
    tx.commit().await?;

    // Count all packages after deletion
    let packages_after = purl_service
        .purls(Query::default(), paginated_with_total, &ctx.db)
        .await?;
    log::debug!(
        "Total packages after second SBOM deletion: {:?}",
        packages_before.total
    );
    assert_eq!(
        packages_after.total,
        Some(2082),
        "Should have packages after second deletion"
    );

    // Delete the UBI SBOM, unrelated with other SBOMs and the advisory
    let ubi_sbom_uuid = results[3].id.parse().expect("SBOM should have a UUID");
    let tx = ctx.db.begin().await?;
    assert!(
        service.delete_sbom(ubi_sbom_uuid, &tx).await?,
        "SBOM should be deleted"
    );
    tx.commit().await?;

    // Count all packages after deletion
    let packages_after = purl_service
        .purls(Query::default(), paginated_with_total, &ctx.db)
        .await?;
    log::debug!(
        "Total packages after third SBOM deletion: {:?}",
        packages_before.total
    );
    assert_eq!(
        packages_after.total,
        Some(1472),
        "Should have packages after second deletion"
    );

    Ok(())
}

/// RED-GREEN-REFACTOR: Test SBOM package licenses with refactored COALESCE
/// Verifies: join_licenses() uses Func::coalesce() for both SPDX and CycloneDX
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_sbom_package_licenses_coalesce(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    // RED: No packages before ingestion
    // GREEN: Ingest SPDX (uses expanded_license) and CycloneDX (uses raw license.text)
    let spdx_result = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;
    let cyclonedx_result = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;

    let spdx_id = Uuid::parse_str(&spdx_result.id)?;
    let cyclonedx_id = Uuid::parse_str(&cyclonedx_result.id)?;

    let spdx_packages = service
        .fetch_sbom_packages(
            spdx_id,
            Query::default(),
            Paginated {
                offset: 0,
                limit: 100,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    let cyclonedx_packages = service
        .fetch_sbom_packages(
            cyclonedx_id,
            Query::default(),
            Paginated {
                offset: 0,
                limit: 100,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    // REFACTOR: Verify SPDX licenses expanded via COALESCE (no LicenseRef-)
    assert!(
        !spdx_packages.items.is_empty(),
        "SPDX SBOM should have packages"
    );

    for package in &spdx_packages.items {
        for license in &package.licenses {
            assert!(
                !license.license_name.contains("LicenseRef-"),
                "SPDX licenses should be expanded via COALESCE: {}",
                license.license_name
            );
        }
    }

    // Verify CycloneDX licenses exist via COALESCE fallback to license.text
    assert!(
        !cyclonedx_packages.items.is_empty(),
        "CycloneDX SBOM should have packages"
    );

    let has_licenses = cyclonedx_packages
        .items
        .iter()
        .any(|p| !p.licenses.is_empty());
    assert!(
        has_licenses,
        "CycloneDX packages should have licenses via COALESCE fallback"
    );

    Ok(())
}

/// RED-GREEN-REFACTOR: Test package license filtering with COALESCE
/// Verifies: License filtering works on both expanded and raw licenses via COALESCE
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_sbom_package_license_filtering_with_coalesce(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    // RED: No packages before ingestion
    // GREEN: Ingest SPDX with Apache licenses
    let result = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;
    let sbom_id = Uuid::parse_str(&result.id)?;

    // Filter by license (should work via COALESCE on expanded_text OR text)
    let apache_packages = service
        .fetch_sbom_packages(
            sbom_id,
            q("license~Apache"),
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
        apache_packages.total > Some(0),
        "Expected at least one package to match Apache filter"
    );
    let has_apache = apache_packages.items.iter().any(|p| {
        p.licenses
            .iter()
            .any(|l| l.license_name.to_lowercase().contains("apache"))
    });
    assert!(
        has_apache,
        "Filtered packages should contain Apache licenses"
    );

    Ok(())
}

/// RED-GREEN-REFACTOR: Test refactored IS NOT NULL filter
/// Verifies: Expr::col().is_not_null() works correctly in license JSON aggregation
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_sbom_package_license_not_null_filter(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    // RED: No packages before ingestion
    // GREEN: Ingest SBOM with licenses
    let result = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;
    let sbom_id = Uuid::parse_str(&result.id)?;

    let packages = service
        .fetch_sbom_packages(
            sbom_id,
            Query::default(),
            Paginated {
                offset: 0,
                limit: 1000,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    // REFACTOR: Verify IS NOT NULL filter works (refactored to Expr::col().is_not_null())
    for package in &packages.items {
        // If a package has licenses, none should be empty (due to IS NOT NULL filter)
        for license in &package.licenses {
            assert!(
                !license.license_name.is_empty(),
                "License should not be empty due to IS NOT NULL filter in join_licenses()"
            );
        }
    }

    Ok(())
}
