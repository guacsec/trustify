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
    db::query::{Query, q},
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

    let service = SbomService::new(ctx.db.clone());

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

    let service = SbomService::new(ctx.db.clone());

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

    let service = SbomService::new(ctx.db.clone());

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

    let service = SbomService::new(ctx.db.clone());

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
    let service = SbomService::new(ctx.db.clone());

    // Ingest SBOMs with license information
    ctx.ingest_document("spdx/mtv-2.6.json").await?;
    ctx.ingest_document("cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-02-24/quay-builder-qemu-rhcos-rhel-8-amd64.json").await?;

    // Test 1: Filter by specific license found in SPDX documents
    let results = service
        .fetch_sboms(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"),
            Paginated::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("License filter results: {results:#?}");
    // Both SBOMs contain packages with this license combination
    assert_eq!(results.total, 2);
    assert_eq!(results.items.len(), 2);

    // Test 2: Filter by partial license match
    let results = service
        .fetch_sboms(
            q("license~GPLv3+ with exceptions"),
            Paginated::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Partial license filter results: {results:#?}");
    // Both SBOMs contain packages with 'GPLv3+ with exceptions' license
    assert_eq!(results.total, 2);
    assert_eq!(results.items.len(), 2);

    // Test 3: Filter by license found in single SBOMs
    let results = service
        .fetch_sboms(
            q("license~OFL"),
            Paginated::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("OFL license filter results: {results:#?}");
    // Only SPDX SBOMs contain packages with OFL license
    assert_eq!(results.total, 1);
    assert_eq!(results.items[0].head.name, "MTV-2.6");

    // Test 3b: Filter by license found in single SBOMs
    let results = service
        .fetch_sboms(
            q("license=Apache 2.0"),
            Paginated::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Apache 2.0 license filter results: {results:#?}");
    // Only CycloneDX SBOM has Apache 2.0
    assert_eq!(results.total, 1);
    assert_eq!(
        results.items[0].head.name,
        "quay/quay-builder-qemu-rhcos-rhel8"
    );

    // Test 4: Test OR operation for multiple licenses
    let results = service
        .fetch_sboms(
            q("license=OFL|Apache 2.0"),
            Paginated::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Multiple license OR filter results: {results:#?}");
    // Both SBOMs contain packages with these licenses
    assert_eq!(results.total, 2);
    assert_eq!(results.items.len(), 2);

    // Test 5: Negative test - license that doesn't exist
    let results = service
        .fetch_sboms(
            q("license=NONEXISTENT_LICENSE"),
            Paginated::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Nonexistent license filter results: {results:#?}");
    // Should return no SBOMs
    assert_eq!(results.total, 0);
    assert!(results.items.is_empty());

    // Test 6: Empty license query
    let results = service
        .fetch_sboms(
            q("license="),
            Paginated::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Empty license query results: {results:#?}");
    // Should return no SBOMs or handle gracefully
    assert_eq!(results.total, 0);
    assert!(results.items.is_empty());

    // Test 7: Combine license filter with other filters (should work together)
    let results = service
        .fetch_sboms(
            q("license~Apache&name~quay"),
            Paginated::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Combined license + name filter results: {results:#?}");
    // Should find SBOMs that have both Apache license and name containing "quay"
    // CycloneDX SBOM has Apache license and "quay" in name
    assert_eq!(results.total, 1);
    assert_eq!(
        results.items[0].head.name,
        "quay/quay-builder-qemu-rhcos-rhel8"
    );

    // Test 8: Pagination with license filtering
    let results = service
        .fetch_sboms(
            q("license~GPL").sort("name:desc"),
            Paginated {
                offset: 0,
                limit: 1,
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
    assert_eq!(results.total, 2);

    // Test 8b: Pagination with license filtering and offset > 0
    let results_offset = service
        .fetch_sboms(
            q("license~GPL").sort("name:desc"),
            Paginated {
                offset: 1,
                limit: 1,
            },
            Default::default(),
            &ctx.db,
        )
        .await?;
    log::debug!("Paginated license filter results with offset: {results_offset:#?}");
    // Should return the second item and total should still be 2
    assert_eq!(results_offset.items.len(), 1);
    assert_eq!(results_offset.items[0].head.name, "MTV-2.6");
    assert_eq!(results_offset.total, 2);

    // Test 9: Verify that SBOMs without license filters still work
    let all_results = service
        .fetch_sboms(
            Query::default(),
            Paginated::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("All SBOMs results: {all_results:#?}");
    // Should return all SBOMs
    assert_eq!(all_results.total, 2); // We ingested exactly 2 SBOMs

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn fetch_sbom_packages_filter_by_license(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone());

    // Ingest an SBOM with license information
    let sbom_id = Uuid::parse_str(&ctx.ingest_document("spdx/mtv-2.6.json").await?.id).unwrap();

    // Test 1: No license filter - should return all packages
    let all_packages = service
        .fetch_sbom_packages(sbom_id, Query::default(), Paginated::default(), &ctx.db)
        .await?;

    log::debug!("All packages count: {}", all_packages.total);
    assert_eq!(all_packages.total, 5388, "Should have packages in the SBOM");

    // Test 2: Filter by specific license that exists
    let license_filtered = service
        .fetch_sbom_packages(
            sbom_id,
            q("license=GPLv2 AND GPLv2+ AND CC-BY"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("License filtered packages: {license_filtered:#?}");
    // Should find packages with this specific license
    // This validates that the license filtering is applied correctly
    assert_eq!(license_filtered.total, 14);

    // Test 3: Filter by partial license match
    let partial_license_filtered = service
        .fetch_sbom_packages(sbom_id, q("license~GPL"), Paginated::default(), &ctx.db)
        .await?;

    log::debug!("Partial license filtered packages: {partial_license_filtered:#?}");
    // Should find packages with licenses containing "GPL"
    assert_eq!(partial_license_filtered.total, 448);

    // Test 4: Filter by non-existent license
    let no_match = service
        .fetch_sbom_packages(
            sbom_id,
            q("license=NONEXISTENT_LICENSE"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("No match packages: {no_match:#?}");
    assert_eq!(
        no_match.total, 0,
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
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Combined filter packages: {combined_filter:#?}");
    // Should apply both license and name filters
    assert_eq!(combined_filter.total, 11);

    // Test 6: Pagination with license filtering
    if partial_license_filtered.total > 1 {
        let paginated = service
            .fetch_sbom_packages(
                sbom_id,
                q("license~GPL"),
                Paginated {
                    offset: 0,
                    limit: 1,
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
    let purl_service = PurlService::new();
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
    let sbom_service = SbomService::new(ctx.db.clone());
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

    let purl_service = PurlService::new();

    // Count all PURLs before deletion
    let packages_before = purl_service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;
    log::debug!(
        "Total packages before SBOM deletion: {}",
        packages_before.total
    );
    assert_eq!(
        packages_before.total, 2087,
        "Should have packages after ingestion"
    );

    // Delete one of the SBOMs
    let service = SbomService::new(ctx.db.clone());
    let sbom_uuid = results[1].id.parse().expect("SBOM should have a UUID");
    let tx = ctx.db.begin().await?;
    assert!(
        service.delete_sbom(sbom_uuid, &tx).await?,
        "SBOM should be deleted"
    );
    tx.commit().await?;

    // Count all packages after deletion
    let packages_after = purl_service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;
    log::debug!(
        "Total packages after SBOM deletion: {}",
        packages_before.total
    );
    assert_eq!(
        packages_after.total, 2083,
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
    let packages_deleted = packages_before.total - packages_after.total;
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
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;
    log::debug!(
        "Total packages after second SBOM deletion: {}",
        packages_before.total
    );
    assert_eq!(
        packages_after.total, 2082,
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
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;
    log::debug!(
        "Total packages after third SBOM deletion: {}",
        packages_before.total
    );
    assert_eq!(
        packages_after.total, 1472,
        "Should have packages after second deletion"
    );

    Ok(())
}
