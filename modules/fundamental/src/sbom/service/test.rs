use crate::{sbom::model::SbomExternalPackageReference, sbom::service::SbomService};
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
        .fetch_sbom_details(id_3_2_12, vec![], &ctx.db)
        .await?;

    assert!(details.is_some());

    let details = details.unwrap();

    log::debug!("{details:#?}");

    let details = service
        .fetch_sbom_details(Id::Uuid(details.summary.head.id), vec![], &ctx.db)
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

    let id_3_2_12 = results[3].id.clone();

    let mut map = HashMap::new();
    map.insert("label_1".to_string(), "First Label".to_string());
    map.insert("label_2".to_string(), "Second Label".to_string());
    let new_labels = Labels(map);
    service
        .set_labels(id_3_2_12.clone(), new_labels, &ctx.db)
        .await?;

    let details = service
        .fetch_sbom_details(id_3_2_12.clone(), vec![], &ctx.db)
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

    let id_3_2_12 = results[3].id.clone();

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
        .fetch_sbom_details(id_3_2_12.clone(), vec![], &ctx.db)
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
            (),
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
            (),
            &ctx.db,
        )
        .await?;

    log::debug!("Partial license filter results: {results:#?}");
    // Both SBOMs contain packages with 'GPLv3+ with exceptions' license
    assert_eq!(results.total, 2);
    assert_eq!(results.items.len(), 2);

    // Test 3: Filter by license found in single SBOMs
    let results = service
        .fetch_sboms(q("license~OFL"), Paginated::default(), (), &ctx.db)
        .await?;

    log::debug!("OFL license filter results: {results:#?}");
    // Only SPDX SBOMs contain packages with OFL license
    assert_eq!(results.total, 1);
    assert_eq!(results.items[0].head.name, "MTV-2.6");

    // Test 3b: Filter by license found in single SBOMs
    let results = service
        .fetch_sboms(q("license=Apache 2.0"), Paginated::default(), (), &ctx.db)
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
            (),
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
            (),
            &ctx.db,
        )
        .await?;

    log::debug!("Nonexistent license filter results: {results:#?}");
    // Should return no SBOMs
    assert_eq!(results.total, 0);
    assert!(results.items.is_empty());

    // Test 6: Empty license query
    let results = service
        .fetch_sboms(q("license="), Paginated::default(), (), &ctx.db)
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
            (),
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
            (),
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
            (),
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
        .fetch_sboms(Query::default(), Paginated::default(), (), &ctx.db)
        .await?;

    log::debug!("All SBOMs results: {all_results:#?}");
    // Should return all SBOMs
    assert_eq!(all_results.total, 2); // We ingested exactly 2 SBOMs

    Ok(())
}
