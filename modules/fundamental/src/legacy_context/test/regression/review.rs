//! Regressions for the legacy applicability PR review, using only synthetic data.
use super::*;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set};
use trustify_entity::{
    advisory_vulnerability_product_identifier::ProductIdentifierType,
    assertion_context_identifier::ContextIdentifierKind, cpe, product, product_status,
    product_version, product_version_range, purl_status, sbom as sbom_entity, sbom_node_checksum,
    sbom_node_product_identifier, status, version_range, version_scheme::VersionScheme,
};
use trustify_module_ingestor::graph::advisory::context::{AssertionContext, ContextCreator};

async fn seed(ctx: &TrustifyContext) -> anyhow::Result<purl_status::Model> {
    assertions(ctx).await?;
    // Keep one stated fixed assertion; the effective views supply its affected range.
    ctx.db
        .execute_unprepared(
            r#"
        DELETE FROM cpe_status;
        DELETE FROM purl_status WHERE vulnerability_id <> 'CVE-2026-111497'
            OR context_cpe_id NOT IN (SELECT id FROM cpe WHERE version = '10.2');
    "#,
        )
        .await?;
    Ok(purl_status::Entity::find().one(&ctx.db).await?.unwrap())
}

async fn range(ctx: &TrustifyContext, version: &str) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    version_range::ActiveModel {
        id: Set(id),
        version_scheme_id: Set(VersionScheme::Rpm),
        low_version: Set(Some(version.into())),
        low_inclusive: Set(Some(true)),
        high_version: Set(Some(version.into())),
        high_inclusive: Set(Some(true)),
    }
    .insert(&ctx.db)
    .await?;
    Ok(id)
}

async fn fix(
    ctx: &TrustifyContext,
    source: &purl_status::Model,
    version: &str,
    base: Uuid,
    cpe: Option<Uuid>,
    assertion: Option<Uuid>,
) -> anyhow::Result<()> {
    // Copy the synthetic assertion's advisory metadata, varying only its scope/package/range.
    let mut row = source.clone().into_active_model();
    row.id = Set(Uuid::new_v4());
    row.base_purl_id = Set(base);
    row.qualified_purl_id = Set(None);
    row.version_range_id = Set(range(ctx, version).await?);
    row.context_cpe_id = Set(cpe);
    row.assertion_context_id = Set(assertion);
    row.insert(&ctx.db).await?;
    Ok(())
}

async fn image(
    ctx: &TrustifyContext,
    packages: &[String],
    sku: Option<&str>,
) -> anyhow::Result<Uuid> {
    let mut components = vec![];
    for (i, package) in packages.iter().enumerate() {
        let parsed: Purl = package.parse()?;
        components.push(json!({"type": "library", "bom-ref": format!("package-{i}"),
            "name": parsed.name, "version": parsed.version, "purl": package}));
    }
    let id: Uuid = ctx.ingest_json(json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": format!("urn:uuid:{}", Uuid::new_v4()),
        "metadata": {"component": {"type": "container", "bom-ref": "root", "name": "review-image"}},
        "components": components,
    })).await?.id.parse()?;
    if let Some(sku) = sku {
        let root = sbom_entity::Entity::find_by_id(id)
            .one(&ctx.db)
            .await?
            .unwrap();
        sbom_node_product_identifier::ActiveModel {
            sbom_id: Set(id),
            node_id: Set(root.node_id),
            identifier_type: Set(ProductIdentifierType::Sku),
            value: Set(sku.into()),
        }
        .insert(&ctx.db)
        .await?;
    }
    Ok(id)
}

async fn sku_context(ctx: &TrustifyContext, sku: &str) -> anyhow::Result<Uuid> {
    let mut context = AssertionContext {
        name: sku.into(),
        ..Default::default()
    };
    context.add(ContextIdentifierKind::Sku, sku);
    let mut creator = ContextCreator::new();
    let id = creator.add(context);
    creator.create(&ctx.db).await?;
    Ok(id)
}

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn fixes_from_every_package_stay_in_their_context(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let source = seed(ctx).await?;
    let major = cpe::Entity::find()
        .filter(cpe::Column::Product.eq("enterprise_linux"))
        .filter(cpe::Column::Version.eq("10"))
        .filter(cpe::Column::Edition.eq("*"))
        .one(&ctx.db)
        .await?
        .unwrap();
    let other_purl: Purl = purl("other-package", "1.0-1.el10", "rhel-10.2").parse()?;
    ctx.graph
        .ingest_qualified_package(&other_purl, &ctx.db)
        .await?;
    let other_base = other_purl.uuids().0;
    fix(
        ctx,
        &source,
        "1.1.0-8.el10_2.2",
        source.base_purl_id,
        Some(major.id),
        None,
    )
    .await?;
    fix(
        ctx,
        &source,
        "2.0-1.el10",
        other_base,
        source.context_cpe_id,
        source.assertion_context_id,
    )
    .await?;

    let service = SbomService::new(PaginationCache::for_test());
    let mut packages = vec![
        purl("libbrotli", "1.1.0-8.el10_2", "rhel-10.2"),
        other_purl.to_string(),
    ];
    for _ in 0..2 {
        let id = image(ctx, &packages, None).await?;
        let details = service
            .fetch_sbom_details(Id::Uuid(id), vec!["affected".into()], &ctx.db)
            .await?
            .unwrap();
        let statuses: Vec<_> = details.advisories.iter().flat_map(|a| &a.status).collect();
        assert_eq!(statuses.len(), 2, "{details:#?}");
        let multiple_packages = statuses.iter().find(|s| s.packages.len() == 2).unwrap();
        assert_eq!(multiple_packages.fixed_versions, [FIX, "2.0-1.el10"]);
        let other_context = statuses.iter().find(|s| s.packages.len() == 1).unwrap();
        assert_eq!(other_context.fixed_versions, ["1.1.0-8.el10_2.2"]);
        assert_ne!(multiple_packages.context, other_context.context);
        packages.reverse();
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn assertion_only_fixes_are_not_global(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let source = seed(ctx).await?;
    purl_status::Entity::delete_many().exec(&ctx.db).await?;
    let a = sku_context(ctx, "image-a").await?;
    let b = sku_context(ctx, "image-b").await?;
    let unproven = sku_context(ctx, "other-product").await?;
    for (assertion, version) in [
        (Some(a), FIX),
        (Some(b), "1.1.0-8.el10_2.2"),
        (Some(unproven), "1.1.0-8.el10_2.4"),
        (None, "1.1.0-8.el10_2.3"),
    ] {
        fix(ctx, &source, version, source.base_purl_id, None, assertion).await?;
    }
    let package: Purl = purl("libbrotli", "1.1.0-8.el10_2", "rhel-10.2").parse()?;
    ctx.graph
        .ingest_qualified_package(&package, &ctx.db)
        .await?;
    let purls = PurlService::new(PaginationCache::for_test());
    let standalone = purls
        .purl_by_purl(&package, Default::default(), &ctx.db)
        .await?
        .unwrap();
    let statuses: Vec<_> = standalone
        .advisories
        .iter()
        .flat_map(|a| &a.status)
        .collect();
    assert_eq!(statuses.len(), 1, "{standalone:#?}");
    assert_eq!(statuses[0].fixed_versions, ["1.1.0-8.el10_2.3"]);

    let service = SbomService::new(PaginationCache::for_test());
    let mut ids = vec![];
    for (sku, scoped_fix) in [
        ("image-a", Some(FIX)),
        ("image-b", Some("1.1.0-8.el10_2.2")),
        ("image-c", None),
    ] {
        let id = image(ctx, &[package.to_string()], Some(sku)).await?;
        ids.push(id);
        let details = service
            .fetch_sbom_details(Id::Uuid(id), vec!["affected".into()], &ctx.db)
            .await?
            .unwrap();
        let actual: BTreeSet<_> = details
            .advisories
            .iter()
            .flat_map(|a| &a.status)
            .map(|s| s.fixed_versions.clone())
            .collect();
        let mut expected = BTreeSet::from([vec!["1.1.0-8.el10_2.3".to_string()]]);
        if let Some(version) = scoped_fix {
            expected.insert(vec![version.into(), "1.1.0-8.el10_2.3".into()]);
        }
        assert_eq!(actual, expected, "{sku}: {details:#?}");
    }
    // Remove the global assertion: the unproven image must now have no count or backlink.
    purl_status::Entity::delete_many()
        .filter(purl_status::Column::AssertionContextId.is_null())
        .exec(&ctx.db)
        .await?;
    let counts = service
        .batch_advisory_severity_counts(&ids, &ctx.db)
        .await?;
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(
            counts
                .get(id)
                .map(|v| v.values().sum::<u64>())
                .unwrap_or_default(),
            u64::from(i < 2)
        );
    }
    let vulnerabilities = VulnerabilityService::new(PaginationCache::for_test());
    let details = vulnerabilities
        .fetch_vulnerability(BROTLI, Default::default(), false, &ctx.db)
        .await?
        .unwrap();
    let linked: BTreeSet<_> = details
        .advisories
        .iter()
        .flat_map(|a| &a.sboms)
        .map(|s| s.head.id)
        .collect();
    assert_eq!(linked, ids[..2].iter().copied().collect());
    let details = purls
        .purl_by_purl(&package, Default::default(), &ctx.db)
        .await?
        .unwrap();
    let fixes: BTreeSet<_> = details
        .advisories
        .iter()
        .flat_map(|a| &a.status)
        .flat_map(|s| &s.fixed_versions)
        .map(String::as_str)
        .collect();
    assert_eq!(fixes, BTreeSet::from([FIX, "1.1.0-8.el10_2.2"]));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn assertion_cpe_can_prove_a_standalone_rpm(ctx: &TrustifyContext) -> anyhow::Result<()> {
    seed(ctx).await?;
    ctx.db
        .execute_unprepared("UPDATE purl_status SET context_cpe_id = NULL")
        .await?;
    let service = PurlService::new(PaginationCache::for_test());
    for (distro, expected) in [("rhel-10.2", true), ("rhel-9", false)] {
        let package: Purl = purl("libbrotli", "1.1.0-8.el10_2", distro).parse()?;
        ctx.graph
            .ingest_qualified_package(&package, &ctx.db)
            .await?;
        let details = service
            .purl_by_purl(&package, Default::default(), &ctx.db)
            .await?
            .unwrap();
        assert_eq!(!details.advisories.is_empty(), expected, "{details:#?}");
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn assertion_identifiers_are_local_and_use_csaf_globs(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let source = seed(ctx).await?;
    let assertion = sku_context(ctx, "image_%?*").await?;
    let mut row = source.into_active_model();
    row.context_cpe_id = Set(None);
    row.assertion_context_id = Set(Some(assertion));
    row.update(&ctx.db).await?;
    let package = purl("libbrotli", "1.1.0-8.el10_2", "rhel-10.2");
    let service = SbomService::new(PaginationCache::for_test());
    for (sku, expected) in [
        (Some("image_%ab"), true),
        (Some("imageXXab"), false),
        (None, false),
    ] {
        let id = image(
            ctx,
            &[package.clone(), purl("sibling", "1-1.el10", "rhel-10.2")],
            sku,
        )
        .await?;
        // A matching identifier on an unrelated sibling is not package/root evidence.
        sbom_node_product_identifier::ActiveModel {
            sbom_id: Set(id),
            node_id: Set("package-1".into()),
            identifier_type: Set(ProductIdentifierType::Sku),
            value: Set("image_%ab".into()),
        }
        .insert(&ctx.db)
        .await?;
        let details = service
            .fetch_sbom_details(Id::Uuid(id), vec!["affected".into()], &ctx.db)
            .await?
            .unwrap();
        assert_eq!(!details.advisories.is_empty(), expected, "{details:#?}");
    }

    let mut context = AssertionContext {
        name: "digest-scoped image".into(),
        ..Default::default()
    };
    context.add(ContextIdentifierKind::Digest, "sha256:abcd");
    let mut creator = ContextCreator::new();
    let digest_context = creator.add(context);
    creator.create(&ctx.db).await?;
    ctx.db
        .execute_unprepared(&format!(
            "UPDATE purl_status SET assertion_context_id = '{digest_context}'"
        ))
        .await?;
    for (digest, expected) in [("ABCD", true), ("ABCE", false)] {
        let id = image(ctx, std::slice::from_ref(&package), None).await?;
        let root = sbom_entity::Entity::find_by_id(id)
            .one(&ctx.db)
            .await?
            .unwrap();
        sbom_node_checksum::ActiveModel {
            sbom_id: Set(id),
            node_id: Set(root.node_id),
            r#type: Set("SHA-256".into()),
            value: Set(digest.into()),
        }
        .insert(&ctx.db)
        .await?;
        let details = service
            .fetch_sbom_details(Id::Uuid(id), vec!["affected".into()], &ctx.db)
            .await?
            .unwrap();
        assert_eq!(!details.advisories.is_empty(), expected, "{details:#?}");
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn product_backlinks_keep_package_and_product_applicability(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let source = seed(ctx).await?;
    purl_status::Entity::delete_many().exec(&ctx.db).await?;
    let product_id = Uuid::new_v4();
    product::ActiveModel {
        id: Set(product_id),
        name: Set("Synthetic RHEL".into()),
        vendor_id: Set(None),
        cpe_key: Set(Some("enterprise_linux".into())),
    }
    .insert(&ctx.db)
    .await?;
    let range_id = Uuid::new_v4();
    product_version_range::ActiveModel {
        id: Set(range_id),
        product_id: Set(product_id),
        version_range_id: Set(range(ctx, "10.2").await?),
        cpe_key: Set(Some("enterprise_linux".into())),
    }
    .insert(&ctx.db)
    .await?;
    let affected = status::Entity::find()
        .filter(status::Column::Slug.eq("affected"))
        .one(&ctx.db)
        .await?
        .unwrap();
    product_status::ActiveModel {
        id: Set(Uuid::new_v4()),
        advisory_id: Set(source.advisory_id),
        vulnerability_id: Set(BROTLI.into()),
        status_id: Set(affected.id),
        package: Set(Some("libbrotli".into())),
        product_version_range_id: Set(range_id),
        context_cpe_id: Set(source.context_cpe_id),
        csaf_product_ids: Set(None),
    }
    .insert(&ctx.db)
    .await?;
    let mut ids = vec![];
    for (distro, rpm, product_version) in [
        ("rhel-10.2", "1.1.0-8.el10_2", "10.2"),
        ("rhel-9", "1.1.0-8.el9", "10.2"),
        ("rhel-10.2", "1.1.0-8.el10_2", "9.0"),
    ] {
        let id = image(ctx, &[purl("libbrotli", rpm, distro)], None).await?;
        product_version::ActiveModel {
            id: Set(Uuid::new_v4()),
            product_id: Set(product_id),
            sbom_id: Set(Some(id)),
            version: Set(product_version.into()),
        }
        .insert(&ctx.db)
        .await?;
        ids.push(id);
    }
    let service = SbomService::new(PaginationCache::for_test());
    for (i, id) in ids[..2].iter().enumerate() {
        let details = service
            .fetch_sbom_details(Id::Uuid(*id), vec!["affected".into()], &ctx.db)
            .await?
            .unwrap();
        assert_eq!(
            details.advisories.len(),
            usize::from(i == 0),
            "{details:#?}"
        );
    }
    let counts = service
        .batch_advisory_severity_counts(&ids[..2], &ctx.db)
        .await?;
    assert_eq!(counts[&ids[0]].values().sum::<u64>(), 1);
    assert_eq!(
        counts
            .get(&ids[1])
            .map(|v| v.values().sum::<u64>())
            .unwrap_or_default(),
        0
    );
    let service = VulnerabilityService::new(PaginationCache::for_test());
    let details = service
        .fetch_vulnerability(BROTLI, Default::default(), false, &ctx.db)
        .await?
        .unwrap();
    let linked: BTreeSet<_> = details
        .advisories
        .iter()
        .flat_map(|a| &a.sboms)
        .map(|s| s.head.id)
        .collect();
    assert_eq!(linked, BTreeSet::from([ids[0]]), "{details:#?}");
    Ok(())
}
