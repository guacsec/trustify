//! Regressions for the legacy applicability PR review, using only synthetic data.
use super::*;
use crate::purl::model::details::purl::StatusContext;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set};
use trustify_common::cpe::Cpe;
use trustify_entity::{
    advisory_vulnerability_product_identifier::ProductIdentifierType,
    assertion_context_identifier::ContextIdentifierKind, cpe, product, product_status,
    product_version, product_version_range, purl_status, sbom_node_checksum,
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
    let mut root = json!({"type": "device", "bom-ref": "root", "name": "review-image"});
    if let Some(sku) = sku {
        root["properties"] = json!([{"name": "cdx:device:sku", "value": sku}]);
    }
    image_with_root(ctx, packages, root).await
}

async fn image_with_root(
    ctx: &TrustifyContext,
    packages: &[String],
    root: Value,
) -> anyhow::Result<Uuid> {
    let mut components = vec![];
    for (i, package) in packages.iter().enumerate() {
        let parsed: Purl = package.parse()?;
        components.push(json!({"type": "library", "bom-ref": format!("package-{i}"),
            "name": parsed.name, "version": parsed.version, "purl": package}));
    }
    Ok(ctx
        .ingest_json(json!({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "serialNumber": format!("urn:uuid:{}", Uuid::new_v4()),
            "metadata": {"component": root},
            "components": components,
        }))
        .await?
        .id
        .parse()?)
}

async fn sku_context(ctx: &TrustifyContext, sku: &str) -> anyhow::Result<Uuid> {
    identifier_context(ctx, ContextIdentifierKind::Sku, sku).await
}

async fn identifier_context(
    ctx: &TrustifyContext,
    kind: ContextIdentifierKind,
    value: &str,
) -> anyhow::Result<Uuid> {
    let mut context = AssertionContext {
        name: value.into(),
        ..Default::default()
    };
    context.add(kind, value);
    let mut creator = ContextCreator::new();
    let id = creator.add(context);
    creator.create(&ctx.db).await?;
    Ok(id)
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
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
#[test_log::test(actix_web::test)]
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
#[test_log::test(actix_web::test)]
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
#[test_log::test(actix_web::test)]
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

    let digest_context = identifier_context(
        ctx,
        ContextIdentifierKind::Digest,
        &format!("sha256:{}", "abcd".repeat(16)),
    )
    .await?;
    ctx.db
        .execute_unprepared(&format!(
            "UPDATE purl_status SET assertion_context_id = '{digest_context}'"
        ))
        .await?;
    for (digest, expected) in [("ABCD", true), ("ABCE", false)] {
        let id = image_with_root(
            ctx,
            std::slice::from_ref(&package),
            json!({
                "type": "container", "bom-ref": "root", "name": "review-image",
                "hashes": [{"alg": "SHA-256", "content": digest.repeat(16)}],
            }),
        )
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
#[test_log::test(actix_web::test)]
async fn platform_purl_assertions_use_the_described_product(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let mut row = seed(ctx).await?.into_active_model();
    let assertion = identifier_context(
        ctx,
        ContextIdentifierKind::Purl,
        &"pkg:npm/%40example/platform".parse::<Purl>()?.to_string(),
    )
    .await?;
    row.context_cpe_id = Set(None);
    row.assertion_context_id = Set(Some(assertion));
    row.update(&ctx.db).await?;

    let package = purl("libbrotli", "1.1.0-8.el10_2", "rhel-10.2");
    let platform = "pkg:npm/%40example/platform@3.0.0";
    let service = SbomService::new(PaginationCache::for_test());
    let mut ids = vec![];
    // The same platform PURL on an unrelated sibling must not establish context.
    for (root_purl, expected) in [(platform, true), ("pkg:npm/other@3.0.0", false)] {
        let id = image_with_root(
            ctx,
            &[package.clone(), platform.to_string()],
            json!({
                "type": "application", "bom-ref": "root", "name": "platform", "version": "3.0.0",
                "purl": root_purl,
            }),
        )
        .await?;
        ids.push(id);
        let details = service
            .fetch_sbom_details(Id::Uuid(id), vec!["affected".into()], &ctx.db)
            .await?
            .unwrap();
        assert_eq!(!details.advisories.is_empty(), expected, "{details:#?}");
    }
    let counts = service
        .batch_advisory_severity_counts(&ids, &ctx.db)
        .await?;
    assert_eq!(counts[&ids[0]].values().sum::<u64>(), 1);
    assert!(!counts.contains_key(&ids[1]));
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
    assert_eq!(linked, BTreeSet::from([ids[0]]));
    let details = PurlService::new(PaginationCache::for_test())
        .purl_by_purl(&package.parse()?, Default::default(), &ctx.db)
        .await?
        .unwrap();
    assert!(!details.advisories.is_empty());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn repeated_purls_do_not_share_package_node_evidence(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let mut row = seed(ctx).await?.into_active_model();
    let digest = "abcd".repeat(16);
    let assertion = identifier_context(
        ctx,
        ContextIdentifierKind::Digest,
        &format!("sha256:{digest}"),
    )
    .await?;
    row.context_cpe_id = Set(None);
    row.assertion_context_id = Set(Some(assertion));
    row.update(&ctx.db).await?;

    let purl = purl("libbrotli", "1.1.0-8.el10_2", "rhel-10.2");
    let id = image(ctx, &[purl.clone(), purl], None).await?;
    sbom_node_checksum::ActiveModel {
        sbom_id: Set(id),
        node_id: Set("package-1".into()),
        r#type: Set("SHA-256".into()),
        value: Set(digest),
    }
    .insert(&ctx.db)
    .await?;

    let service = SbomService::new(PaginationCache::for_test());
    let details = service
        .fetch_sbom_details(Id::Uuid(id), vec!["affected".into()], &ctx.db)
        .await?
        .unwrap();
    let matches: Vec<_> = details
        .advisories
        .iter()
        .flat_map(|a| &a.status)
        .flat_map(|s| &s.packages)
        .map(|p| p.id.as_str())
        .collect();
    assert_eq!(matches, ["package-1"]);
    let counts = service
        .batch_advisory_severity_counts(&[id], &ctx.db)
        .await?;
    assert_eq!(counts[&id].values().sum::<u64>(), 1);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn rhel_repos_and_layered_products_use_distinct_evidence(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let source = seed(ctx).await?;
    purl_status::Entity::delete_many().exec(&ctx.db).await?;
    let baseos = "cpe:/o:redhat:enterprise_linux:9::baseos";
    let appstream = "cpe:/a:redhat:enterprise_linux:9::appstream";
    let eus = "cpe:/o:redhat:rhel_eus:9.2::appstream";
    let openshift = "cpe:/a:redhat:openshift:4.14::el9";
    let fastdatapath = "cpe:/o:redhat:enterprise_linux:9::fastdatapath";
    for scope in [baseos, appstream, eus, openshift, fastdatapath] {
        let scope = ctx
            .graph
            .ingest_cpe22(scope.parse::<Cpe>()?, &ctx.db)
            .await?;
        fix(
            ctx,
            &source,
            "1.1.0-2.el9",
            source.base_purl_id,
            Some(scope.cpe.id),
            None,
        )
        .await?;
    }

    let package = purl("libbrotli", "1.1.0-1.el9", "rhel-9");
    let service = SbomService::new(PaginationCache::for_test());
    let mut ids = vec![];
    for (root_cpe, extra_scope) in [
        (None, None),
        (Some("cpe:/a:example:private_image:1"), None),
        (Some(baseos), None),
        (Some(eus), Some("cpe:/o:redhat:rhel_eus:9.2:*:appstream:*")),
        (
            Some(openshift),
            Some("cpe:/a:redhat:openshift:4.14:*:el9:*"),
        ),
    ] {
        let mut root = json!({"type": "container", "bom-ref": "root", "name": "review-image"});
        if let Some(cpe) = root_cpe {
            root["cpe"] = cpe.into();
        }
        let id = image_with_root(ctx, std::slice::from_ref(&package), root).await?;
        ids.push(id);
        let details = service
            .fetch_sbom_details(Id::Uuid(id), vec!["affected".into()], &ctx.db)
            .await?
            .unwrap();
        let matches = details
            .advisories
            .iter()
            .flat_map(|a| &a.status)
            .map(|s| match &s.context {
                Some(StatusContext::Cpe(scope)) => scope.as_str(),
                other => panic!("expected CPE context, got {other:?}"),
            })
            .collect::<BTreeSet<_>>();
        // Compare the API's CPE strings directly: its wildcard language is
        // rendered as `*`, which the CPE URI parser does not accept.
        let expected = [
            "cpe:/o:redhat:enterprise_linux:9:*:baseos:*",
            "cpe:/a:redhat:enterprise_linux:9:*:appstream:*",
        ]
        .into_iter()
        .chain(extra_scope)
        .collect::<BTreeSet<_>>();
        assert_eq!(matches, expected, "root {root_cpe:?}: {details:#?}");
    }
    let counts = service
        .batch_advisory_severity_counts(&ids, &ctx.db)
        .await?;
    for id in &ids {
        assert_eq!(counts[id].values().sum::<u64>(), 1);
    }
    // Isolate the layered assertions to also verify the PURL-backed backlinks.
    ctx.db
        .execute_unprepared(
            "DELETE FROM purl_status WHERE context_cpe_id IN
             (SELECT id FROM cpe WHERE product = 'enterprise_linux')",
        )
        .await?;
    let details = PurlService::new(PaginationCache::for_test())
        .purl_by_purl(&package.parse()?, Default::default(), &ctx.db)
        .await?
        .unwrap();
    assert_eq!(
        details
            .advisories
            .iter()
            .flat_map(|a| &a.status)
            .filter(|s| s.status == "affected")
            .count(),
        2
    );
    let details = VulnerabilityService::new(PaginationCache::for_test())
        .fetch_vulnerability(BROTLI, Default::default(), false, &ctx.db)
        .await?
        .unwrap();
    let linked: BTreeSet<_> = details
        .advisories
        .iter()
        .flat_map(|a| &a.sboms)
        .map(|s| s.head.id)
        .collect();
    assert_eq!(linked, ids[3..].iter().copied().collect());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn product_backlinks_keep_package_and_product_applicability(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let source = seed(ctx).await?;
    purl_status::Entity::delete_many().exec(&ctx.db).await?;
    let mut expected = product_backlink_cases(
        ctx,
        source.advisory_id,
        "enterprise_linux",
        source.context_cpe_id.unwrap(),
        "10.2",
    )
    .await?;
    let openshift = ctx
        .graph
        .ingest_cpe22("cpe:/a:redhat:openshift:4.14::el9".parse::<Cpe>()?, &ctx.db)
        .await?;
    expected.extend(
        product_backlink_cases(
            ctx,
            source.advisory_id,
            "openshift",
            openshift.cpe.id,
            "4.14",
        )
        .await?,
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
    assert_eq!(linked, expected, "{details:#?}");
    Ok(())
}

async fn product_backlink_cases(
    ctx: &TrustifyContext,
    advisory_id: Uuid,
    product_key: &str,
    context_cpe_id: Uuid,
    expected_version: &str,
) -> anyhow::Result<BTreeSet<Uuid>> {
    let is_generic_rhel = product_key == "enterprise_linux";
    let name = if is_generic_rhel {
        "libbrotli"
    } else {
        "openshift-component"
    };
    let product_id = Uuid::new_v4();
    product::ActiveModel {
        id: Set(product_id),
        name: Set(format!("Synthetic {product_key}")),
        vendor_id: Set(None),
        cpe_key: Set(Some(product_key.into())),
    }
    .insert(&ctx.db)
    .await?;
    let range_id = Uuid::new_v4();
    product_version_range::ActiveModel {
        id: Set(range_id),
        product_id: Set(product_id),
        version_range_id: Set(range(ctx, expected_version).await?),
        cpe_key: Set(Some(product_key.into())),
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
        advisory_id: Set(advisory_id),
        vulnerability_id: Set(BROTLI.into()),
        status_id: Set(affected.id),
        package: Set(Some(name.into())),
        product_version_range_id: Set(range_id),
        context_cpe_id: Set(Some(context_cpe_id)),
        csaf_product_ids: Set(None),
    }
    .insert(&ctx.db)
    .await?;
    let mut ids = vec![];
    for (distro, rpm, product_version) in [
        ("rhel-10.2", "1.1.0-8.el10_2", expected_version),
        ("rhel-9", "1.1.0-8.el9", expected_version),
        ("rhel-10.2", "1.1.0-8.el10_2", "0.1"),
    ] {
        let id = image(ctx, &[purl(name, rpm, distro)], None).await?;
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
            usize::from(is_generic_rhel && i == 0),
            "{details:#?}"
        );
    }
    let counts = service
        .batch_advisory_severity_counts(&ids[..2], &ctx.db)
        .await?;
    assert_eq!(
        counts
            .get(&ids[0])
            .map(|v| v.values().sum::<u64>())
            .unwrap_or_default(),
        u64::from(is_generic_rhel)
    );
    assert_eq!(
        counts
            .get(&ids[1])
            .map(|v| v.values().sum::<u64>())
            .unwrap_or_default(),
        0
    );
    // Only the generic RHEL product additionally checks the RPM's RHEL major.
    Ok(ids[..if is_generic_rhel { 1 } else { 2 }]
        .iter()
        .copied()
        .collect())
}
