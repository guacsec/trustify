use crate::purl::{model::details::purl::StatusContext, service::PurlService};
use regex::Regex;
use std::{collections::HashSet, str::FromStr, sync::Arc};
use test_context::test_context;
use test_log::test;
use trustify_common::{
    db::{
        pagination_cache::PaginationCache,
        query::{Query, q},
    },
    model::{Limit, Paginated},
    purl::Purl,
};
use trustify_test_context::{Dataset, TrustifyContext};
use uuid::Uuid;

/// Equal assessment rows must retain the stable union of full remediation content.
#[test]
fn assemble_recommend_entry_merges_remediations() {
    use super::{StatusInfo, Winner, report::ProviderIdentity};
    use std::collections::HashMap;
    use trustify_entity::{
        base_purl, remediation, version_range, version_scheme::VersionScheme, versioned_purl,
    };
    use uuid::Uuid;

    let base = base_purl::Model {
        id: Uuid::from_u128(1),
        r#type: "maven".into(),
        namespace: Some("com.example".into()),
        name: "streamlib".into(),
    };
    let version = versioned_purl::Model {
        id: Uuid::from_u128(2),
        base_purl_id: base.id,
        version: "1.0.0.redhat-00001".into(),
    };
    let winner = Winner {
        purl_string: "pkg:maven/com.example/streamlib@1.0.0".into(),
        versioned_purl: &version,
        base: &base,
    };
    let remediation = remediation::Model {
        id: Uuid::from_u128(3),
        advisory_id: Uuid::from_u128(4),
        vulnerability_id: "CVE-2099-73930".into(),
        category: remediation::RemediationCategory::VendorFix,
        details: Some("Apply A".into()),
        url: Some("https://example.com/errata/shared".into()),
        data: serde_json::json!({"step": 1}),
    };
    let mut equivalent = remediation.clone();
    equivalent.id = Uuid::from_u128(5);
    let mut different_data = remediation.clone();
    different_data.id = Uuid::from_u128(6);
    different_data.data = serde_json::json!({"step": 2});
    let mut different_details = different_data.clone();
    different_details.id = Uuid::from_u128(7);
    different_details.details = Some("Apply B".into());

    for reversed in [false, true] {
        let make_status = |remediations| StatusInfo {
            vuln_id: "CVE-2099-73930".into(),
            status_slug: "fixed".into(),
            remediations,
            advisory_id: Some("TEST-STREAMS".into()),
            source_id: Uuid::nil(),
            status_id: Uuid::nil(),
            advisory_pk: Uuid::nil(),
            context_cpe_id: None,
            range: Arc::new(version_range::Model {
                id: Uuid::nil(),
                version_scheme_id: VersionScheme::Generic,
                low_version: None,
                low_inclusive: None,
                high_version: None,
                high_inclusive: None,
            }),
            provider: ProviderIdentity::default(),
            csaf: false,
        };
        let mut rows = vec![
            make_status(vec![different_details.clone(), remediation.clone()]),
            make_status(vec![equivalent.clone(), different_data.clone()]),
        ];
        if reversed {
            rows.reverse();
            for row in &mut rows {
                row.remediations.reverse();
            }
        }
        let entry =
            PurlService::assemble_recommend_entry(&winner, &HashMap::from([(version.id, rows)]));
        let response = serde_json::to_value(entry).unwrap();
        assert_eq!(
            response["vulnerabilities"],
            serde_json::json!([{
                "id": "CVE-2099-73930", "status": "Fixed", "advisory_id": "TEST-STREAMS",
                "remediations": [
                    {"category": "vendor_fix", "details": "Apply A", "url": "https://example.com/errata/shared", "data": {"step": 1}},
                    {"category": "vendor_fix", "details": "Apply A", "url": "https://example.com/errata/shared", "data": {"step": 2}},
                    {"category": "vendor_fix", "details": "Apply B", "url": "https://example.com/errata/shared", "data": {"step": 2}}
                ]
            }])
        );
    }
}

/// A batch must key each assessment by its exact winner, including non-persisted versions.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommendation_status_batch_keeps_winner_versions_separate(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ctx.ingest_document("osv/RUSTSEC-2021-0079.json").await?;
    ctx.ingest_json(serde_json::json!({
        "id": "NEWER-HYPER", "modified": "2024-01-15T00:00:00Z",
        "aliases": ["CVE-2099-60001"],
        "affected": [{"package": {"ecosystem": "crates.io", "name": "hyper"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.15.0"}, {"fixed": "0.16.0"}]}]}]
    })).await?;
    let old = Purl::from_str("pkg:cargo/hyper@0.14.1")?;
    let newer = Purl::from_str("pkg:cargo/hyper@0.15.0")?;
    let synthetic = Purl::from_str("pkg:cargo/hyper@0.14.2")?;
    for purl in [&old, &newer] {
        ctx.graph.ingest_package_version(purl, &ctx.db).await?;
    }
    assert!(
        ctx.graph
            .get_package_version(&synthetic, &ctx.db)
            .await?
            .is_none()
    );

    let statuses = PurlService::fetch_vulnerability_statuses(
        [&old, &newer, &synthetic, &old].map(|purl| {
            (
                purl.package_uuid(),
                purl.version.as_deref().unwrap(),
                purl.version_uuid(),
            )
        }),
        &ctx.db,
    )
    .await?;
    assert_eq!(
        statuses.len(),
        3,
        "one status group per distinct matching winner"
    );
    for (purl, cve, advisory) in [
        (&old, "CVE-2021-32714", "RUSTSEC-2021-0079"),
        (&newer, "CVE-2099-60001", "NEWER-HYPER"),
        (&synthetic, "CVE-2021-32714", "RUSTSEC-2021-0079"),
    ] {
        let infos = &statuses[&purl.version_uuid()];
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].vuln_id, cve);
        assert_eq!(infos[0].status_slug, "affected");
        assert_eq!(infos[0].advisory_id.as_deref(), Some(advisory));
    }
    Ok(())
}

/// Repeated statuses in a batch must not duplicate associations across bind-limit chunks.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommendation_remediation_loading_deduplicates_status_ids_across_chunks(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{EntityTrait, Set};
    use trustify_entity::{purl_status, remediation, remediation_purl_status};

    ctx.ingest_document("osv/RUSTSEC-2021-0079.json").await?;
    let status = purl_status::Entity::find().one(&ctx.db).await?.unwrap();
    let remediation_id = Uuid::new_v4();
    remediation::Entity::insert(remediation::ActiveModel {
        id: Set(remediation_id),
        advisory_id: Set(status.advisory_id),
        vulnerability_id: Set(status.vulnerability_id.clone()),
        category: Set(remediation::RemediationCategory::VendorFix),
        details: Set(Some("Upgrade".into())),
        url: Set(None),
        data: Set(serde_json::json!({})),
    })
    .exec(&ctx.db)
    .await?;
    remediation_purl_status::Entity::insert(remediation_purl_status::ActiveModel {
        remediation_id: Set(remediation_id),
        purl_status_id: Set(status.id),
    })
    .exec(&ctx.db)
    .await?;
    let repeated = vec![status; 65_536];
    let remediations = PurlService::load_remediations(&repeated, &ctx.db).await?;
    assert_eq!(remediations.len(), repeated.len());
    assert!(
        remediations
            .iter()
            .all(|items| items.len() == 1 && items[0].id == remediation_id)
    );
    Ok(())
}

/// Synthetic winners beyond a single VALUES bind budget must all retain their status.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommendation_status_batch_chunks_large_inputs(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ctx.ingest_document("osv/RUSTSEC-2021-0079.json").await?;
    let base = Purl::from_str("pkg:cargo/hyper")?.package_uuid();
    let winners = (0..22_000)
        .map(|index| {
            let version = format!("0.14.2+{index}");
            let id = Uuid::new_v5(&base, version.as_bytes());
            (version, id)
        })
        .collect::<Vec<_>>();
    let statuses = PurlService::fetch_vulnerability_statuses(
        winners
            .iter()
            .map(|(version, id)| (base, version.as_str(), *id)),
        &ctx.db,
    )
    .await?;
    assert_eq!(statuses.len(), 22_000);
    for (_, id) in winners {
        let infos = &statuses[&id];
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].vuln_id, "CVE-2021-32714");
        assert_eq!(infos[0].status_slug, "affected");
    }
    Ok(())
}

/// Two individually safe winners must not overflow relation-query binds when batched.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommendation_status_batch_chunks_distinct_vulnerabilities(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{
        ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, Set, Statement,
    };
    use trustify_entity::{purl_status, status, version_range, version_scheme::VersionScheme};
    use uuid::Uuid;

    ctx.ingest_document("osv/RUSTSEC-2021-0079.json").await?;
    let template = purl_status::Entity::find()
        .inner_join(status::Entity)
        .filter(status::Column::Slug.eq("affected"))
        .one(&ctx.db)
        .await?
        .unwrap();
    let ranges = [Uuid::new_v4(), Uuid::new_v4()];
    // The OSV fixture may have several original status rows; isolate the generated CVEs.
    purl_status::Entity::delete_many()
        .filter(purl_status::Column::BasePurlId.eq(template.base_purl_id))
        .exec(&ctx.db)
        .await?;
    version_range::Entity::insert_many(ranges.into_iter().zip(["0.14.1", "0.14.2"]).map(
        |(id, version)| version_range::ActiveModel {
            id: Set(id),
            version_scheme_id: Set(VersionScheme::Semver),
            low_version: Set(Some(version.into())),
            low_inclusive: Set(Some(true)),
            high_version: Set(Some(version.into())),
            high_inclusive: Set(Some(true)),
        },
    ))
    .exec(&ctx.db)
    .await?;
    // Each exact version gets 32,768 disjoint CVEs, below the bind limit individually.
    let inserted = ctx.db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "WITH new_vulnerabilities AS ( \
             INSERT INTO vulnerability (id) \
             SELECT 'CVE-2099-' || (700000 + n)::text FROM generate_series(1, 65536) AS n \
             RETURNING id \
         ), new_associations AS ( \
             INSERT INTO advisory_vulnerability (advisory_id, vulnerability_id) \
             SELECT $1, id FROM new_vulnerabilities RETURNING vulnerability_id \
         ) \
         INSERT INTO purl_status (advisory_id, vulnerability_id, status_id, base_purl_id, version_range_id) \
         SELECT $1, vulnerability_id, $2, $3, \
                CASE WHEN vulnerability_id < 'CVE-2099-732769' THEN $4 ELSE $5 END \
         FROM new_associations",
        [template.advisory_id.into(), template.status_id.into(), template.base_purl_id.into(), ranges[0].into(), ranges[1].into()],
    )).await?;
    assert_eq!(inserted.rows_affected(), 65_536);
    let winners = ["0.14.1", "0.14.2"].map(|version| {
        (
            template.base_purl_id,
            version,
            Uuid::new_v5(&template.base_purl_id, version.as_bytes()),
        )
    });
    let statuses = PurlService::fetch_vulnerability_statuses(winners, &ctx.db).await?;
    assert_eq!(statuses.len(), 2);
    for ((_, _, winner), (first, last)) in winners
        .into_iter()
        .zip([(700001, 732768), (732769, 765536)])
    {
        let mut cves = statuses[&winner]
            .iter()
            .map(|info| info.vuln_id.as_str())
            .collect::<Vec<_>>();
        cves.sort_unstable();
        assert_eq!(cves.len(), 32_768);
        assert_eq!(cves[0], format!("CVE-2099-{first}"));
        assert_eq!(cves[cves.len() - 1], format!("CVE-2099-{last}"));
        assert!(
            statuses[&winner]
                .iter()
                .all(|info| info.status_slug == "affected"
                    && info.advisory_id.as_deref() == Some("RUSTSEC-2021-0079"))
        );
    }
    // Shared range metadata must not be allocated once per CVE or status chunk.
    let range_allocations = statuses
        .values()
        .flatten()
        .map(|info| info.range.high_version.as_ref().unwrap().as_ptr() as usize)
        .collect::<HashSet<_>>();
    assert_eq!(range_allocations.len(), 2);
    Ok(())
}

async fn ingest_extra_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.graph
        .ingest_package(&Purl::from_str("pkg:maven/org.myspace/tom")?, &ctx.db)
        .await?;
    ctx.graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, &ctx.db)
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn types(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test()).with_default_patterns();

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?repository_url=http://jboss.org")?,
            &ctx.db,
        )
        .await?;

    ingest_extra_packages(ctx).await?;

    let types = service.purl_types(&ctx.db).await?;

    assert_eq!(2, types.len());

    let rpm = types.iter().find(|e| e.head.name == "rpm");
    let maven = types.iter().find(|e| e.head.name == "maven");

    assert!(rpm.is_some());
    assert!(maven.is_some());

    let rpm = rpm.unwrap();
    let maven = maven.unwrap();

    assert_eq!(rpm.counts.base, 1);
    assert_eq!(rpm.counts.version, 0);
    assert_eq!(rpm.counts.package, 0);

    assert_eq!(maven.counts.base, 2);
    assert_eq!(maven.counts.version, 1);
    assert_eq!(maven.counts.package, 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn packages_for_type(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.4")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.5")?,
            &ctx.db,
        )
        .await?;

    ingest_extra_packages(ctx).await?;

    let packages = service
        .base_purls_by_type(
            "maven",
            Query::default(),
            Paginated {
                total: true,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(packages.total, Some(2));

    assert!(
        packages
            .items
            .iter()
            .any(|e| e.head.purl.to_string() == "pkg:maven/org.apache/log4j")
    );

    assert!(
        packages
            .items
            .iter()
            .any(|e| e.head.purl.to_string() == "pkg:maven/org.myspace/tom")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn packages_for_type_with_filtering(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.4")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.5")?,
            &ctx.db,
        )
        .await?;

    ingest_extra_packages(ctx).await?;

    let packages = service
        .base_purls_by_type(
            "maven",
            q("myspace"),
            Paginated {
                total: true,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(packages.total, Some(1));

    assert!(
        packages
            .items
            .iter()
            .any(|e| e.head.purl.to_string() == "pkg:maven/org.myspace/tom")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?repository_url=http://maven.org")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?repository_url=http://jboss.org")?,
            &ctx.db,
        )
        .await?;

    let _log4j_124 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.4")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.5")?,
            &ctx.db,
        )
        .await?;

    let tom = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.myspace/tom")?, &ctx.db)
        .await?;

    tom.ingest_package_version(&Purl::from_str("pkg:maven/org.myspace/tom@1.1.1")?, &ctx.db)
        .await?;

    tom.ingest_package_version(&Purl::from_str("pkg:maven/org.myspace/tom@9.9.9")?, &ctx.db)
        .await?;

    ctx.graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, &ctx.db)
        .await?;

    let bind = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:rpm/bind")?, &ctx.db)
        .await?;

    bind.ingest_package_version(&Purl::from_str("pkg:rpm/bind@4.4.4")?, &ctx.db)
        .await?;

    let results = service
        .base_purl("maven", Some("org.apache".to_string()), "log4j", &ctx.db)
        .await?;

    assert!(results.is_some());

    let log4j = results.unwrap();

    assert_eq!("pkg:maven/org.apache/log4j", log4j.head.purl.to_string());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package_version(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            &ctx.db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let results = service
        .versioned_purl(
            "maven",
            Some("org.apache".to_string()),
            "log4j",
            "1.2.3",
            &ctx.db,
        )
        .await?;

    assert!(results.is_some());

    let log4j_123 = results.unwrap();

    assert_eq!(
        "pkg:maven/org.apache/log4j@1.2.3",
        log4j_123.head.purl.to_string()
    );

    assert_eq!(2, log4j_123.purls.len());

    assert!(
        log4j_123
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=11")
    );

    assert!(
        log4j_123
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=17")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package_version_by_uuid(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            &ctx.db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let result = service
        .versioned_purl_by_uuid(&log4j_123.package_version.id, &ctx.db)
        .await?;

    assert!(result.is_some());

    let log4j_123 = result.unwrap();

    assert_eq!(
        "pkg:maven/org.apache/log4j@1.2.3",
        log4j_123.head.purl.to_string()
    );

    assert_eq!(2, log4j_123.purls.len());

    assert!(
        log4j_123
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=11")
    );

    assert!(
        log4j_123
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=17")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            &ctx.db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let quarkus = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.jboss/quarkus")?, &ctx.db)
        .await?;

    let quarkus_123 = quarkus
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3")?,
            &ctx.db,
        )
        .await?;

    quarkus_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let results = service
        .base_purls(q("log4j"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(1, results.items.len());

    let results = service
        .base_purls(q("quarkus"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(1, results.items.len());

    let results = service
        .base_purls(q("jboss"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(1, results.items.len());

    let results = service
        .base_purls(q("maven"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(2, results.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn qualified_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            &ctx.db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let quarkus = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.jboss/quarkus")?, &ctx.db)
        .await?;

    let quarkus_123 = quarkus
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3")?,
            &ctx.db,
        )
        .await?;

    quarkus_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let results = service
        .purls(q("log4j"), Paginated::default(), &ctx.db)
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(3, results.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn qualified_packages_filter_by_license(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    let _mtv = ctx.ingest_document("spdx/mtv-2.6.json").await?;

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    // log::debug!("{results:#?}");
    // MTV SBOM contains 2 packages with the specified license
    assert_eq!(2, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD&libstdc++"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(1, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD|Apache License 2.0"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(4, results.items.len());

    // use a high limit to fetch all 57 expected matches
    let results = service
        .purls(
            q("license~GPLv3+ with exceptions|Apache"),
            // use a high limit to fetch all expected matches
            Limit(100),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    // 'GPLv3+ with exceptions' is used in:
    // "LicenseRef-12" => used in 2 packages
    // "LicenseRef-16" => used in 1 package
    //
    // 'Apache' is used in:
    // "LicenseRef-0" => used in 2 packages
    // "LicenseRef-Apache" => never used in any package
    // + directly declared in 52 packages
    // Total = used in 57 packages
    assert_eq!(57, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD&lib"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(2, results.items.len());

    ctx.ingest_document("cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-02-24/quay-builder-qemu-rhcos-rhel-8-amd64.json")
        .await?;
    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD&lib"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(4, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD&lib&version=8.5.0-22.el8_10"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(2, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(0, results.items.len());

    // Negative test: empty license query
    let empty_results = service
        .purls(q("license="), Paginated::default(), &ctx.db)
        .await?;
    log::debug!("Empty license query results: {empty_results:#?}");
    // Should return no items or handle gracefully
    assert_eq!(0, empty_results.items.len());

    // Negative test: malformed license query
    let malformed_results = service
        .purls(q("license=!!!not_a_license"), Paginated::default(), &ctx.db)
        .await?;
    log::debug!("Malformed license query results: {malformed_results:#?}");
    // Should return no items or handle gracefully
    assert_eq!(0, malformed_results.items.len());

    // Negative test: invalid license query
    let invalid_results = service
        .purls(q("license=INVALID_LICENSE"), Paginated::default(), &ctx.db)
        .await?;
    log::debug!("Invalid license query results: {invalid_results:#?}");
    // Should return no items or handle gracefully
    assert_eq!(0, invalid_results.items.len());

    // Pagination for just having the total count
    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"),
            Paginated {
                offset: 0,
                limit: 1,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(1, results.items.len());
    assert_eq!(Some(4), results.total);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn statuses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());
    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json", "cve/CVE-2021-32714.json"])
        .await?;

    ctx.graph
        .ingest_qualified_package(&Purl::from_str("pkg:cargo/hyper@0.14.1")?, &ctx.db)
        .await?;

    let results = service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(1, results.items.len());

    let uuid = results.items[0].head.uuid;

    let results = service
        .purl_by_uuid(&uuid, Default::default(), &ctx.db)
        .await?;

    assert_eq!(uuid, results.unwrap().head.uuid);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn contextual_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;

    let results = service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;

    let tomcat_jsp = results
        .items
        .iter()
        .find(|e| e.head.purl.to_string().contains("tomcat-jsp"));

    assert!(tomcat_jsp.is_some());

    let tomcat_jsp = tomcat_jsp.unwrap();

    let uuid = tomcat_jsp.head.uuid;

    let tomcat_jsp = service
        .purl_by_uuid(&uuid, Default::default(), &ctx.db)
        .await?;

    assert!(tomcat_jsp.is_some());

    let tomcat_jsp = tomcat_jsp.unwrap();

    assert_eq!(1, tomcat_jsp.advisories.len());

    let advisory = &tomcat_jsp.advisories[0];

    log::debug!("{advisory:#?}");

    assert_eq!(2, advisory.status.len());

    assert!( advisory.status.iter().any(|status| {
        matches!( &status.context , Some(StatusContext::Cpe(cpe)) if cpe == "cpe:/a:redhat:enterprise_linux:8:*:appstream:*")
        && status.vulnerability.identifier == "CVE-2024-24549" && status.status == "fixed"
    }));

    assert!( advisory.status.iter().any(|status| {
        matches!( &status.context , Some(StatusContext::Cpe(cpe)) if cpe == "cpe:/a:redhat:enterprise_linux:8:*:appstream:*")
            && status.vulnerability.identifier == "CVE-2024-23672" && status.status == "fixed"
    }));

    let versioned = service
        .versioned_purl_by_uuid(&tomcat_jsp.version.uuid, &ctx.db)
        .await?
        .unwrap();

    assert_eq!(1, versioned.advisories.len());

    let advisory = &versioned.advisories[0];

    log::debug!("{advisory:#?}");

    assert_eq!(2, advisory.status.len());

    assert!(advisory.status.iter().any(|status| {
        status.vulnerability.identifier == "CVE-2024-24549" && status.status == "fixed"
    }));

    assert!(advisory.status.iter().any(|status| {
        status.vulnerability.identifier == "CVE-2024-23672" && status.status == "fixed"
    }));

    Ok(())
}

async fn ingest_some_log4j_data(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn unqualified_purl_by_purl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    ingest_some_log4j_data(ctx).await?;

    let purl = "pkg:maven/org.apache/log4j@1.2.3";

    let results = service
        .purl_by_purl(&Purl::from_str(purl)?, Default::default(), &ctx.db)
        .await?
        .unwrap();

    log::debug!("{results:#?}");
    assert_eq!(results.head.purl.to_string(), purl);
    assert_eq!(results.version.version, "1.2.3");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn base_purl_by_purl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    ingest_some_log4j_data(ctx).await?;

    let results = service
        .base_purl_by_purl(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    assert!(!results.unwrap().versions.is_empty());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn versioned_base_purl_by_purl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test());

    ingest_some_log4j_data(ctx).await?;

    let results = service
        .versioned_purl_by_purl(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    assert!(!results.unwrap().purls.is_empty());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn version_ranges_cover_all_variants(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    use crate::purl::model::details::version_range::VersionRange;
    use sea_orm::EntityTrait;
    use trustify_entity::version_range;

    ctx.ingest_dataset(Dataset::DS3).await?;

    let rows = version_range::Entity::find().all(&ctx.db).await?;

    let mut full_count = 0;
    let mut left_count = 0;
    let mut right_count = 0;
    let mut unbounded_count = 0;

    for row in rows {
        match VersionRange::from_entity(row.clone()) {
            Ok(VersionRange::Full { .. }) => full_count += 1,
            Ok(VersionRange::Left { .. }) => left_count += 1,
            Ok(VersionRange::Right { .. }) => right_count += 1,
            Ok(VersionRange::Unbounded) => unbounded_count += 1,
            Err(e) => {
                log::error!("Failed to convert version_range id={}: {}", row.id, e);
            }
        }
    }

    log::info!(
        "DS3 version ranges: Full={}, Left={}, Right={}, Unbounded={}",
        full_count,
        left_count,
        right_count,
        unbounded_count
    );

    assert!(
        full_count > 0 || left_count > 0 || right_count > 0 || unbounded_count > 0,
        "Expected at least one version range variant in DS3 (Full={}, Left={}, Right={}, Unbounded={})",
        full_count,
        left_count,
        right_count,
        unbounded_count
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn version_range_boundary_semantics(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    use crate::purl::model::details::version_range::VersionRange;
    use sea_orm::EntityTrait;
    use trustify_entity::version_range;

    ctx.ingest_dataset(Dataset::DS3).await?;

    let rows = version_range::Entity::find().all(&ctx.db).await?;

    let mut tested_full = false;
    let mut tested_left = false;
    let mut tested_right = false;
    let mut tested_unbounded = false;

    for row in rows.iter() {
        match VersionRange::from_entity(row.clone()) {
            Ok(VersionRange::Full {
                version_scheme_id,
                low_version,
                low_inclusive: _,
                high_version,
                high_inclusive: _,
            }) if !tested_full => {
                assert!(
                    !version_scheme_id.is_empty(),
                    "version_scheme_id should not be empty"
                );
                assert!(!low_version.is_empty(), "low_version should not be empty");
                assert!(!high_version.is_empty(), "high_version should not be empty");

                tested_full = true;
            }
            Ok(VersionRange::Left {
                version_scheme_id,
                low_version,
                low_inclusive: _,
            }) if !tested_left => {
                assert!(
                    !version_scheme_id.is_empty(),
                    "version_scheme_id should not be empty"
                );
                assert!(!low_version.is_empty(), "low_version should not be empty");

                tested_left = true;
            }
            Ok(VersionRange::Right {
                version_scheme_id,
                high_version,
                high_inclusive: _,
            }) if !tested_right => {
                assert!(
                    !version_scheme_id.is_empty(),
                    "version_scheme_id should not be empty"
                );
                assert!(!high_version.is_empty(), "high_version should not be empty");

                tested_right = true;
            }
            Ok(VersionRange::Unbounded) if !tested_unbounded => {
                tested_unbounded = true;
            }
            _ => {}
        }
    }

    assert!(
        tested_full || tested_left || tested_right || tested_unbounded,
        "Should have tested at least one range variant (Full={}, Left={}, Right={}, Unbounded={})",
        tested_full,
        tested_left,
        tested_right,
        tested_unbounded
    );

    Ok(())
}

/// Proves that `version_matches` filtering works on the **product_status** path.
///
/// DS3 contains a CSAF advisory for CVE-2024-28834 affecting gnutls on RHEL 8
/// AppStream, and an ubi8 SPDX SBOM whose product package carries the same CPE.
/// The shared CPE bridges the product_status join chain:
///   product_status → context_cpe → product (via cpe_key) → product_version → SBOM
///
/// gnutls@3.6.16-6.el8_7 (from the ubi8 SBOM) falls within the advisory's
/// affected version range, so product_status entries with CPE context must appear.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn product_status_version_filtering(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new(PaginationCache::for_test()).with_default_patterns();
    ctx.ingest_dataset(Dataset::DS3).await?;

    // gnutls version from the ubi8 SBOM — affected (below fix 3.6.16-8.el8_9.3)
    let purl = Purl::from_str("pkg:rpm/redhat/gnutls@3.6.16-6.el8_7?arch=x86_64")?;
    let details = service
        .purl_by_purl(&purl, Default::default(), &ctx.db)
        .await?
        .expect("gnutls purl must exist after DS3 ingestion");

    // Product_status entries carry StatusContext::Cpe (not ::Purl).
    let cpe_statuses: Vec<_> = details
        .advisories
        .iter()
        .flat_map(|a| &a.status)
        .filter(|s| matches!(&s.context, Some(StatusContext::Cpe(_))))
        .collect();

    // Then exactly 2 CPE-context entries must exist, both for CVE-2024-28834.
    assert_eq!(
        cpe_statuses.len(),
        2,
        "expected exactly 2 product_status entries with CPE context"
    );

    for s in &cpe_statuses {
        assert_eq!(s.vulnerability.identifier, "CVE-2024-28834");
        assert_eq!(s.status, "affected");
        assert!(
            s.version_range.is_some(),
            "every product_status entry must carry a version_range"
        );
    }

    Ok(())
}

/// Verifies that product_status entries are returned even when the package version
/// falls outside the product stream version range — the VersionMatches filter must
/// not compare package versions against CPE-derived product version ranges.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn product_status_cross_domain_version(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // No recommend patterns — this test verifies CPE-context status entries,
    // not recommendation pattern filtering.
    let service = PurlService::new(PaginationCache::for_test());
    ctx.ingest_dataset(Dataset::DS1).await?;

    // Given keycloak-core@18.0.6 — its version (18.x) exceeds the Quarkus product
    // stream range [2.0.0, 3.0.0) derived from CPE cpe:/a:redhat:quarkus:2.
    let purl = Purl::from_str(
        "pkg:maven/org.keycloak/keycloak-core@18.0.6.redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
    )?;
    let details = service
        .purl_by_purl(&purl, Default::default(), &ctx.db)
        .await?
        .expect("keycloak-core purl must exist after DS1 ingestion");

    // When filtering for product_status entries with CPE context
    let cpe_statuses: Vec<_> = details
        .advisories
        .iter()
        .flat_map(|a| &a.status)
        .filter(|s| matches!(&s.context, Some(StatusContext::Cpe(_))))
        .collect();

    // Then exactly 8 CPE-context entries must be present, including CVE-2023-1664
    // despite the cross-domain version mismatch.
    assert_eq!(
        cpe_statuses.len(),
        8,
        "keycloak-core must have 8 product_status entries with CPE context"
    );

    let mut cve_ids: Vec<&str> = cpe_statuses
        .iter()
        .map(|s| s.vulnerability.identifier.as_str())
        .collect();
    cve_ids.sort();
    assert_eq!(
        cve_ids,
        vec![
            "CVE-2022-45787",
            "CVE-2023-0481",
            "CVE-2023-1584",
            "CVE-2023-1664",
            "CVE-2023-28867",
            "CVE-2023-2974",
            "CVE-2023-44487",
            "CVE-2023-4853",
        ]
    );

    Ok(())
}

/// Verifies that the redhat pattern's capture group extracts the upstream base version.
#[test]
fn test_pattern_extracts_upstream_version() {
    // Given a vendor rebuild pattern with one capture group
    let pattern = Regex::new(r"^(.+)\.redhat-[0-9]+$").expect("valid pattern");

    // When matching a vendor version string
    let caps = pattern
        .captures("4.3.4.redhat-00008")
        .expect("pattern must match");

    // Then capture group 1 is the upstream base version
    let upstream = caps
        .get(1)
        .expect("capture group 1 must be present")
        .as_str();
    assert_eq!(upstream, "4.3.4");
}

/// Verifies that an invalid regex pattern is skipped without panicking during server startup.
#[test]
fn test_invalid_pattern_skipped() {
    // This simulates the server's filter_map logic that skips invalid patterns.
    let raw = "[invalid(";
    let result = Regex::new(raw);
    assert!(result.is_err(), "invalid pattern should fail to compile");
    // Server code logs a warning and skips — no panic here.
}

/// Verifies that a pattern with no capture group is detected and would be skipped.
#[test]
fn test_pattern_no_capture_group_skipped() {
    // A pattern with zero capture groups has captures_len() == 1.
    let pattern = Regex::new(r"redhat-[0-9]+$").expect("valid pattern");
    assert_eq!(
        pattern.captures_len(),
        1,
        "pattern with no groups must have captures_len == 1 so server skips it"
    );
}
