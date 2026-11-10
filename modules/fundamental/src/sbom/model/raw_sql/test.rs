use super::batch_severity_counts_sql;
use crate::sbom::{model::AffectedSeverity, service::SbomService};
use sea_orm::{ConnectionTrait, Statement, TransactionTrait};
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_common::db::{pagination_cache::PaginationCache, sql};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

async fn ingest_sbom(
    ctx: &TrustifyContext,
    name: &str,
    version: &str,
    context: Option<&str>,
) -> anyhow::Result<Uuid> {
    let mut component = json!({"type": "application", "name": name});
    if let Some(context) = context {
        component["cpe"] = context.into();
    }
    let document = json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": component},
        // Repeated nodes and qualifiers must not multiply matches or counts.
        "components": [
            {"type": "library", "bom-ref": "a", "name": "aiohttp", "version": version,
             "purl": format!("pkg:pypi/aiohttp@{version}")},
            {"type": "library", "bom-ref": "b", "name": "aiohttp", "version": version,
             "purl": format!("pkg:pypi/aiohttp@{version}")},
            {"type": "library", "bom-ref": "c", "name": "aiohttp", "version": version,
             "purl": format!("pkg:pypi/aiohttp@{version}?arch=x86_64")}
        ]
    });
    Ok(ctx
        .ingest_read(serde_json::to_vec(&document)?.as_slice())
        .await?
        .id
        .parse()?)
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn severity_counts_share_versions_without_sharing_sbom_context(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ctx.ingest_document("osv/GHSA-45c4-8wx5-qw6w.json").await?;
    let matching = ingest_sbom(
        ctx,
        "matching-context",
        "3.8.4",
        Some("cpe:2.3:o:test:platform:1:*:*:*:*:*:*:*"),
    )
    .await?;
    let other = ingest_sbom(
        ctx,
        "other-context",
        "3.8.4",
        Some("cpe:2.3:o:test:other:1:*:*:*:*:*:*:*"),
    )
    .await?;
    let no_context = ingest_sbom(ctx, "no-context", "3.8.4", None).await?;
    let fixed = ingest_sbom(ctx, "fixed-version", "3.8.5", None).await?;

    let tx = ctx.db.begin().await?;
    tx.execute_raw(sql(
        "UPDATE purl_status SET context_cpe_id = (SELECT cpe_id FROM sbom_describing_cpe WHERE sbom_id = $1 LIMIT 1)",
        vec![matching.into()],
    ))
    .await?;
    let service = SbomService::new(PaginationCache::for_test());
    let ids = [matching, other, no_context, fixed, Uuid::nil(), matching];
    let counts = service.batch_advisory_severity_counts(&ids, &tx).await?;
    assert_eq!(counts.len(), 2, "{counts:?}");
    for id in [matching, no_context] {
        assert_eq!(counts[&id].values().sum::<u64>(), 1);
        assert_eq!(counts[&id][&AffectedSeverity::Medium], 1);
        // Batching must not change per-SBOM context or version semantics.
        let single = service.batch_advisory_severity_counts(&[id], &tx).await?;
        assert_eq!(counts[&id], single[&id]);
    }
    for id in [other, fixed, Uuid::nil()] {
        assert!(!counts.contains_key(&id));
    }
    // Multiple score versions still contribute one vulnerability at its highest severity.
    tx.execute_unprepared(
        "UPDATE advisory_vulnerability_score SET severity = 'critical' WHERE type = '4.0'",
    )
    .await?;
    let counts = service.batch_advisory_severity_counts(&ids, &tx).await?;
    for id in [matching, no_context] {
        assert_eq!(counts[&id].len(), 1);
        assert_eq!(counts[&id][&AffectedSeverity::Critical], 1);
    }
    tx.execute_unprepared("DELETE FROM advisory_vulnerability_score")
        .await?;
    let counts = service.batch_advisory_severity_counts(&ids, &tx).await?;
    for id in [matching, no_context] {
        assert_eq!(counts[&id][&AffectedSeverity::Unknown], 1);
    }
    // An exact fixed statement must still imply the publisher's derived affected range.
    tx.execute_unprepared(
        r#"
        UPDATE advisory SET publisher_namespace = 'https://www.redhat.com';
        UPDATE purl_status SET status_id = (SELECT id FROM status WHERE slug = 'fixed' ORDER BY id LIMIT 1);
        UPDATE version_range SET low_version = high_version, low_inclusive = true, high_inclusive = true
        WHERE id IN (SELECT version_range_id FROM purl_status);
        "#,
    )
    .await?;
    let derived = service.batch_advisory_severity_counts(&ids, &tx).await?;
    assert_eq!(derived, counts);
    tx.execute_unprepared("UPDATE purl_status SET is_default = true")
        .await?;
    assert!(
        service
            .batch_advisory_severity_counts(&ids, &tx)
            .await?
            .is_empty()
    );
    tx.execute_unprepared("UPDATE purl_status SET is_default = false")
        .await?;
    tx.execute_unprepared("UPDATE advisory SET deprecated = true")
        .await?;
    assert!(
        service
            .batch_advisory_severity_counts(&ids, &tx)
            .await?
            .is_empty()
    );
    assert!(
        service
            .batch_advisory_severity_counts(&[], &tx)
            .await?
            .is_empty()
    );
    Ok(())
}

fn plan_nodes<'a>(node: &'a Value, nodes: &mut Vec<&'a Value>) {
    nodes.push(node);
    if let Some(children) = node["Plans"].as_array() {
        for child in children {
            plan_nodes(child, nodes);
        }
    }
}

fn package_scoped_index_scan(node: &Value) -> bool {
    match node["Node Type"].as_str() {
        Some("Index Scan" | "Index Only Scan" | "Bitmap Index Scan") => {
            node["Index Cond"].as_str().is_some_and(|condition| {
                condition.contains("(base_purl_id = sbom_purl_info.base_purl_id)")
            })
        }
        Some("Bitmap Heap Scan" | "BitmapAnd" | "BitmapOr") => {
            node["Plans"].as_array().is_some_and(|children| {
                !children.is_empty() && children.iter().all(package_scoped_index_scan)
            })
        }
        _ => false,
    }
}

#[test]
fn status_index_scans_must_be_constrained_to_the_current_package() {
    for kind in ["Index Scan", "Index Only Scan", "Bitmap Index Scan"] {
        let scoped = json!({
            "Node Type": kind,
            "Index Cond": "(base_purl_id = sbom_purl_info.base_purl_id)"
        });
        assert!(package_scoped_index_scan(&scoped), "{scoped}");
        // A full index scan, a post-scan filter, or an unrelated constant restriction
        // must not stand in for a parameterized index lookup of the current package.
        for condition in [
            Value::Null,
            json!("(base_purl_id IS NOT NULL)"),
            json!("(base_purl_id = '00000000-0000-0000-0000-000000000001'::uuid)"),
        ] {
            let unscoped = json!({
                "Node Type": kind,
                "Index Cond": condition,
                "Filter": "(base_purl_id = sbom_purl_info.base_purl_id)",
                "Actual Loops": 500
            });
            assert!(!package_scoped_index_scan(&unscoped), "{unscoped}");
        }
    }
    let scoped = json!({
        "Node Type": "Bitmap Index Scan",
        "Index Cond": "(base_purl_id = sbom_purl_info.base_purl_id)"
    });
    let unscoped = json!({"Node Type": "Bitmap Index Scan"});
    assert!(package_scoped_index_scan(&json!({
        "Node Type": "Bitmap Heap Scan", "Plans": [scoped.clone()]
    })));
    for kind in ["BitmapAnd", "BitmapOr"] {
        assert!(package_scoped_index_scan(&json!({
            "Node Type": "Bitmap Heap Scan",
            "Plans": [{"Node Type": kind, "Plans": [scoped.clone(), scoped.clone()]}]
        })));
        assert!(!package_scoped_index_scan(&json!({
            "Node Type": "Bitmap Heap Scan",
            "Plans": [{"Node Type": kind, "Plans": [scoped.clone(), unscoped.clone()]}]
        })));
    }
    assert!(!package_scoped_index_scan(&json!({
        "Node Type": "Bitmap Heap Scan", "Plans": []
    })));
    // An unrelated package index elsewhere in the plan must not hide a full status scan.
    let plan = json!({"Node Type": "Nested Loop", "Plans": [
        {"Node Type": "Index Scan", "Relation Name": "base_purl",
         "Index Cond": "(base_purl_id = sbom_purl_info.base_purl_id)"},
        {"Node Type": "Index Scan", "Relation Name": "purl_status", "Actual Loops": 500}
    ]});
    let mut nodes = Vec::new();
    plan_nodes(&plan, &mut nodes);
    let status = nodes
        .iter()
        .find(|node| node["Relation Name"] == "purl_status")
        .unwrap();
    assert!(!package_scoped_index_scan(status));
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn severity_counts_use_package_scoped_status_lookups(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ctx.ingest_document("osv/GHSA-45c4-8wx5-qw6w.json").await?;
    let mut ids = Vec::new();
    for name in ["page-a", "page-b"] {
        let components = (1..=500)
            .flat_map(|n| {
                (0..2).map(move |copy| {
                    json!({
                        "type": "library", "bom-ref": format!("{n}-{copy}"),
                        "name": format!("page-package-{n}"), "version": "1.0.0",
                        "purl": format!("pkg:generic/page-package-{n}@1.0.0")
                    })
                })
            })
            .collect::<Vec<_>>();
        let document = json!({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": name}},
            "components": components
        });
        ids.push(Uuid::parse_str(
            &ctx.ingest_read(serde_json::to_vec(&document)?.as_slice())
                .await?
                .id,
        )?);
    }
    let (a, b) = (ids[0], ids[1]);
    let tx = ctx.db.begin().await?;
    // Five assertions per package, most outside the requested page.
    tx.execute_unprepared(
        r#"
        INSERT INTO base_purl(id, type, name)
        SELECT md5('unrelated-' || n)::uuid, 'generic', 'unrelated-' || n
        FROM generate_series(1, 20000) n;
        INSERT INTO purl_status(advisory_id, status_id, base_purl_id, version_range_id, vulnerability_id)
        SELECT src.advisory_id, src.status_id, bp.id, src.version_range_id, src.vulnerability_id
        FROM base_purl bp
        CROSS JOIN (SELECT * FROM purl_status LIMIT 1) src
        CROSS JOIN generate_series(1, 5) copies
        WHERE bp.type = 'generic';
        ANALYZE base_purl;
        ANALYZE purl_status;
        ANALYZE version_range;
        "#,
    )
    .await?;
    let row = tx
        .query_one_raw(Statement::from_sql_and_values(
            tx.get_database_backend(),
            format!(
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                batch_severity_counts_sql()
            ),
            vec![vec![a, b].into()],
        ))
        .await?
        .unwrap();
    let plan: Value = row.try_get("", "QUERY PLAN")?;
    let mut nodes = Vec::new();
    plan_nodes(&plan[0]["Plan"], &mut nodes);
    let status_scans = nodes
        .iter()
        .filter(|node| node["Relation Name"] == "purl_status")
        .collect::<Vec<_>>();
    assert!(!status_scans.is_empty(), "missing status access: {plan:#}");
    let matches = nodes
        .iter()
        .find(|node| node["Subplan Name"] == "CTE purl_version_matches")
        .expect("range matches must be materialized once for the page");
    assert_eq!(matches["Actual Rows"], 500);
    assert_eq!(matches["Actual Loops"], 1);
    for node in status_scans {
        // Bitmap index conditions live under the heap scan, not on the relation node.
        assert!(
            package_scoped_index_scan(node),
            "every status access must use an index condition for the current package: {plan:#}"
        );
        assert_eq!(
            node["Actual Loops"], 500,
            "one status lookup per distinct version, not per node or SBOM: {plan:#}"
        );
    }
    let service = SbomService::new(PaginationCache::for_test());
    let counts = service.batch_advisory_severity_counts(&[a, b], &tx).await?;
    assert_eq!(counts.len(), 2);
    for id in [a, b] {
        assert_eq!(counts[&id].values().sum::<u64>(), 1);
    }
    Ok(())
}
