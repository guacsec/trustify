#![recursion_limit = "512"]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use sea_orm::FromQueryResult;
use std::collections::HashSet;
use test_context::test_context;
use test_log::test;
use trustify_common::{db::pagination_cache::PaginationCache, id::Id};
use trustify_module_correlation::{config::CorrelationConfig, service::CorrelationService};
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::{Dataset, TrustifyContext};

#[derive(Debug, FromQueryResult)]
struct MatchCheck {
    package: String,
    has_cpe_context: bool,
    name_match: Option<String>,
    ns_name_match: Option<String>,
}

/// Diagnostic: show which advisories v3a finds vs v3 for quarkus-bom.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn diagnostic_advisory_diff(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;

    let sbom = &result.files["spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2"];
    let sbom_id = Id::parse_uuid(&sbom.id)?;

    // v3a
    let sbom_service = SbomService::new(PaginationCache::for_test());
    let v3a_details = sbom_service
        .fetch_sbom_details(sbom_id.clone(), vec![], &ctx.db)
        .await?
        .expect("SBOM should exist");

    let v3a_advisory_ids: HashSet<_> = v3a_details
        .advisories
        .iter()
        .map(|a| a.head.uuid.to_string())
        .collect();

    // v3
    let db_ro = trustify_common::db::ReadOnly::new(ctx.db.clone());
    let db_rw = trustify_common::db::ReadWrite::new(ctx.db.clone());
    let config = CorrelationConfig {
        correlation_poll_interval_secs: 30,
        correlation_debounce_secs: 2,
    };
    let correlation = CorrelationService::new(&config, db_ro, &db_rw).await?;

    let sbom_uuid = match sbom_id {
        Id::Uuid(u) => u,
        _ => panic!("expected UUID"),
    };

    let v3_matches = correlation.correlate_sbom(sbom_uuid)?;
    let v3_advisory_ids: HashSet<_> = v3_matches
        .iter()
        .map(|m| m.advisory_id.to_string())
        .collect();

    let only_v3a: Vec<_> = v3a_advisory_ids.difference(&v3_advisory_ids).collect();
    log::info!(
        "v3a={}, v3={}, only_v3a={}",
        v3a_advisory_ids.len(),
        v3_advisory_ids.len(),
        only_v3a.len()
    );

    // State summary
    let state = correlation.state();
    log::info!(
        "v3 state: {} purl_keys, {} product_by_name, {} sbom packages for this SBOM",
        state.advisory_index.by_purl.len(),
        state.advisory_index.product_by_name.len(),
        state
            .sbom_index
            .by_sbom
            .get(&sbom_uuid)
            .map(|p| p.len())
            .unwrap_or(0),
    );

    // For one v3a-only advisory (CVE-2023-33201), check if product_status.package
    // values match any SBOM base_purl name or namespace/name
    let checks: Vec<MatchCheck> = MatchCheck::find_by_statement(sea_orm::Statement::from_string(
        sea_orm::DatabaseBackend::Postgres,
        format!(
            r#"
            WITH sbom_pkgs AS (
                SELECT DISTINCT bp.name, bp.namespace
                FROM sbom_node_purl_ref snpr
                JOIN qualified_purl qp ON qp.id = snpr.qualified_purl_id
                JOIN versioned_purl vp ON vp.id = qp.versioned_purl_id
                JOIN base_purl bp ON bp.id = vp.base_purl_id
                WHERE snpr.sbom_id = '{}'
            )
            SELECT DISTINCT
                ps.package,
                (ps.context_cpe_id IS NOT NULL) as has_cpe_context,
                sp_name.name as name_match,
                CONCAT(sp_ns.namespace, '/', sp_ns.name) as ns_name_match
            FROM product_status ps
            JOIN advisory_vulnerability av ON av.advisory_id = ps.advisory_id
                AND av.vulnerability_id = ps.vulnerability_id
            LEFT JOIN sbom_pkgs sp_name ON ps.package = sp_name.name
            LEFT JOIN sbom_pkgs sp_ns ON sp_ns.namespace IS NOT NULL
                AND ps.package = CONCAT(sp_ns.namespace, '/', sp_ns.name)
            WHERE av.vulnerability_id = 'CVE-2023-33201'
            AND ps.package IS NOT NULL
            ORDER BY ps.package
            "#,
            sbom_uuid
        ),
    ))
    .all(&ctx.db)
    .await?;

    for c in &checks {
        log::info!(
            "CVE-2023-33201 product_status: package={:?} has_cpe={} name_match={:?} ns_match={:?}",
            c.package,
            c.has_cpe_context,
            c.name_match,
            c.ns_name_match
        );
    }

    // Check: does v3 product_by_name have these package names?
    for c in &checks {
        let in_index = state
            .advisory_index
            .product_by_name
            .contains_key(c.package.as_str());
        log::info!("  product_by_name[{:?}] exists: {}", c.package, in_index);
    }

    // What SBOM packages would match these product_status entries?
    let package_indices = state.sbom_index.by_sbom.get(&sbom_uuid).unwrap();
    let matching_pkgs: Vec<_> = package_indices
        .iter()
        .map(|&idx| state.sbom_index.catalog.get(idx))
        .filter(|p| {
            checks.iter().any(|c| {
                c.package.as_str() == &*p.name
                    || p.namespace
                        .as_ref()
                        .is_some_and(|ns| c.package == format!("{}/{}", ns, p.name))
            })
        })
        .collect();
    log::info!(
        "SBOM packages matching CVE-2023-33201 product_status names: {}",
        matching_pkgs.len()
    );
    for p in &matching_pkgs {
        log::info!("  matched: name={:?} ns={:?}", p.name, p.namespace);
    }

    // Check the CPE context for the SBOM
    let sbom_cpes = state.sbom_index.describing_cpes.get(&sbom_uuid);
    log::info!("SBOM describing CPEs: {:?}", sbom_cpes.map(|c| c.len()));

    Ok(())
}
