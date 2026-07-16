use crate::model::{
    AdvisoryIndex, CorrelationState, PurlStatusEntry, SbomIndex, SbomPackageEntry, VersionRangeData,
};
use sea_orm::{ConnectionTrait, FromQueryResult};
use std::collections::{HashMap, HashSet};
use tracing::{Instrument, info_span, instrument};
use trustify_common::db::ReadOnly;
use trustify_entity::version_scheme::VersionScheme;
use uuid::Uuid;

/// Loads the complete correlation state from the database.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
pub async fn load_all(db: &ReadOnly) -> Result<CorrelationState, anyhow::Error> {
    let txn = db.begin().await?;

    let advisory_index = load_advisory_index(&txn)
        .instrument(info_span!("load advisory index"))
        .await?;

    let sbom_index = load_sbom_index(&txn)
        .instrument(info_span!("load sbom index"))
        .await?;

    tracing::info!(
        purl_entries = advisory_index.by_base_purl.len(),
        statuses = advisory_index.statuses.len(),
        deprecated = advisory_index.deprecated_advisories.len(),
        sboms = sbom_index.by_sbom.len(),
        "correlation state loaded"
    );

    Ok(CorrelationState {
        advisory_index,
        sbom_index,
    })
}

/// Raw row for purl_status + version_range join.
#[derive(Debug, FromQueryResult)]
struct PurlStatusRow {
    advisory_id: Uuid,
    vulnerability_id: String,
    status_id: Uuid,
    base_purl_id: Uuid,
    context_cpe_id: Option<Uuid>,
    version_scheme_id: String,
    low_version: Option<String>,
    low_inclusive: bool,
    high_version: Option<String>,
    high_inclusive: bool,
}

/// Raw row for status slugs.
#[derive(Debug, FromQueryResult)]
struct StatusRow {
    id: Uuid,
    slug: String,
}

/// Raw row for deprecated advisory IDs.
#[derive(Debug, FromQueryResult)]
struct DeprecatedRow {
    advisory_id: Uuid,
}

/// Loads the advisory index: purl_status entries + version ranges + statuses.
async fn load_advisory_index(txn: &impl ConnectionTrait) -> Result<AdvisoryIndex, anyhow::Error> {
    // Load all purl_status entries joined with version_range
    let rows: Vec<PurlStatusRow> =
        PurlStatusRow::find_by_statement(sea_orm::Statement::from_string(
            sea_orm::DatabaseBackend::Postgres,
            r#"
            SELECT
                ps.advisory_id,
                ps.vulnerability_id,
                ps.status_id,
                ps.base_purl_id,
                ps.context_cpe_id,
                vr.version_scheme_id,
                vr.low_version,
                vr.low_inclusive,
                vr.high_version,
                vr.high_inclusive
            FROM purl_status ps
            JOIN version_range vr ON vr.id = ps.version_range_id
            ORDER BY ps.base_purl_id
            "#
            .to_string(),
        ))
        .all(txn)
        .await?;

    let mut by_base_purl: HashMap<Uuid, Vec<PurlStatusEntry>> = HashMap::new();

    for row in rows {
        let version_scheme = parse_version_scheme(&row.version_scheme_id);

        let entry = PurlStatusEntry {
            advisory_id: row.advisory_id,
            vulnerability_id: row.vulnerability_id,
            status_id: row.status_id,
            version_range: VersionRangeData {
                version_scheme,
                low_version: row.low_version,
                low_inclusive: row.low_inclusive,
                high_version: row.high_version,
                high_inclusive: row.high_inclusive,
            },
            context_cpe_id: row.context_cpe_id,
        };

        by_base_purl
            .entry(row.base_purl_id)
            .or_default()
            .push(entry);
    }

    // Load status slugs
    let status_rows: Vec<StatusRow> =
        StatusRow::find_by_statement(sea_orm::Statement::from_string(
            sea_orm::DatabaseBackend::Postgres,
            "SELECT id, slug FROM status".to_string(),
        ))
        .all(txn)
        .await?;

    let statuses: HashMap<Uuid, String> = status_rows.into_iter().map(|r| (r.id, r.slug)).collect();

    // Load deprecated advisory IDs
    let deprecated_rows: Vec<DeprecatedRow> =
        DeprecatedRow::find_by_statement(sea_orm::Statement::from_string(
            sea_orm::DatabaseBackend::Postgres,
            "SELECT id as advisory_id FROM advisory WHERE deprecated = true".to_string(),
        ))
        .all(txn)
        .await?;

    let deprecated_advisories: HashSet<Uuid> =
        deprecated_rows.into_iter().map(|r| r.advisory_id).collect();

    // Load product_status entries indexed by package name
    let product_rows: Vec<ProductStatusRow> =
        ProductStatusRow::find_by_statement(sea_orm::Statement::from_string(
            sea_orm::DatabaseBackend::Postgres,
            r#"
            SELECT
                ps.advisory_id,
                ps.vulnerability_id,
                ps.status_id,
                ps.context_cpe_id,
                ps.package
            FROM product_status ps
            WHERE ps.package IS NOT NULL
            "#
            .to_string(),
        ))
        .all(txn)
        .await?;

    let mut product_by_name: HashMap<String, Vec<crate::model::ProductStatusEntry>> =
        HashMap::new();
    for row in product_rows {
        if let Some(pkg) = row.package {
            product_by_name
                .entry(pkg)
                .or_default()
                .push(crate::model::ProductStatusEntry {
                    advisory_id: row.advisory_id,
                    vulnerability_id: row.vulnerability_id,
                    status_id: row.status_id,
                    context_cpe_id: row.context_cpe_id,
                });
        }
    }

    Ok(AdvisoryIndex {
        by_base_purl,
        product_by_name,
        statuses,
        deprecated_advisories,
    })
}

/// Raw row for product_status entries.
#[derive(Debug, FromQueryResult)]
struct ProductStatusRow {
    advisory_id: Uuid,
    vulnerability_id: String,
    status_id: Uuid,
    context_cpe_id: Option<Uuid>,
    package: Option<String>,
}

/// Raw row for SBOM package data.
#[derive(Debug, FromQueryResult)]
struct SbomPackageRow {
    sbom_id: Uuid,
    base_purl_id: Uuid,
    version: String,
    name: String,
    namespace: Option<String>,
}

/// Raw row for SBOM describing CPEs.
#[derive(Debug, FromQueryResult)]
struct SbomCpeRow {
    sbom_id: Uuid,
    cpe_id: Uuid,
}

/// Loads the SBOM index: packages and describing CPEs per SBOM.
async fn load_sbom_index(txn: &impl ConnectionTrait) -> Result<SbomIndex, anyhow::Error> {
    let pkg_rows: Vec<SbomPackageRow> =
        SbomPackageRow::find_by_statement(sea_orm::Statement::from_string(
            sea_orm::DatabaseBackend::Postgres,
            r#"
            SELECT DISTINCT
                snpr.sbom_id,
                vp.base_purl_id,
                vp.version,
                bp.name,
                bp.namespace
            FROM sbom_node_purl_ref snpr
            JOIN qualified_purl qp ON qp.id = snpr.qualified_purl_id
            JOIN versioned_purl vp ON vp.id = qp.versioned_purl_id
            JOIN base_purl bp ON bp.id = vp.base_purl_id
            WHERE vp.version IS NOT NULL AND vp.version != ''
            ORDER BY snpr.sbom_id
            "#
            .to_string(),
        ))
        .all(txn)
        .await?;

    let mut by_sbom: HashMap<Uuid, Vec<SbomPackageEntry>> = HashMap::new();
    for row in pkg_rows {
        by_sbom
            .entry(row.sbom_id)
            .or_default()
            .push(SbomPackageEntry {
                base_purl_id: row.base_purl_id,
                version: row.version,
                name: row.name,
                namespace: row.namespace,
            });
    }

    // Load allowed CPE IDs per SBOM (direct + generalized, matching v3 logic).
    // Generalized CPEs share vendor/product/major-version with wildcard edition.
    let cpe_rows: Vec<SbomCpeRow> = SbomCpeRow::find_by_statement(sea_orm::Statement::from_string(
        sea_orm::DatabaseBackend::Postgres,
        r#"
            WITH filtered AS (
                SELECT sdc.sbom_id, cpe.id AS cpe_id, cpe.vendor, cpe.product, cpe.version
                FROM sbom_describing_cpe sdc
                JOIN cpe ON sdc.cpe_id = cpe.id
            ),
            generalized AS (
                SELECT f.sbom_id, c.id AS cpe_id
                FROM filtered f
                JOIN cpe c ON c.vendor = f.vendor
                    AND c.product = f.product
                    AND c.version = split_part(f.version, '.', 1)
                    AND (c.edition IS NULL OR c.edition = '*')
            )
            SELECT sbom_id, cpe_id FROM filtered
            UNION
            SELECT sbom_id, cpe_id FROM generalized
            "#
        .to_string(),
    ))
    .all(txn)
    .await?;

    let mut describing_cpes: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
    for row in cpe_rows {
        describing_cpes
            .entry(row.sbom_id)
            .or_default()
            .insert(row.cpe_id);
    }

    Ok(SbomIndex {
        by_sbom,
        describing_cpes,
    })
}

/// Maps a version_scheme_id string to the VersionScheme enum.
fn parse_version_scheme(s: &str) -> VersionScheme {
    match s {
        "semver" => VersionScheme::Semver,
        "rpm" => VersionScheme::Rpm,
        "maven" => VersionScheme::Maven,
        "python" => VersionScheme::Python,
        "npm" => VersionScheme::Npm,
        "gem" => VersionScheme::Gem,
        "golang" => VersionScheme::Golang,
        "nuget" => VersionScheme::NuGet,
        "packagist" => VersionScheme::Packagist,
        "hex" => VersionScheme::Hex,
        "swift" => VersionScheme::Swift,
        "pub" => VersionScheme::Pub,
        "cargo" => VersionScheme::Cargo,
        "git" => VersionScheme::Git,
        _ => VersionScheme::Generic,
    }
}
