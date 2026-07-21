use crate::model::{
    AdvisoryIndex, AdvisoryPatch, CorrelationState, ProductStatusEntry, PurlKey, PurlStatusEntry,
    SbomIndex, SbomPackageEntry, SbomPatch, SeverityIndex, VersionRangeData, VulnEntrySource,
    VulnIndexEntry,
};
use futures::TryStreamExt;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, JoinType, QueryFilter, QuerySelect,
    RelationTrait, StreamTrait,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{Instrument, info_span, instrument};
use trustify_common::db::ReadOnly;
use trustify_entity::advisory_vulnerability_score::Severity;
use trustify_entity::version_scheme::VersionScheme;
use trustify_entity::{
    advisory, advisory_vulnerability_score, base_purl, product_status, purl_status, qualified_purl,
    sbom_node_purl_ref, status, version_range,
};
use uuid::Uuid;

/// Deduplicates strings into `Arc<str>` to reduce heap allocations.
///
/// Strings that appear across many rows (purl types, namespaces, vulnerability IDs,
/// version bounds) are interned so identical values share a single allocation.
struct StringInterner(HashMap<String, Arc<str>>);

impl StringInterner {
    fn new() -> Self {
        Self(HashMap::new())
    }

    /// Interns a string, returning a shared reference.
    fn intern(&mut self, s: String) -> Arc<str> {
        if let Some(existing) = self.0.get(s.as_str()) {
            Arc::clone(existing)
        } else {
            let arc: Arc<str> = Arc::from(s.as_str());
            self.0.insert(s, Arc::clone(&arc));
            arc
        }
    }

    /// Interns an optional string.
    fn intern_opt(&mut self, s: Option<String>) -> Option<Arc<str>> {
        s.map(|s| self.intern(s))
    }
}

/// Loads the complete correlation state from the database.
///
/// Advisory and SBOM indexes are loaded sequentially to avoid doubling peak
/// memory from parallel materialization. Each uses streaming cursors to avoid
/// intermediate Vecs.
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
        purl_entries = advisory_index.by_purl.len(),
        statuses = advisory_index.statuses.len(),
        product_entries = advisory_index.product_by_name.len(),
        sboms = sbom_index.by_sbom.len(),
        cpe_sboms = sbom_index.describing_cpes.len(),
        "correlation state loaded"
    );

    Ok(CorrelationState {
        advisory_index,
        sbom_index,
    })
}

/// Raw row for purl_status + version_range + base_purl join.
#[derive(Debug, FromQueryResult)]
struct PurlStatusRow {
    purl_status_id: Uuid,
    advisory_id: Uuid,
    vulnerability_id: String,
    status_id: Uuid,
    purl_type: String,
    purl_namespace: Option<String>,
    purl_name: String,
    context_cpe_id: Option<Uuid>,
    version_scheme_id: VersionScheme,
    low_version: Option<String>,
    low_inclusive: Option<bool>,
    high_version: Option<String>,
    high_inclusive: Option<bool>,
}

/// Raw row for advisory_vulnerability_score (severity lookup).
#[derive(Debug, FromQueryResult)]
struct SeverityRow {
    advisory_id: Uuid,
    vulnerability_id: String,
    severity: Severity,
}

/// Raw row for SBOM describing CPEs.
#[derive(Debug, FromQueryResult)]
struct SbomCpeRow {
    sbom_id: Uuid,
    cpe_id: Uuid,
}

/// Loads the full advisory index using streaming cursors.
///
/// Queries run sequentially within a single transaction to share the server-side cursor.
/// Deprecated advisories are filtered out at the SQL level.
pub(crate) async fn load_advisory_index(
    txn: &(impl ConnectionTrait + StreamTrait),
) -> Result<AdvisoryIndex, anyhow::Error> {
    let mut interner = StringInterner::new();

    // Stream purl_status rows and build the by_purl index incrementally
    let mut by_purl: HashMap<PurlKey, Vec<PurlStatusEntry>> = HashMap::new();
    let mut purl_row_count: u64 = 0;

    let mut stream = purl_status::Entity::find()
        .join(
            JoinType::InnerJoin,
            purl_status::Relation::VersionRange.def(),
        )
        .join(JoinType::InnerJoin, purl_status::Relation::BasePurl.def())
        .join(JoinType::InnerJoin, purl_status::Relation::Advisory.def())
        .filter(advisory::Column::Deprecated.eq(false))
        .select_only()
        .column_as(purl_status::Column::Id, "purl_status_id")
        .column(purl_status::Column::AdvisoryId)
        .column(purl_status::Column::VulnerabilityId)
        .column(purl_status::Column::StatusId)
        .column(purl_status::Column::ContextCpeId)
        .column_as(base_purl::Column::Type, "purl_type")
        .column_as(base_purl::Column::Namespace, "purl_namespace")
        .column_as(base_purl::Column::Name, "purl_name")
        .column(version_range::Column::VersionSchemeId)
        .column(version_range::Column::LowVersion)
        .column(version_range::Column::LowInclusive)
        .column(version_range::Column::HighVersion)
        .column(version_range::Column::HighInclusive)
        .into_model::<PurlStatusRow>()
        .stream(txn)
        .await?;

    while let Some(row) = stream.try_next().await? {
        purl_row_count += 1;
        let key = PurlKey {
            ty: interner.intern(row.purl_type),
            namespace: interner.intern_opt(row.purl_namespace),
            name: interner.intern(row.purl_name),
        };
        by_purl.entry(key).or_default().push(PurlStatusEntry {
            purl_status_id: row.purl_status_id,
            advisory_id: row.advisory_id,
            vulnerability_id: interner.intern(row.vulnerability_id),
            status_id: row.status_id,
            version_range: build_version_range(
                &mut interner,
                row.version_scheme_id,
                row.low_version,
                row.low_inclusive.unwrap_or(true),
                row.high_version,
                row.high_inclusive.unwrap_or(false),
            ),
            context_cpe_id: row.context_cpe_id,
        });
    }
    drop(stream);

    tracing::info!(
        purl_keys = by_purl.len(),
        purl_status_rows = purl_row_count,
        interned_strings = interner.0.len(),
        "advisory purl_status loaded"
    );

    // Status table is small — load all at once
    let status_rows = status::Entity::find()
        .all(txn)
        .instrument(info_span!("load statuses"))
        .await?;

    let statuses: HashMap<_, _> = status_rows
        .into_iter()
        .map(|r| (r.id, interner.intern(r.slug)))
        .collect();

    // Stream product_status rows and build the product_by_name index
    let mut product_by_name: HashMap<Arc<str>, Vec<ProductStatusEntry>> = HashMap::new();
    let mut product_row_count: u64 = 0;

    let mut stream = product_status::Entity::find()
        .join(
            JoinType::InnerJoin,
            product_status::Relation::Advisory.def(),
        )
        .filter(advisory::Column::Deprecated.eq(false))
        .filter(product_status::Column::Package.is_not_null())
        .stream(txn)
        .await?;

    while let Some(row) = stream.try_next().await? {
        if let Some(pkg) = row.package {
            product_row_count += 1;
            product_by_name
                .entry(interner.intern(pkg))
                .or_default()
                .push(ProductStatusEntry {
                    product_status_id: row.id,
                    advisory_id: row.advisory_id,
                    vulnerability_id: interner.intern(row.vulnerability_id),
                    status_id: row.status_id,
                    context_cpe_id: row.context_cpe_id,
                });
        }
    }
    drop(stream);

    tracing::info!(
        product_keys = product_by_name.len(),
        product_rows = product_row_count,
        "advisory product_status loaded"
    );

    // Load severity index from advisory_vulnerability_score
    let severity = load_severity_index(&mut interner, txn)
        .instrument(info_span!("load severity index"))
        .await?;

    tracing::info!(severity_entries = severity.len(), "severity index loaded");

    // Build reverse vulnerability index from by_purl and product_by_name
    let by_vulnerability = build_vulnerability_index(&by_purl, &product_by_name);

    tracing::info!(
        vulnerability_keys = by_vulnerability.len(),
        "vulnerability reverse index built"
    );

    Ok(AdvisoryIndex {
        by_purl,
        product_by_name,
        statuses,
        severity,
        by_vulnerability,
    })
}

/// Loads the SBOM index by joining sbom_node_purl_ref with qualified_purl,
/// building per-SBOM package vectors directly.
/// The CPE query uses a CTE with a self-join and `split_part()` — kept as raw SQL.
pub(crate) async fn load_sbom_index(
    txn: &(impl ConnectionTrait + StreamTrait),
) -> Result<SbomIndex, anyhow::Error> {
    let mut interner = StringInterner::new();

    let mut by_sbom_build: HashMap<Uuid, Vec<SbomPackageEntry>> = HashMap::new();
    let mut seen_per_sbom: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
    let mut ref_count: u64 = 0;

    let rows: Vec<(sbom_node_purl_ref::Model, Option<qualified_purl::Model>)> =
        sbom_node_purl_ref::Entity::find()
            .find_also_related(qualified_purl::Entity)
            .all(txn)
            .instrument(info_span!("load sbom purl refs"))
            .await?;

    for (snpr, qp_opt) in rows {
        if let Some(qp) = qp_opt
            && let Some(version) = qp.purl.version
            && !version.is_empty()
        {
            let seen = seen_per_sbom.entry(snpr.sbom_id).or_default();
            if !seen.insert(qp.id) {
                continue;
            }
            ref_count += 1;
            by_sbom_build
                .entry(snpr.sbom_id)
                .or_default()
                .push(SbomPackageEntry {
                    ty: interner.intern(qp.purl.ty),
                    name: interner.intern(qp.purl.name),
                    namespace: interner.intern_opt(qp.purl.namespace),
                    version: interner.intern(version),
                });
        }
    }
    drop(seen_per_sbom);

    let by_sbom: HashMap<Uuid, Arc<[SbomPackageEntry]>> = by_sbom_build
        .into_iter()
        .map(|(id, pkgs)| (id, Arc::from(pkgs.into_boxed_slice())))
        .collect();

    tracing::info!(
        sboms = by_sbom.len(),
        purl_refs = ref_count,
        interned_strings = interner.0.len(),
        "per-SBOM package index built"
    );

    // Load CPE IDs per SBOM (direct + generalized, matching v3a SQL logic).
    // Kept as raw SQL — CTE with self-join and split_part() doesn't map to SeaORM.
    let mut describing_cpes: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();

    let mut stream = SbomCpeRow::find_by_statement(sea_orm::Statement::from_string(
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
    .stream(txn)
    .await?;

    while let Some(row) = stream.try_next().await? {
        describing_cpes
            .entry(row.sbom_id)
            .or_default()
            .insert(row.cpe_id);
    }
    drop(stream);

    tracing::info!(cpe_sboms = describing_cpes.len(), "sbom cpes loaded");

    // Build reverse PurlKey → sbom_ids index
    let mut by_purl_key: HashMap<PurlKey, Vec<Uuid>> = HashMap::new();
    for (&sbom_id, packages) in &by_sbom {
        for pkg in packages.iter() {
            let key = PurlKey {
                ty: Arc::clone(&pkg.ty),
                namespace: pkg.namespace.as_ref().map(Arc::clone),
                name: Arc::clone(&pkg.name),
            };
            by_purl_key.entry(key).or_default().push(sbom_id);
        }
    }

    tracing::info!(
        purl_key_entries = by_purl_key.len(),
        "sbom by_purl_key reverse index built"
    );

    Ok(SbomIndex {
        by_sbom,
        describing_cpes,
        by_purl_key,
    })
}

/// Loads advisory patches for a batch of advisory IDs.
///
/// Returns one AdvisoryPatch per advisory that has data. Uses SeaORM query builder
/// with `.is_in()` for parameter binding.
#[instrument(skip_all, fields(count = ids.len()), err(level = tracing::Level::INFO))]
pub(crate) async fn load_advisory_patches(
    ids: &[Uuid],
    txn: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, AdvisoryPatch>, anyhow::Error> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut interner = StringInterner::new();

    let purl_rows = purl_status::Entity::find()
        .join(
            JoinType::InnerJoin,
            purl_status::Relation::VersionRange.def(),
        )
        .join(JoinType::InnerJoin, purl_status::Relation::BasePurl.def())
        .join(JoinType::InnerJoin, purl_status::Relation::Advisory.def())
        .filter(purl_status::Column::AdvisoryId.is_in(ids.iter().copied()))
        .filter(advisory::Column::Deprecated.eq(false))
        .select_only()
        .column_as(purl_status::Column::Id, "purl_status_id")
        .column(purl_status::Column::AdvisoryId)
        .column(purl_status::Column::VulnerabilityId)
        .column(purl_status::Column::StatusId)
        .column(purl_status::Column::ContextCpeId)
        .column_as(base_purl::Column::Type, "purl_type")
        .column_as(base_purl::Column::Namespace, "purl_namespace")
        .column_as(base_purl::Column::Name, "purl_name")
        .column(version_range::Column::VersionSchemeId)
        .column(version_range::Column::LowVersion)
        .column(version_range::Column::LowInclusive)
        .column(version_range::Column::HighVersion)
        .column(version_range::Column::HighInclusive)
        .into_model::<PurlStatusRow>()
        .all(txn)
        .instrument(info_span!("load advisory purl_status patches"))
        .await?;

    let product_rows = product_status::Entity::find()
        .join(
            JoinType::InnerJoin,
            product_status::Relation::Advisory.def(),
        )
        .filter(product_status::Column::AdvisoryId.is_in(ids.iter().copied()))
        .filter(advisory::Column::Deprecated.eq(false))
        .filter(product_status::Column::Package.is_not_null())
        .all(txn)
        .instrument(info_span!("load advisory product_status patches"))
        .await?;

    let mut patches: HashMap<Uuid, AdvisoryPatch> = HashMap::new();

    for row in purl_rows {
        let key = PurlKey {
            ty: interner.intern(row.purl_type),
            namespace: interner.intern_opt(row.purl_namespace),
            name: interner.intern(row.purl_name),
        };
        patches
            .entry(row.advisory_id)
            .or_default()
            .purl_statuses
            .entry(key)
            .or_default()
            .push(PurlStatusEntry {
                purl_status_id: row.purl_status_id,
                advisory_id: row.advisory_id,
                vulnerability_id: interner.intern(row.vulnerability_id),
                status_id: row.status_id,
                version_range: build_version_range(
                    &mut interner,
                    row.version_scheme_id,
                    row.low_version,
                    row.low_inclusive.unwrap_or(true),
                    row.high_version,
                    row.high_inclusive.unwrap_or(false),
                ),
                context_cpe_id: row.context_cpe_id,
            });
    }

    for row in product_rows {
        if let Some(pkg) = row.package {
            patches
                .entry(row.advisory_id)
                .or_default()
                .product_statuses
                .entry(interner.intern(pkg))
                .or_default()
                .push(ProductStatusEntry {
                    product_status_id: row.id,
                    advisory_id: row.advisory_id,
                    vulnerability_id: interner.intern(row.vulnerability_id),
                    status_id: row.status_id,
                    context_cpe_id: row.context_cpe_id,
                });
        }
    }

    // Load severity data for these advisories
    let severity_rows = advisory_vulnerability_score::Entity::find()
        .filter(advisory_vulnerability_score::Column::AdvisoryId.is_in(ids.iter().copied()))
        .select_only()
        .column(advisory_vulnerability_score::Column::AdvisoryId)
        .column(advisory_vulnerability_score::Column::VulnerabilityId)
        .column(advisory_vulnerability_score::Column::Severity)
        .into_model::<SeverityRow>()
        .all(txn)
        .instrument(info_span!("load advisory severity patches"))
        .await?;

    for row in severity_rows {
        let vuln_id = interner.intern(row.vulnerability_id);
        let affected = crate::model::severity_to_affected(row.severity);
        let patch = patches.entry(row.advisory_id).or_default();
        patch
            .severity
            .entry((row.advisory_id, vuln_id))
            .and_modify(|existing| {
                if affected > *existing {
                    *existing = affected;
                }
            })
            .or_insert(affected);
    }

    Ok(patches)
}

/// Loads SBOM patches for a batch of SBOM IDs.
///
/// Returns one SbomPatch per SBOM that has data. Uses SeaORM query builder
/// for packages and raw SQL for the CPE CTE query.
#[instrument(skip_all, fields(count = ids.len()), err(level = tracing::Level::INFO))]
pub(crate) async fn load_sbom_patches(
    ids: &[Uuid],
    txn: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, SbomPatch>, anyhow::Error> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut interner = StringInterner::new();

    let pkg_rows: Vec<(sbom_node_purl_ref::Model, Option<qualified_purl::Model>)> =
        sbom_node_purl_ref::Entity::find()
            .filter(sbom_node_purl_ref::Column::SbomId.is_in(ids.iter().copied()))
            .find_also_related(qualified_purl::Entity)
            .all(txn)
            .instrument(info_span!("load sbom package patches"))
            .await?;

    let placeholders = build_placeholders(ids.len());
    let values: Vec<sea_orm::Value> = ids.iter().copied().map(Into::into).collect();

    let cpe_rows = SbomCpeRow::find_by_statement(sea_orm::Statement::from_sql_and_values(
        sea_orm::DatabaseBackend::Postgres,
        format!(
            r#"
            WITH filtered AS (
                SELECT sdc.sbom_id, cpe.id AS cpe_id, cpe.vendor, cpe.product, cpe.version
                FROM sbom_describing_cpe sdc
                JOIN cpe ON sdc.cpe_id = cpe.id
                WHERE sdc.sbom_id IN ({placeholders})
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
            "#,
        ),
        values,
    ))
    .all(txn)
    .instrument(info_span!("load sbom cpe patches"))
    .await?;

    let mut patches: HashMap<Uuid, SbomPatch> = HashMap::new();

    for (snpr, qp_opt) in pkg_rows {
        if let Some(qp) = qp_opt
            && let Some(version) = qp.purl.version
            && !version.is_empty()
        {
            patches
                .entry(snpr.sbom_id)
                .or_default()
                .packages
                .push(SbomPackageEntry {
                    ty: interner.intern(qp.purl.ty),
                    name: interner.intern(qp.purl.name),
                    namespace: interner.intern_opt(qp.purl.namespace),
                    version: interner.intern(version),
                });
        }
    }

    for row in cpe_rows {
        patches
            .entry(row.sbom_id)
            .or_default()
            .describing_cpes
            .insert(row.cpe_id);
    }

    Ok(patches)
}

/// Loads max severity per (advisory_id, vulnerability_id) from advisory_vulnerability_score.
///
/// For each pair, keeps the highest severity using the CVSS ranking order.
async fn load_severity_index(
    interner: &mut StringInterner,
    txn: &(impl ConnectionTrait + StreamTrait),
) -> Result<SeverityIndex, anyhow::Error> {
    let mut severity: SeverityIndex = HashMap::new();

    let mut stream = advisory_vulnerability_score::Entity::find()
        .select_only()
        .column(advisory_vulnerability_score::Column::AdvisoryId)
        .column(advisory_vulnerability_score::Column::VulnerabilityId)
        .column(advisory_vulnerability_score::Column::Severity)
        .into_model::<SeverityRow>()
        .stream(txn)
        .await?;

    while let Some(row) = stream.try_next().await? {
        let vuln_id = interner.intern(row.vulnerability_id);
        let affected = crate::model::severity_to_affected(row.severity);
        let key = (row.advisory_id, vuln_id);
        severity
            .entry(key)
            .and_modify(|existing| {
                if affected > *existing {
                    *existing = affected;
                }
            })
            .or_insert(affected);
    }
    drop(stream);

    Ok(severity)
}

/// Builds the reverse vulnerability index from the purl and product indexes.
fn build_vulnerability_index(
    by_purl: &HashMap<PurlKey, Vec<PurlStatusEntry>>,
    product_by_name: &HashMap<Arc<str>, Vec<ProductStatusEntry>>,
) -> HashMap<Arc<str>, Vec<VulnIndexEntry>> {
    let mut by_vulnerability: HashMap<Arc<str>, Vec<VulnIndexEntry>> = HashMap::new();

    for (purl_key, entries) in by_purl {
        for entry in entries {
            by_vulnerability
                .entry(Arc::clone(&entry.vulnerability_id))
                .or_default()
                .push(VulnIndexEntry {
                    advisory_id: entry.advisory_id,
                    status_id: entry.status_id,
                    context_cpe_id: entry.context_cpe_id,
                    source: VulnEntrySource::Purl {
                        purl_key: purl_key.clone(),
                        version_range: entry.version_range.clone(),
                    },
                });
        }
    }

    for (package_name, entries) in product_by_name {
        for entry in entries {
            by_vulnerability
                .entry(Arc::clone(&entry.vulnerability_id))
                .or_default()
                .push(VulnIndexEntry {
                    advisory_id: entry.advisory_id,
                    status_id: entry.status_id,
                    context_cpe_id: entry.context_cpe_id,
                    source: VulnEntrySource::Product {
                        package_name: Arc::clone(package_name),
                    },
                });
        }
    }

    by_vulnerability
}

/// Builds a comma-separated placeholder list ($1, $2, ..., $n) for raw SQL queries.
fn build_placeholders(count: usize) -> String {
    (1..=count)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Builds a `VersionRangeData` with pre-parsed semver boundaries when applicable.
fn build_version_range(
    interner: &mut StringInterner,
    scheme: VersionScheme,
    low_version: Option<String>,
    low_inclusive: bool,
    high_version: Option<String>,
    high_inclusive: bool,
) -> VersionRangeData {
    let (low_parsed, high_parsed) = if is_semver_family(scheme) {
        (
            low_version
                .as_deref()
                .and_then(|v| lenient_semver::parse(v).ok()),
            high_version
                .as_deref()
                .and_then(|v| lenient_semver::parse(v).ok()),
        )
    } else {
        (None, None)
    };

    VersionRangeData {
        version_scheme: scheme,
        low_version: interner.intern_opt(low_version),
        low_inclusive,
        high_version: interner.intern_opt(high_version),
        high_inclusive,
        low_parsed,
        high_parsed,
    }
}

/// Returns true for version schemes that use semver-style comparison.
fn is_semver_family(scheme: VersionScheme) -> bool {
    matches!(
        scheme,
        VersionScheme::Semver
            | VersionScheme::Npm
            | VersionScheme::Gem
            | VersionScheme::NuGet
            | VersionScheme::Packagist
            | VersionScheme::Hex
            | VersionScheme::Swift
            | VersionScheme::Pub
            | VersionScheme::Cargo
            | VersionScheme::Golang
    )
}
