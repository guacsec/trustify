/// In-memory read-optimized index over advisory status assertions.
///
/// Loaded from `purl_status`, `cpe_status`, and `product_status` tables.
/// Provides O(1) lookup by PURL identity, CPE identity, product name,
/// and vulnerability ID. Used by the correlation engine to avoid the
/// multi-join SQL queries that are the primary performance bottleneck.
use std::collections::HashMap;
use tracing::{info, instrument};
use trustify_common::version::{VersionRange, VersionScheme};
use uuid::Uuid;

/// A single advisory status assertion about a vulnerability affecting
/// packages matching a specific identity and version range.
#[derive(Debug, Clone)]
pub struct StatusEntry {
    /// FK to the advisory that made this assertion.
    pub advisory_id: Uuid,
    /// The vulnerability identifier (e.g., "CVE-2024-1234").
    pub vulnerability_id: String,
    /// FK to the status value (affected, fixed, not_affected, etc.).
    pub status_id: Uuid,
    /// The status slug for fast filtering without a DB lookup.
    pub status_slug: String,
    /// Version range this assertion applies to.
    pub version_range: VersionRange,
    /// Optional context CPE scoping (NULL = universally applicable).
    pub context_cpe: Option<ContextCpe>,
}

/// Context CPE data for scoping, extracted from the `cpe` table.
#[derive(Debug, Clone)]
pub struct ContextCpe {
    pub cpe_id: Uuid,
    pub vendor: String,
    pub product: String,
    pub version: String,
}

/// Key for PURL-based lookups: (type, namespace, name) — matches `base_purl`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BasePurlKey {
    pub ty: String,
    pub namespace: Option<String>,
    pub name: String,
}

/// Key for CPE-based lookups: (vendor, product) where part = 'a'.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CpeKey {
    pub vendor: String,
    pub product: String,
}

/// The in-memory advisory index.
///
/// Each map contains all non-deprecated status assertions from the
/// database, keyed by the identity dimension used for lookup.
#[derive(Debug, Clone)]
pub struct AdvisoryIndex {
    /// PURL identity → status entries (from `purl_status` table).
    pub by_purl: HashMap<BasePurlKey, Vec<StatusEntry>>,

    /// CPE identity → status entries (from `cpe_status` table).
    pub by_cpe: HashMap<CpeKey, Vec<StatusEntry>>,

    /// Product name → status entries (from `product_status` table).
    /// Both bare name and `namespace/name` forms are indexed.
    pub by_product_name: HashMap<String, Vec<StatusEntry>>,

    /// Vulnerability ID → indices into the other maps.
    /// Used for Direction B (given a vuln, find candidate SBOMs).
    pub by_vuln: HashMap<String, Vec<VulnEntry>>,
}

/// A reference from a vulnerability to a status entry, recording
/// which index map and key the entry lives under.
#[derive(Debug, Clone)]
pub struct VulnEntry {
    pub advisory_id: Uuid,
    pub status_id: Uuid,
    pub status_slug: String,
    pub match_source: MatchSource,
}

/// Which index map a status entry came from.
#[derive(Debug, Clone)]
pub enum MatchSource {
    Purl(BasePurlKey),
    Cpe(CpeKey),
    ProductName(String),
}

impl AdvisoryIndex {
    /// Build an empty index.
    pub fn empty() -> Self {
        Self {
            by_purl: HashMap::new(),
            by_cpe: HashMap::new(),
            by_product_name: HashMap::new(),
            by_vuln: HashMap::new(),
        }
    }

    /// Load the advisory index from the database.
    ///
    /// Queries `purl_status`, `cpe_status`, and `product_status` tables
    /// with their associated `version_range`, `status`, `advisory`, and
    /// `cpe` data. Only non-deprecated advisories are included.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn load<C: sea_orm::ConnectionTrait>(
        connection: &C,
    ) -> Result<Self, anyhow::Error> {
        let mut index = Self::empty();

        let purl_count = load_purl_statuses(&mut index, connection).await?;
        let cpe_count = load_cpe_statuses(&mut index, connection).await?;
        let product_count = load_product_statuses(&mut index, connection).await?;

        info!(
            purl_entries = purl_count,
            cpe_entries = cpe_count,
            product_entries = product_count,
            vuln_entries = index.by_vuln.len(),
            "advisory index loaded"
        );

        Ok(index)
    }

    /// Register a status entry in the `by_vuln` secondary index.
    fn index_by_vuln(&mut self, entry: &StatusEntry, source: MatchSource) {
        self.by_vuln
            .entry(entry.vulnerability_id.clone())
            .or_default()
            .push(VulnEntry {
                advisory_id: entry.advisory_id,
                status_id: entry.status_id,
                status_slug: entry.status_slug.clone(),
                match_source: source,
            });
    }
}

/// Load `purl_status` entries into the index.
async fn load_purl_statuses<C: sea_orm::ConnectionTrait>(
    index: &mut AdvisoryIndex,
    connection: &C,
) -> Result<usize, anyhow::Error> {
    use sea_orm::{FromQueryResult, Statement};

    #[derive(Debug, FromQueryResult)]
    struct Row {
        advisory_id: Uuid,
        vulnerability_id: String,
        status_id: Uuid,
        status_slug: String,
        purl_type: String,
        purl_namespace: Option<String>,
        purl_name: String,
        version_scheme_id: String,
        low_version: Option<String>,
        low_inclusive: Option<bool>,
        high_version: Option<String>,
        high_inclusive: Option<bool>,
        context_cpe_id: Option<Uuid>,
        cpe_vendor: Option<String>,
        cpe_product: Option<String>,
        cpe_version: Option<String>,
    }

    let rows: Vec<Row> = Row::find_by_statement(Statement::from_string(
        sea_orm::DatabaseBackend::Postgres,
        r#"
        SELECT
            ps.advisory_id,
            ps.vulnerability_id,
            ps.status_id,
            s.slug AS status_slug,
            bp.type AS purl_type,
            bp.namespace AS purl_namespace,
            bp.name AS purl_name,
            vr.version_scheme_id,
            vr.low_version,
            vr.low_inclusive,
            vr.high_version,
            vr.high_inclusive,
            ps.context_cpe_id,
            c.vendor AS cpe_vendor,
            c.product AS cpe_product,
            c.version AS cpe_version
        FROM purl_status ps
        JOIN status s ON ps.status_id = s.id
        JOIN base_purl bp ON ps.base_purl_id = bp.id
        JOIN version_range vr ON ps.version_range_id = vr.id
        JOIN advisory a ON ps.advisory_id = a.id AND a.deprecated = false
        LEFT JOIN cpe c ON ps.context_cpe_id = c.id
        "#
        .to_string(),
    ))
    .all(connection)
    .await?;

    let count = rows.len();

    for row in rows {
        let scheme = match VersionScheme::from_db_str(&row.version_scheme_id) {
            Some(s) => s,
            None => continue,
        };

        let context_cpe = match (row.context_cpe_id, row.cpe_vendor, row.cpe_product) {
            (Some(id), Some(vendor), Some(product)) => Some(ContextCpe {
                cpe_id: id,
                vendor,
                product,
                version: row.cpe_version.unwrap_or_default(),
            }),
            _ => None,
        };

        let entry = StatusEntry {
            advisory_id: row.advisory_id,
            vulnerability_id: row.vulnerability_id.clone(),
            status_id: row.status_id,
            status_slug: row.status_slug,
            version_range: VersionRange {
                scheme,
                low_version: row.low_version,
                low_inclusive: row.low_inclusive.unwrap_or(false),
                high_version: row.high_version,
                high_inclusive: row.high_inclusive.unwrap_or(false),
            },
            context_cpe,
        };

        let key = BasePurlKey {
            ty: row.purl_type,
            namespace: row.purl_namespace,
            name: row.purl_name,
        };

        index.index_by_vuln(&entry, MatchSource::Purl(key.clone()));
        index.by_purl.entry(key).or_default().push(entry);
    }

    Ok(count)
}

/// Load `cpe_status` entries into the index.
async fn load_cpe_statuses<C: sea_orm::ConnectionTrait>(
    index: &mut AdvisoryIndex,
    connection: &C,
) -> Result<usize, anyhow::Error> {
    use sea_orm::{FromQueryResult, Statement};

    #[derive(Debug, FromQueryResult)]
    struct Row {
        advisory_id: Uuid,
        vulnerability_id: String,
        status_id: Uuid,
        status_slug: String,
        cpe_vendor: String,
        cpe_product: String,
        version_scheme_id: String,
        low_version: Option<String>,
        low_inclusive: Option<bool>,
        high_version: Option<String>,
        high_inclusive: Option<bool>,
    }

    let rows: Vec<Row> = Row::find_by_statement(Statement::from_string(
        sea_orm::DatabaseBackend::Postgres,
        r#"
        SELECT
            cs.advisory_id,
            cs.vulnerability_id,
            cs.status_id,
            s.slug AS status_slug,
            c.vendor AS cpe_vendor,
            c.product AS cpe_product,
            vr.version_scheme_id,
            vr.low_version,
            vr.low_inclusive,
            vr.high_version,
            vr.high_inclusive
        FROM cpe_status cs
        JOIN status s ON cs.status_id = s.id
        JOIN cpe c ON cs.cpe_id = c.id AND c.part = 'a'
        JOIN version_range vr ON cs.version_range_id = vr.id
        JOIN advisory a ON cs.advisory_id = a.id AND a.deprecated = false
        "#
        .to_string(),
    ))
    .all(connection)
    .await?;

    let count = rows.len();

    for row in rows {
        let scheme = match VersionScheme::from_db_str(&row.version_scheme_id) {
            Some(s) => s,
            None => continue,
        };

        let entry = StatusEntry {
            advisory_id: row.advisory_id,
            vulnerability_id: row.vulnerability_id.clone(),
            status_id: row.status_id,
            status_slug: row.status_slug,
            version_range: VersionRange {
                scheme,
                low_version: row.low_version,
                low_inclusive: row.low_inclusive.unwrap_or(false),
                high_version: row.high_version,
                high_inclusive: row.high_inclusive.unwrap_or(false),
            },
            context_cpe: None,
        };

        let key = CpeKey {
            vendor: row.cpe_vendor,
            product: row.cpe_product,
        };

        index.index_by_vuln(&entry, MatchSource::Cpe(key.clone()));
        index.by_cpe.entry(key).or_default().push(entry);
    }

    Ok(count)
}

/// Load `product_status` entries into the index.
async fn load_product_statuses<C: sea_orm::ConnectionTrait>(
    index: &mut AdvisoryIndex,
    connection: &C,
) -> Result<usize, anyhow::Error> {
    use sea_orm::{FromQueryResult, Statement};

    #[derive(Debug, FromQueryResult)]
    struct Row {
        advisory_id: Uuid,
        vulnerability_id: String,
        status_id: Uuid,
        status_slug: String,
        package: String,
        version_scheme_id: String,
        low_version: Option<String>,
        low_inclusive: Option<bool>,
        high_version: Option<String>,
        high_inclusive: Option<bool>,
        context_cpe_id: Option<Uuid>,
        cpe_vendor: Option<String>,
        cpe_product: Option<String>,
        cpe_version: Option<String>,
    }

    let rows: Vec<Row> = Row::find_by_statement(Statement::from_string(
        sea_orm::DatabaseBackend::Postgres,
        r#"
        SELECT
            ps.advisory_id,
            ps.vulnerability_id,
            ps.status_id,
            s.slug AS status_slug,
            ps.package,
            vr.version_scheme_id,
            vr.low_version,
            vr.low_inclusive,
            vr.high_version,
            vr.high_inclusive,
            ps.context_cpe_id,
            c.vendor AS cpe_vendor,
            c.product AS cpe_product,
            c.version AS cpe_version
        FROM product_status ps
        JOIN status s ON ps.status_id = s.id
        JOIN product_version_range pvr ON ps.product_version_range_id = pvr.id
        JOIN version_range vr ON pvr.version_range_id = vr.id
        JOIN advisory a ON ps.advisory_id = a.id AND a.deprecated = false
        LEFT JOIN cpe c ON ps.context_cpe_id = c.id
        WHERE ps.package IS NOT NULL
        "#
        .to_string(),
    ))
    .all(connection)
    .await?;

    let count = rows.len();

    for row in rows {
        let scheme = match VersionScheme::from_db_str(&row.version_scheme_id) {
            Some(s) => s,
            None => continue,
        };

        let context_cpe = match (row.context_cpe_id, row.cpe_vendor, row.cpe_product) {
            (Some(id), Some(vendor), Some(product)) => Some(ContextCpe {
                cpe_id: id,
                vendor,
                product,
                version: row.cpe_version.unwrap_or_default(),
            }),
            _ => None,
        };

        let entry = StatusEntry {
            advisory_id: row.advisory_id,
            vulnerability_id: row.vulnerability_id.clone(),
            status_id: row.status_id,
            status_slug: row.status_slug,
            version_range: VersionRange {
                scheme,
                low_version: row.low_version,
                low_inclusive: row.low_inclusive.unwrap_or(false),
                high_version: row.high_version,
                high_inclusive: row.high_inclusive.unwrap_or(false),
            },
            context_cpe,
        };

        let name = row.package;
        index.index_by_vuln(&entry, MatchSource::ProductName(name.clone()));
        index
            .by_product_name
            .entry(name)
            .or_default()
            .push(entry);
    }

    Ok(count)
}
