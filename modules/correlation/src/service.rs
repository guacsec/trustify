/// Correlation service: matches SBOM packages against advisory status
/// assertions using the in-memory advisory index and the existing
/// graph cache for SBOM data.
use crate::advisory_index::{AdvisoryIndex, BasePurlKey, CpeKey, ContextCpe, StatusEntry};
use arc_swap::ArcSwap;
use petgraph::visit::EdgeRef;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, instrument};
use trustify_common::version;
use trustify_module_analysis::model::graph;
use trustify_module_analysis::service::AnalysisService;
use uuid::Uuid;

/// A single correlation match: a package in an SBOM matched an advisory
/// status assertion via a specific matching strategy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CorrelationMatch {
    /// The SBOM that contains the matched package.
    pub sbom_id: Uuid,
    /// The node ID of the matched package within the SBOM.
    pub node_id: String,
    /// The advisory that asserted this status.
    pub advisory_id: Uuid,
    /// The vulnerability identifier.
    pub vulnerability_id: String,
    /// The status assertion ID.
    pub status_id: Uuid,
    /// The status slug (affected, fixed, not_affected, etc.).
    pub status_slug: String,
    /// Which matching strategy produced this match.
    pub match_kind: MatchKind,
}

/// How a match was established.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MatchKind {
    /// Matched via PURL identity + version range.
    Purl,
    /// Matched via CPE identity (vendor/product) + version range.
    Cpe,
    /// Matched via product name + version range.
    ProductName,
}

/// Generalized describing CPE for context scoping.
///
/// Extracted from the SBOM's root node and expanded to
/// `(vendor, product, major_version)` triples.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DescribingCpe {
    vendor: String,
    product: String,
    major_version: String,
}

/// The correlation service orchestrates in-memory matching.
#[derive(Clone)]
pub struct CorrelationService {
    /// The advisory index, atomically swappable for live reloads.
    index: Arc<ArcSwap<AdvisoryIndex>>,
    /// The existing graph cache for SBOM package data.
    analysis: AnalysisService,
}

impl CorrelationService {
    /// Create a new correlation service with an empty index.
    ///
    /// Call [`load_index`] to populate from the database.
    pub fn new(analysis: AnalysisService) -> Self {
        Self {
            index: Arc::new(ArcSwap::from_pointee(AdvisoryIndex::empty())),
            analysis,
        }
    }

    /// Get a snapshot of the current advisory index.
    pub fn index(&self) -> arc_swap::Guard<Arc<AdvisoryIndex>> {
        self.index.load()
    }

    /// Load (or reload) the advisory index from the database.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn load_index<C: sea_orm::ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<(), anyhow::Error> {
        let index = AdvisoryIndex::load(connection).await?;
        self.index.store(Arc::new(index));
        info!("advisory index reloaded");
        Ok(())
    }

    /// Direction A: given an SBOM, find all matching advisory status assertions.
    ///
    /// Loads the SBOM's graph from the cache, iterates its packages, and
    /// matches each against the advisory index using PURL identity, CPE
    /// identity, and product name strategies. Applies context CPE scoping.
    #[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
    pub async fn correlate_sbom<C: sea_orm::ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        status_filter: &[&str],
        connection: &C,
    ) -> Result<Vec<CorrelationMatch>, anyhow::Error> {
        // Load the SBOM graph from the analysis cache.
        let graph = self
            .analysis
            .load_graph(connection, sbom_id)
            .await
            .map_err(|e| anyhow::anyhow!("failed to load SBOM graph {sbom_id}: {e}"))?;

        let index = self.index.load();

        // Extract describing CPEs from the graph's root node for context scoping.
        let describing_cpes = extract_describing_cpes(&graph);

        let mut matches = Vec::new();
        let mut seen = HashSet::new();

        // Iterate all package nodes in the graph.
        for node_idx in graph.node_indices() {
            let node = &graph[node_idx];
            let graph::Node::Package(pkg) = node else {
                continue;
            };

            let version = &pkg.version;
            let name = &pkg.name;

            // Strategy 1: PURL identity + version range
            for purl in pkg.purl.iter() {
                let key = BasePurlKey {
                    ty: purl.ty.clone(),
                    namespace: purl.namespace.clone(),
                    name: purl.name.clone(),
                };

                if let Some(entries) = index.by_purl.get(&key) {
                    collect_matches(
                        entries,
                        version,
                        &describing_cpes,
                        status_filter,
                        sbom_id,
                        &pkg.base.node_id,
                        MatchKind::Purl,
                        &mut matches,
                        &mut seen,
                    );
                }
            }

            // Strategy 2: CPE identity + version range
            for cpe in pkg.cpe.iter() {
                let key = CpeKey {
                    vendor: cpe.vendor().to_string(),
                    product: cpe.product().to_string(),
                };

                if let Some(entries) = index.by_cpe.get(&key) {
                    // For CPE matches, use the CPE's version if not wildcard,
                    // otherwise fall back to the package version.
                    let cpe_version = cpe.version().to_string();
                    let effective_version = if cpe_version == "*" || cpe_version.is_empty() {
                        version.as_str()
                    } else {
                        &cpe_version
                    };

                    collect_matches_no_context(
                        entries,
                        effective_version,
                        status_filter,
                        sbom_id,
                        &pkg.base.node_id,
                        MatchKind::Cpe,
                        &mut matches,
                        &mut seen,
                    );
                }
            }

            // Strategy 3: Product name matching
            // Try both bare name and namespace/name forms.
            let name_keys: Vec<String> = {
                let mut keys = vec![name.clone()];
                // Also try namespace/name for each PURL
                for purl in pkg.purl.iter() {
                    if let Some(ref ns) = purl.namespace {
                        keys.push(format!("{ns}/{}", purl.name));
                    }
                }
                keys
            };

            for name_key in &name_keys {
                if let Some(entries) = index.by_product_name.get(name_key) {
                    collect_matches(
                        entries,
                        version,
                        &describing_cpes,
                        status_filter,
                        sbom_id,
                        &pkg.base.node_id,
                        MatchKind::ProductName,
                        &mut matches,
                        &mut seen,
                    );
                }
            }
        }

        Ok(matches)
    }

    /// Direction B: given a vulnerability ID, find all SBOMs that match.
    ///
    /// Looks up the advisory index for all status entries mentioning the
    /// vulnerability, queries the DB for candidate SBOMs, then verifies
    /// each candidate against the graph cache using the same matching
    /// logic as Direction A.
    #[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
    pub async fn correlate_vuln<C: sea_orm::ConnectionTrait>(
        &self,
        vulnerability_id: &str,
        status_filter: &[&str],
        connection: &C,
    ) -> Result<Vec<CorrelationMatch>, anyhow::Error> {
        use sea_orm::{FromQueryResult, Statement};

        let index = self.index.load();

        let vuln_entries = match index.by_vuln.get(vulnerability_id) {
            Some(entries) => entries,
            None => return Ok(Vec::new()),
        };

        // Collect all unique purl keys, cpe keys, and product names
        // from the vulnerability's status entries to find candidate SBOMs.
        let mut purl_keys: Vec<&BasePurlKey> = Vec::new();
        let mut cpe_keys: Vec<&CpeKey> = Vec::new();
        let mut product_names: Vec<&str> = Vec::new();

        for entry in vuln_entries {
            if !status_filter.is_empty() && !status_filter.contains(&entry.status_slug.as_str()) {
                continue;
            }
            match &entry.match_source {
                crate::advisory_index::MatchSource::Purl(key) => purl_keys.push(key),
                crate::advisory_index::MatchSource::Cpe(key) => cpe_keys.push(key),
                crate::advisory_index::MatchSource::ProductName(name) => {
                    product_names.push(name.as_str())
                }
            }
        }

        // Query candidate SBOM IDs from the database.
        // This is a set of indexed lookups, not the full multi-join.
        let mut candidate_sbom_ids: HashSet<Uuid> = HashSet::new();

        // Find SBOMs containing matching PURLs.
        if !purl_keys.is_empty() {
            let types: Vec<String> = purl_keys.iter().map(|k| k.ty.clone()).collect();
            let names: Vec<String> = purl_keys.iter().map(|k| k.name.clone()).collect();

            #[derive(Debug, FromQueryResult)]
            struct SbomId {
                sbom_id: Uuid,
            }

            let rows: Vec<SbomId> = SbomId::find_by_statement(
                Statement::from_sql_and_values(
                    sea_orm::DatabaseBackend::Postgres,
                    r#"
                    SELECT DISTINCT snpr.sbom_id
                    FROM sbom_node_purl_ref snpr
                    JOIN qualified_purl qp ON snpr.qualified_purl_id = qp.id
                    JOIN versioned_purl vp ON qp.versioned_purl_id = vp.id
                    JOIN base_purl bp ON vp.base_purl_id = bp.id
                    WHERE bp.type = ANY($1) AND bp.name = ANY($2)
                    "#,
                    [types.into(), names.into()],
                ),
            )
            .all(connection)
            .await?;

            for row in rows {
                candidate_sbom_ids.insert(row.sbom_id);
            }
        }

        // Find SBOMs containing matching CPEs.
        if !cpe_keys.is_empty() {
            let vendors: Vec<String> = cpe_keys.iter().map(|k| k.vendor.clone()).collect();
            let products: Vec<String> = cpe_keys.iter().map(|k| k.product.clone()).collect();

            #[derive(Debug, FromQueryResult)]
            struct SbomId {
                sbom_id: Uuid,
            }

            let rows: Vec<SbomId> = SbomId::find_by_statement(
                Statement::from_sql_and_values(
                    sea_orm::DatabaseBackend::Postgres,
                    r#"
                    SELECT DISTINCT sncr.sbom_id
                    FROM sbom_node_cpe_ref sncr
                    JOIN cpe c ON sncr.cpe_id = c.id
                    WHERE c.vendor = ANY($1) AND c.product = ANY($2) AND c.part = 'a'
                    "#,
                    [vendors.into(), products.into()],
                ),
            )
            .all(connection)
            .await?;

            for row in rows {
                candidate_sbom_ids.insert(row.sbom_id);
            }
        }

        // Find SBOMs containing matching product names.
        if !product_names.is_empty() {
            let names: Vec<String> = product_names.iter().map(|s| s.to_string()).collect();

            #[derive(Debug, FromQueryResult)]
            struct SbomId {
                sbom_id: Uuid,
            }

            let rows: Vec<SbomId> = SbomId::find_by_statement(
                Statement::from_sql_and_values(
                    sea_orm::DatabaseBackend::Postgres,
                    r#"
                    SELECT DISTINCT sp.sbom_id
                    FROM sbom_package sp
                    JOIN sbom_node sn ON sp.sbom_id = sn.sbom_id AND sp.node_id = sn.node_id
                    WHERE sn.name = ANY($1)
                    "#,
                    [names.into()],
                ),
            )
            .all(connection)
            .await?;

            for row in rows {
                candidate_sbom_ids.insert(row.sbom_id);
            }
        }

        // For each candidate SBOM, run the same matching logic as Direction A.
        let mut all_matches = Vec::new();
        for sbom_id in candidate_sbom_ids {
            match self
                .correlate_sbom(sbom_id, status_filter, connection)
                .await
            {
                Ok(mut sbom_matches) => {
                    // Filter to only matches for this vulnerability.
                    sbom_matches.retain(|m| m.vulnerability_id == vulnerability_id);
                    all_matches.append(&mut sbom_matches);
                }
                Err(e) => {
                    tracing::warn!(
                        sbom_id = %sbom_id,
                        error = %e,
                        "failed to correlate candidate SBOM, skipping"
                    );
                }
            }
        }

        Ok(all_matches)
    }
}

/// Extract describing CPEs from the SBOM graph's root node.
///
/// The root node is identified by DESCRIBES relationships. Its CPEs
/// are generalized to `(vendor, product, major_version)` triples.
fn extract_describing_cpes(
    graph: &trustify_module_analysis::model::PackageGraph,
) -> Vec<DescribingCpe> {
    use trustify_entity::relationship::Relationship;

    let mut cpes = Vec::new();

    for edge in graph.edge_references() {
        if *edge.weight() != Relationship::Describes {
            continue;
        }
        let source_node = &graph[edge.source()];
        if let graph::Node::Package(pkg) = source_node {
            for cpe in pkg.cpe.iter() {
                let version_str = cpe.version().to_string();
                let major = version_str
                    .split('.')
                    .next()
                    .unwrap_or(&version_str)
                    .to_string();
                cpes.push(DescribingCpe {
                    vendor: cpe.vendor().to_string(),
                    product: cpe.product().to_string(),
                    major_version: major,
                });
            }
        }

        // Also check the target node (the described package may have CPEs)
        let target_node = &graph[edge.target()];
        if let graph::Node::Package(pkg) = target_node {
            for cpe in pkg.cpe.iter() {
                let version_str = cpe.version().to_string();
                let major = version_str
                    .split('.')
                    .next()
                    .unwrap_or(&version_str)
                    .to_string();
                cpes.push(DescribingCpe {
                    vendor: cpe.vendor().to_string(),
                    product: cpe.product().to_string(),
                    major_version: major,
                });
            }
        }
    }

    cpes
}

/// Check if a status entry's context CPE matches the SBOM's describing CPEs.
///
/// Implements the unified scoping rule from ADR 00021:
/// - NULL context → universal (always matches)
/// - Matches if vendor/product/major_version align with any describing CPE
/// - SBOM with no describing CPEs → matches everything (unscoped)
fn context_cpe_matches(
    context: &Option<ContextCpe>,
    describing: &[DescribingCpe],
) -> bool {
    let Some(ctx) = context else {
        // NULL context = universally applicable
        return true;
    };

    if describing.is_empty() {
        // Unscoped SBOM = matches everything
        return true;
    }

    let ctx_major = ctx
        .version
        .split('.')
        .next()
        .unwrap_or(&ctx.version);

    describing.iter().any(|d| {
        d.vendor == ctx.vendor && d.product == ctx.product && d.major_version == ctx_major
    })
}

/// Collect matches from status entries, applying version matching,
/// context CPE scoping, and status filtering.
#[allow(clippy::too_many_arguments)]
fn collect_matches(
    entries: &[StatusEntry],
    version: &str,
    describing_cpes: &[DescribingCpe],
    status_filter: &[&str],
    sbom_id: Uuid,
    node_id: &str,
    match_kind: MatchKind,
    matches: &mut Vec<CorrelationMatch>,
    seen: &mut HashSet<(Uuid, String, Uuid, String)>,
) {
    for entry in entries {
        // Status filter
        if !status_filter.is_empty() && !status_filter.contains(&entry.status_slug.as_str()) {
            continue;
        }

        // Context CPE scoping
        if !context_cpe_matches(&entry.context_cpe, describing_cpes) {
            continue;
        }

        // Version matching
        if !version::version_matches(version, &entry.version_range) {
            continue;
        }

        // Dedup key: (advisory_id, vulnerability_id, status_id, node_id)
        let dedup_key = (
            entry.advisory_id,
            entry.vulnerability_id.clone(),
            entry.status_id,
            node_id.to_string(),
        );
        if !seen.insert(dedup_key) {
            continue;
        }

        matches.push(CorrelationMatch {
            sbom_id,
            node_id: node_id.to_string(),
            advisory_id: entry.advisory_id,
            vulnerability_id: entry.vulnerability_id.clone(),
            status_id: entry.status_id,
            status_slug: entry.status_slug.clone(),
            match_kind: match_kind.clone(),
        });
    }
}

/// Collect matches without context CPE scoping (used for CPE identity
/// matches, where context scoping is deliberately omitted — see L5 in
/// ADR 00020).
#[allow(clippy::too_many_arguments)]
fn collect_matches_no_context(
    entries: &[StatusEntry],
    version: &str,
    status_filter: &[&str],
    sbom_id: Uuid,
    node_id: &str,
    match_kind: MatchKind,
    matches: &mut Vec<CorrelationMatch>,
    seen: &mut HashSet<(Uuid, String, Uuid, String)>,
) {
    for entry in entries {
        if !status_filter.is_empty() && !status_filter.contains(&entry.status_slug.as_str()) {
            continue;
        }

        if !version::version_matches(version, &entry.version_range) {
            continue;
        }

        let dedup_key = (
            entry.advisory_id,
            entry.vulnerability_id.clone(),
            entry.status_id,
            node_id.to_string(),
        );
        if !seen.insert(dedup_key) {
            continue;
        }

        matches.push(CorrelationMatch {
            sbom_id,
            node_id: node_id.to_string(),
            advisory_id: entry.advisory_id,
            vulnerability_id: entry.vulnerability_id.clone(),
            status_id: entry.status_id,
            status_slug: entry.status_slug.clone(),
            match_kind: match_kind.clone(),
        });
    }
}
