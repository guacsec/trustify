pub mod version;

use std::collections::{HashMap, HashSet};
use trustify_entity::version_scheme::VersionScheme;
use uuid::Uuid;

/// Version range data needed for in-memory version matching.
#[derive(Debug, Clone)]
pub struct VersionRangeData {
    pub version_scheme: VersionScheme,
    pub low_version: Option<String>,
    pub low_inclusive: bool,
    pub high_version: Option<String>,
    pub high_inclusive: bool,
}

/// A single purl_status entry stored in the advisory index.
#[derive(Debug, Clone)]
pub struct PurlStatusEntry {
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status_id: Uuid,
    pub version_range: VersionRangeData,
    pub context_cpe_id: Option<Uuid>,
}

/// A single product_status entry for name-based matching.
#[derive(Debug, Clone)]
pub struct ProductStatusEntry {
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status_id: Uuid,
    pub context_cpe_id: Option<Uuid>,
}

/// Advisory-side index: maps base_purl_id to vulnerability status entries.
#[derive(Debug, Clone)]
pub struct AdvisoryIndex {
    /// Primary lookup: base_purl_id → purl_status entries.
    pub by_base_purl: HashMap<Uuid, Vec<PurlStatusEntry>>,
    /// Product status lookup by package name (simple name match).
    pub product_by_name: HashMap<String, Vec<ProductStatusEntry>>,
    /// Status slugs by ID (affected, fixed, not_affected, etc.).
    pub statuses: HashMap<Uuid, String>,
    /// Set of deprecated advisory IDs for exclusion.
    pub deprecated_advisories: HashSet<Uuid>,
}

/// A package entry within an SBOM, storing only what's needed for matching.
#[derive(Debug, Clone)]
pub struct SbomPackageEntry {
    pub base_purl_id: Uuid,
    pub version: String,
    pub name: String,
    pub namespace: Option<String>,
}

/// SBOM-side index: maps sbom_id to its packages.
#[derive(Debug, Clone)]
pub struct SbomIndex {
    /// sbom_id → list of packages.
    pub by_sbom: HashMap<Uuid, Vec<SbomPackageEntry>>,
    /// Per-SBOM describing CPE IDs for context filtering.
    pub describing_cpes: HashMap<Uuid, HashSet<Uuid>>,
}

/// All in-memory state needed for correlation.
#[derive(Debug, Clone)]
pub struct CorrelationState {
    pub advisory_index: AdvisoryIndex,
    pub sbom_index: SbomIndex,
}

impl CorrelationState {
    /// Creates an empty state for use before the initial load completes.
    pub fn empty() -> Self {
        Self {
            advisory_index: AdvisoryIndex {
                by_base_purl: HashMap::new(),
                product_by_name: HashMap::new(),
                statuses: HashMap::new(),
                deprecated_advisories: HashSet::new(),
            },
            sbom_index: SbomIndex {
                by_sbom: HashMap::new(),
                describing_cpes: HashMap::new(),
            },
        }
    }
}

/// Result of the in-memory correlation phase (before DB hydration).
#[derive(Debug, Clone)]
pub struct CorrelationMatch {
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub status_id: Uuid,
    pub context_cpe_id: Option<Uuid>,
    pub base_purl_id: Uuid,
    pub version: String,
}
