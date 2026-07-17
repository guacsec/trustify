pub mod version;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use trustify_entity::version_scheme::VersionScheme;
use uuid::Uuid;

/// Composite key for matching purls between advisories and SBOMs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PurlKey {
    pub ty: Arc<str>,
    pub namespace: Option<Arc<str>>,
    pub name: Arc<str>,
}

/// Version range data needed for in-memory version matching.
///
/// For semver-family schemes, `low_parsed` and `high_parsed` hold pre-parsed
/// `semver::Version` values to avoid re-parsing on every comparison.
#[derive(Debug, Clone)]
pub struct VersionRangeData {
    pub version_scheme: VersionScheme,
    pub low_version: Option<Arc<str>>,
    pub low_inclusive: bool,
    pub high_version: Option<Arc<str>>,
    pub high_inclusive: bool,
    pub low_parsed: Option<semver::Version>,
    pub high_parsed: Option<semver::Version>,
}

/// A single purl_status entry stored in the advisory index.
#[derive(Debug, Clone)]
pub struct PurlStatusEntry {
    pub advisory_id: Uuid,
    pub vulnerability_id: Arc<str>,
    pub status_id: Uuid,
    pub version_range: VersionRangeData,
    pub context_cpe_id: Option<Uuid>,
}

/// A single product_status entry for name-based matching.
#[derive(Debug, Clone)]
pub struct ProductStatusEntry {
    pub advisory_id: Uuid,
    pub vulnerability_id: Arc<str>,
    pub status_id: Uuid,
    pub context_cpe_id: Option<Uuid>,
}

/// Loaded data for a single advisory, ready to apply to the index.
///
/// Deprecated advisories are filtered out at the SQL level and never appear here.
#[derive(Debug, Clone, Default)]
pub struct AdvisoryPatch {
    /// Purl status entries grouped by purl key.
    pub purl_statuses: HashMap<PurlKey, Vec<PurlStatusEntry>>,
    /// Product status entries grouped by package name.
    pub product_statuses: HashMap<Arc<str>, Vec<ProductStatusEntry>>,
}

/// Advisory-side index: maps purl key to vulnerability status entries.
///
/// Deprecated advisories are filtered out at the SQL level and never loaded.
#[derive(Debug, Clone)]
pub struct AdvisoryIndex {
    /// Primary lookup: (type, namespace, name) → purl_status entries.
    pub by_purl: HashMap<PurlKey, Vec<PurlStatusEntry>>,
    /// Product status lookup by package name (simple name match).
    pub product_by_name: HashMap<Arc<str>, Vec<ProductStatusEntry>>,
    /// Status slugs by ID (affected, fixed, not_affected, etc.).
    pub statuses: HashMap<Uuid, Arc<str>>,
}

impl AdvisoryIndex {
    /// Removes all entries belonging to a specific advisory.
    fn remove_advisory(&mut self, advisory_id: Uuid) {
        for entries in self.by_purl.values_mut() {
            entries.retain(|e| e.advisory_id != advisory_id);
        }
        self.by_purl.retain(|_, v| !v.is_empty());

        for entries in self.product_by_name.values_mut() {
            entries.retain(|e| e.advisory_id != advisory_id);
        }
        self.product_by_name.retain(|_, v| !v.is_empty());
    }

    /// Applies a patch: removes old data for this advisory, then inserts new data.
    pub fn apply_patch(&mut self, advisory_id: Uuid, patch: AdvisoryPatch) {
        self.remove_advisory(advisory_id);

        for (purl_key, entries) in patch.purl_statuses {
            self.by_purl.entry(purl_key).or_default().extend(entries);
        }

        for (package, entries) in patch.product_statuses {
            self.product_by_name
                .entry(package)
                .or_default()
                .extend(entries);
        }
    }
}

/// A package entry within an SBOM, storing only what's needed for matching.
#[derive(Debug, Clone)]
pub struct SbomPackageEntry {
    pub ty: Arc<str>,
    pub name: Arc<str>,
    pub namespace: Option<Arc<str>>,
    pub version: Arc<str>,
}

/// Deduplicated catalog of package entries, indexed by `u32`.
///
/// During initial load, entries are deduplicated by (ty, namespace, name, version)
/// so that the ~4M qualified_purl rows collapse to ~1.6M unique tuples. Per-SBOM
/// vectors store compact `u32` indices into this catalog instead of full structs.
#[derive(Debug, Clone)]
pub struct PackageCatalog {
    entries: Vec<SbomPackageEntry>,
}

impl PackageCatalog {
    /// Creates a catalog from a pre-built entry vector.
    pub fn from_entries(entries: Vec<SbomPackageEntry>) -> Self {
        Self { entries }
    }

    /// Returns the package entry at the given index.
    #[inline]
    pub fn get(&self, index: u32) -> &SbomPackageEntry {
        &self.entries[index as usize]
    }

    /// Returns the number of entries in the catalog.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the catalog has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Appends a new entry and returns its index.
    pub fn append(&mut self, entry: SbomPackageEntry) -> u32 {
        let idx = self.entries.len() as u32;
        self.entries.push(entry);
        idx
    }
}

/// Loaded data for a single SBOM, ready to apply to the index.
#[derive(Debug, Clone, Default)]
pub struct SbomPatch {
    /// Packages belonging to this SBOM.
    pub packages: Vec<SbomPackageEntry>,
    /// Describing CPE IDs for this SBOM.
    pub describing_cpes: HashSet<Uuid>,
}

/// SBOM-side index: maps sbom_id to catalog indices for its packages.
///
/// The `catalog` holds deduplicated package entries; each SBOM stores only
/// compact `u32` indices wrapped in `Arc<[u32]>` for cheap cloning.
#[derive(Debug, Clone)]
pub struct SbomIndex {
    /// Shared catalog of all known package entries.
    pub catalog: PackageCatalog,
    /// sbom_id → list of indices into `catalog`.
    pub by_sbom: HashMap<Uuid, Arc<[u32]>>,
    /// Per-SBOM describing CPE IDs for context filtering.
    pub describing_cpes: HashMap<Uuid, HashSet<Uuid>>,
}

impl SbomIndex {
    /// Applies a patch: replaces packages and CPEs for this SBOM.
    ///
    /// New package entries are appended to the catalog, and their indices are
    /// stored in the per-SBOM vector. If the patch is empty (deleted SBOM),
    /// the entries are removed.
    pub fn apply_patch(&mut self, sbom_id: Uuid, patch: SbomPatch) {
        if patch.packages.is_empty() {
            self.by_sbom.remove(&sbom_id);
        } else {
            let indices: Arc<[u32]> = patch
                .packages
                .into_iter()
                .map(|entry| self.catalog.append(entry))
                .collect::<Vec<u32>>()
                .into();
            self.by_sbom.insert(sbom_id, indices);
        }

        if patch.describing_cpes.is_empty() {
            self.describing_cpes.remove(&sbom_id);
        } else {
            self.describing_cpes.insert(sbom_id, patch.describing_cpes);
        }
    }
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
                by_purl: HashMap::new(),
                product_by_name: HashMap::new(),
                statuses: HashMap::new(),
            },
            sbom_index: SbomIndex {
                catalog: PackageCatalog::from_entries(Vec::new()),
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
    pub vulnerability_id: Arc<str>,
    pub status_id: Uuid,
    pub context_cpe_id: Option<Uuid>,
    pub purl_key: PurlKey,
    pub version: Arc<str>,
}
