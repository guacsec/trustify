pub mod version;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use trustify_entity::{advisory_vulnerability_score::Severity, version_scheme::VersionScheme};
use trustify_module_fundamental::sbom::model::AffectedSeverity;
use uuid::Uuid;

/// Converts an entity-level CVSS severity into the affected-severity enum.
pub fn severity_to_affected(severity: Severity) -> AffectedSeverity {
    match severity {
        Severity::None => AffectedSeverity::None,
        Severity::Low => AffectedSeverity::Low,
        Severity::Medium => AffectedSeverity::Medium,
        Severity::High => AffectedSeverity::High,
        Severity::Critical => AffectedSeverity::Critical,
    }
}

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
    pub purl_status_id: Uuid,
    pub advisory_id: Uuid,
    pub vulnerability_id: Arc<str>,
    pub status_id: Uuid,
    pub version_range: VersionRangeData,
    pub context_cpe_id: Option<Uuid>,
}

/// A single product_status entry for name-based matching.
#[derive(Debug, Clone)]
pub struct ProductStatusEntry {
    pub product_status_id: Uuid,
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
    /// Max severity per (advisory_id, vulnerability_id) pair.
    pub severity: SeverityIndex,
}

/// Max severity per (advisory_id, vulnerability_id) pair.
pub type SeverityIndex = HashMap<(Uuid, Arc<str>), AffectedSeverity>;

/// Source reference for a vulnerability reverse index entry.
#[derive(Debug, Clone)]
pub enum VulnEntrySource {
    Purl {
        purl_key: PurlKey,
        version_range: VersionRangeData,
    },
    Product {
        package_name: Arc<str>,
    },
}

/// An entry in the reverse vulnerability index (vulnerability_id → entries).
#[derive(Debug, Clone)]
pub struct VulnIndexEntry {
    pub advisory_id: Uuid,
    pub status_id: Uuid,
    pub context_cpe_id: Option<Uuid>,
    pub source: VulnEntrySource,
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
    /// Max severity per (advisory_id, vulnerability_id) pair.
    pub severity: SeverityIndex,
    /// Reverse index: vulnerability_id → all purl/product entries referencing it.
    pub by_vulnerability: HashMap<Arc<str>, Vec<VulnIndexEntry>>,
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

        self.severity
            .retain(|(adv_id, _), _| *adv_id != advisory_id);

        for entries in self.by_vulnerability.values_mut() {
            entries.retain(|e| e.advisory_id != advisory_id);
        }
        self.by_vulnerability.retain(|_, v| !v.is_empty());
    }

    /// Applies a patch: removes old data for this advisory, then inserts new data.
    pub fn apply_patch(&mut self, advisory_id: Uuid, patch: AdvisoryPatch) {
        self.remove_advisory(advisory_id);

        for (purl_key, entries) in &patch.purl_statuses {
            for entry in entries {
                self.by_vulnerability
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

        for (package, entries) in &patch.product_statuses {
            for entry in entries {
                self.by_vulnerability
                    .entry(Arc::clone(&entry.vulnerability_id))
                    .or_default()
                    .push(VulnIndexEntry {
                        advisory_id: entry.advisory_id,
                        status_id: entry.status_id,
                        context_cpe_id: entry.context_cpe_id,
                        source: VulnEntrySource::Product {
                            package_name: Arc::clone(package),
                        },
                    });
            }
        }

        for (purl_key, entries) in patch.purl_statuses {
            self.by_purl.entry(purl_key).or_default().extend(entries);
        }

        for (package, entries) in patch.product_statuses {
            self.product_by_name
                .entry(package)
                .or_default()
                .extend(entries);
        }

        for ((adv_id, vuln_id), sev) in patch.severity {
            self.severity.insert((adv_id, vuln_id), sev);
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

/// Loaded data for a single SBOM, ready to apply to the index.
#[derive(Debug, Clone, Default)]
pub struct SbomPatch {
    /// Packages belonging to this SBOM.
    pub packages: Vec<SbomPackageEntry>,
    /// Describing CPE IDs for this SBOM.
    pub describing_cpes: HashSet<Uuid>,
}

/// SBOM-side index: maps sbom_id to its package entries.
#[derive(Debug, Clone)]
pub struct SbomIndex {
    /// sbom_id → package entries for that SBOM.
    pub by_sbom: HashMap<Uuid, Arc<[SbomPackageEntry]>>,
    /// Per-SBOM describing CPE IDs for context filtering.
    pub describing_cpes: HashMap<Uuid, HashSet<Uuid>>,
    /// Reverse index: PurlKey → SBOMs containing packages with that key.
    pub by_purl_key: HashMap<PurlKey, Vec<Uuid>>,
}

impl SbomIndex {
    /// Applies a patch: replaces packages and CPEs for this SBOM.
    pub fn apply_patch(&mut self, sbom_id: Uuid, patch: SbomPatch) {
        for entries in self.by_purl_key.values_mut() {
            entries.retain(|id| *id != sbom_id);
        }
        self.by_purl_key.retain(|_, v| !v.is_empty());

        if patch.packages.is_empty() {
            self.by_sbom.remove(&sbom_id);
        } else {
            for entry in &patch.packages {
                let key = PurlKey {
                    ty: Arc::clone(&entry.ty),
                    namespace: entry.namespace.as_ref().map(Arc::clone),
                    name: Arc::clone(&entry.name),
                };
                self.by_purl_key.entry(key).or_default().push(sbom_id);
            }
            self.by_sbom
                .insert(sbom_id, Arc::from(patch.packages.into_boxed_slice()));
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
                severity: HashMap::new(),
                by_vulnerability: HashMap::new(),
            },
            sbom_index: SbomIndex {
                by_sbom: HashMap::new(),
                describing_cpes: HashMap::new(),
                by_purl_key: HashMap::new(),
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

/// Result of correlating a standalone PURL (no SBOM context).
///
/// Matches can originate from either the `purl_status` table (version-range
/// matching) or the `product_status` table (name-based matching from CSAF).
/// Exactly one of `purl_status_id` / `product_status_id` is set.
#[derive(Debug, Clone)]
pub struct PurlCorrelationMatch {
    pub purl_status_id: Option<Uuid>,
    pub product_status_id: Option<Uuid>,
    pub advisory_id: Uuid,
    pub vulnerability_id: Arc<str>,
    pub status_id: Uuid,
    pub context_cpe_id: Option<Uuid>,
    pub version_range: Option<VersionRangeData>,
}

/// Result of correlating a vulnerability against the SBOM index.
///
/// Each match represents a specific PURL version in a specific SBOM that is
/// affected by the vulnerability according to an advisory.
#[derive(Debug, Clone)]
pub struct VulnCorrelationMatch {
    pub advisory_id: Uuid,
    pub status_id: Uuid,
    pub context_cpe_id: Option<Uuid>,
    pub sbom_id: Uuid,
    pub purl_key: PurlKey,
    pub version: Arc<str>,
}
