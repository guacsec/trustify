use crate::cataloger::{self, DiscoveredPackage};
use crate::client::TrustifyClient;
use crate::container;
use crate::error::Error;
use crate::target::Target;
use serde::Serialize;
use std::collections::HashMap;

/// Result of scanning a target.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    /// The target that was scanned.
    pub target: String,
    /// Total packages discovered.
    pub total_packages: usize,
    /// Packages with version information (submitted for analysis).
    pub analyzed_packages: usize,
    /// Vulnerability matches found.
    pub vulnerabilities: Vec<VulnerabilityMatch>,
    /// Warnings from analysis.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Ecosystems that were searched (cataloger names that found matching files).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ecosystems_searched: Vec<String>,
    /// All discovered PURLs (populated for verbose output).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub purls: Vec<String>,
}

/// A vulnerability matched to a specific package.
#[derive(Debug, Serialize)]
pub struct VulnerabilityMatch {
    pub package_name: String,
    pub package_version: String,
    pub package_type: String,
    pub purl: String,
    pub vulnerability_id: String,
    pub title: Option<String>,
    pub severity: Option<String>,
    pub score: Option<f64>,
    pub status: String,
    pub advisory: String,
}

/// Run the full scan: discover packages, call trustify, assemble results.
pub async fn scan(
    target: Target,
    client: &TrustifyClient,
    upload: bool,
    follow_links: bool,
) -> Result<ScanResult, Error> {
    let target_str = format!("{target:?}");

    // 1. Discover packages.
    let (packages, ecosystems_searched) = discover_packages(&target, follow_links).await?;
    let total_packages = packages.len();

    tracing::info!(total_packages, "packages discovered");

    // 2. Collect versioned PURLs for analysis.
    let purls = packages
        .iter()
        .filter(|p| !p.version.is_empty())
        .map(|p| p.purl.clone())
        .collect::<Vec<_>>();

    let analyzed_packages = purls.len();

    if purls.is_empty() {
        tracing::warn!("no versioned packages found, nothing to analyze");
        return Ok(ScanResult {
            target: target_str,
            total_packages,
            analyzed_packages: 0,
            vulnerabilities: Vec::new(),
            warnings: vec!["no versioned packages found".to_string()],
            ecosystems_searched,
            purls: Vec::new(),
        });
    }

    tracing::info!(analyzed_packages, "submitting PURLs for analysis");

    // 3. Call trustify vulnerability analysis.
    let analysis = client.analyze(&purls).await?;

    // 4. Assemble results.
    let mut vulnerabilities = Vec::new();
    let mut warnings = Vec::new();

    // Index packages by PURL for O(1) lookup instead of O(n) per match.
    let pkg_by_purl: HashMap<&str, &DiscoveredPackage> =
        packages.iter().map(|p| (p.purl.as_str(), p)).collect();

    for (purl, result) in &analysis {
        for warning in &result.warnings {
            warnings.push(format!("{purl}: {warning}"));
        }

        for detail in &result.details {
            let vuln_id = &detail.identifier;
            let title = detail.title.clone();
            let base_severity = detail.base_score.as_ref().and_then(|s| s.severity.clone());
            let base_score = detail.base_score.as_ref().and_then(|s| s.score);

            for ps in &detail.purl_statuses {
                let advisory_id = ps
                    .advisory
                    .as_ref()
                    .map(|a| a.identifier.clone())
                    .unwrap_or_default();

                let score = ps.scores.first().and_then(|s| s.score).or(base_score);
                let severity = ps
                    .scores
                    .first()
                    .and_then(|s| s.severity.clone())
                    .or(base_severity.clone());

                let pkg_type = purl
                    .strip_prefix("pkg:")
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("unknown")
                    .to_string();

                let (pkg_name, pkg_version) = pkg_by_purl
                    .get(purl.as_str())
                    .map(|p| (p.name.clone(), p.version.clone()))
                    .unwrap_or_else(|| (purl.clone(), String::new()));

                vulnerabilities.push(VulnerabilityMatch {
                    package_name: pkg_name,
                    package_version: pkg_version,
                    package_type: pkg_type,
                    purl: purl.clone(),
                    vulnerability_id: vuln_id.clone(),
                    title: title.clone(),
                    severity,
                    score,
                    status: ps.status.clone(),
                    advisory: advisory_id,
                });
            }
        }
    }

    // Deduplicate: multiple purl_statuses for the same
    // (purl, vuln, advisory) produce identical rows. Keep the entry
    // with the highest score when duplicates exist.
    vulnerabilities.sort_by(|a, b| {
        a.purl
            .cmp(&b.purl)
            .then(a.vulnerability_id.cmp(&b.vulnerability_id))
            .then(a.advisory.cmp(&b.advisory))
            .then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    vulnerabilities.dedup_by(|a, b| {
        a.purl == b.purl && a.vulnerability_id == b.vulnerability_id && a.advisory == b.advisory
    });

    // Sort by severity score descending for display.
    vulnerabilities.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // 5. Optionally upload a minimal CycloneDX SBOM to trustify.
    if upload {
        let sbom_json = build_minimal_sbom(&packages);
        match client.upload_sbom(sbom_json.as_bytes()).await {
            Ok(result) => {
                tracing::info!(id = %result.id, "SBOM uploaded to trustify");
            }
            Err(e) => {
                tracing::warn!(error = %e, "SBOM upload failed");
                warnings.push(format!("SBOM upload failed: {e}"));
            }
        }
    }

    Ok(ScanResult {
        target: target_str,
        total_packages,
        analyzed_packages,
        vulnerabilities,
        warnings,
        ecosystems_searched,
        purls,
    })
}

/// Discover packages from the given target.
///
/// Returns `(packages, ecosystems_searched)`.
async fn discover_packages(
    target: &Target,
    follow_links: bool,
) -> Result<(Vec<DiscoveredPackage>, Vec<String>), Error> {
    match target {
        Target::Sbom(path) => {
            let packages = cataloger::sbom::catalog_sbom(path)?;
            Ok((packages, vec!["sbom".to_string()]))
        }
        Target::Dir(path) => {
            let result = cataloger::run_catalogers(path, follow_links)?;
            Ok((result.packages, result.ecosystems_searched))
        }
        Target::Purl(purl_str) => {
            let (name, version) = parse_purl_name_version(purl_str);
            Ok((
                vec![DiscoveredPackage {
                    purl: purl_str.clone(),
                    name,
                    version,
                    source: "purl",
                    locations: Vec::new(),
                }],
                vec!["purl".to_string()],
            ))
        }
        Target::Registry(image_ref) => {
            let result = container::scan_registry_image(image_ref, follow_links).await?;
            Ok((result.packages, result.ecosystems_searched))
        }
        Target::OciArchive(path) => {
            let result = container::scan_oci_archive(path, follow_links).await?;
            Ok((result.packages, result.ecosystems_searched))
        }
    }
}

/// Build a minimal CycloneDX JSON SBOM from discovered packages.
fn build_minimal_sbom(packages: &[DiscoveredPackage]) -> String {
    let components: Vec<serde_json::Value> = packages
        .iter()
        .filter(|p| !p.version.is_empty())
        .map(|p| {
            serde_json::json!({
                "type": "library",
                "name": p.name,
                "version": p.version,
                "purl": p.purl,
            })
        })
        .collect();

    let bom = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    });

    serde_json::to_string_pretty(&bom).unwrap_or_default()
}

/// Best-effort parse of a PURL string to extract name and version.
fn parse_purl_name_version(purl: &str) -> (String, String) {
    // Format: pkg:type/namespace/name@version?qualifiers#subpath
    let without_scheme = purl.strip_prefix("pkg:").unwrap_or(purl);
    let without_qualifiers = without_scheme.split('?').next().unwrap_or(without_scheme);
    let without_subpath = without_qualifiers
        .split('#')
        .next()
        .unwrap_or(without_qualifiers);

    if let Some((path, version)) = without_subpath.rsplit_once('@') {
        let name = path.rsplit('/').next().unwrap_or(path);
        (name.to_string(), version.to_string())
    } else {
        let name = without_subpath
            .rsplit('/')
            .next()
            .unwrap_or(without_subpath);
        (name.to_string(), String::new())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_simple_purl() {
        let (name, ver) = parse_purl_name_version("pkg:cargo/serde@1.0.183");
        assert_eq!(name, "serde");
        assert_eq!(ver, "1.0.183");
    }

    #[test]
    fn parse_namespaced_purl() {
        let (name, ver) = parse_purl_name_version("pkg:maven/io.quarkus/quarkus-core@3.2.0");
        assert_eq!(name, "quarkus-core");
        assert_eq!(ver, "3.2.0");
    }

    #[test]
    fn parse_purl_with_qualifiers() {
        let (name, ver) =
            parse_purl_name_version("pkg:rpm/redhat/openssl@3.0.7?arch=x86_64&distro=el9");
        assert_eq!(name, "openssl");
        assert_eq!(ver, "3.0.7");
    }

    #[test]
    fn parse_purl_with_subpath() {
        let (name, ver) = parse_purl_name_version("pkg:golang/github.com/foo/bar@v1.2.3#sub/path");
        assert_eq!(name, "bar");
        assert_eq!(ver, "v1.2.3");
    }

    #[test]
    fn parse_purl_no_version() {
        let (name, ver) = parse_purl_name_version("pkg:npm/express");
        assert_eq!(name, "express");
        assert_eq!(ver, "");
    }
}
