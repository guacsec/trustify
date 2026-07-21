pub mod apk;
pub mod cargo;
pub mod dpkg;
pub mod go;
pub mod maven;
pub mod npm;
pub mod python;
pub mod rpm;
pub mod sbom;

use crate::error::Error;
use std::path::{Path, PathBuf};

/// Maximum file size (256 MiB) to read for any single dependency file.
/// Prevents OOM on unexpectedly large files.
const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// Read a file to string with a size guard against OOM.
pub fn read_file_limited(path: &Path) -> Result<String, Error> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(Error::SbomParse(format!(
            "{}: file too large ({} bytes, max {})",
            path.display(),
            metadata.len(),
            MAX_FILE_SIZE,
        )));
    }
    Ok(std::fs::read_to_string(path)?)
}

/// A discovered software package.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredPackage {
    /// The package URL identifying this package.
    pub purl: String,
    /// Human-readable package name.
    pub name: String,
    /// Package version string.
    pub version: String,
    /// Which cataloger discovered this package.
    pub source: &'static str,
    /// Filesystem locations where this package was found.
    pub locations: Vec<PathBuf>,
}

/// Trait for package discovery from a filesystem tree.
pub trait Cataloger: Send + Sync {
    /// Human-readable name of this cataloger.
    fn name(&self) -> &'static str;

    /// Glob patterns for files this cataloger can process.
    fn globs(&self) -> &[&str];

    /// Discover packages from matched files under `root`.
    fn catalog(&self, root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error>;
}

/// Result of running catalogers against a directory.
pub struct CatalogResult {
    /// Discovered packages (deduplicated by PURL).
    pub packages: Vec<DiscoveredPackage>,
    /// Names of catalogers that found matching files.
    pub ecosystems_searched: Vec<String>,
}

/// Run all catalogers against a directory, returning deduplicated packages.
pub fn run_catalogers(root: &Path, follow_links: bool) -> Result<CatalogResult, Error> {
    let catalogers: Vec<Box<dyn Cataloger>> = vec![
        Box::new(apk::ApkCataloger),
        Box::new(cargo::CargoCataloger),
        Box::new(dpkg::DpkgCataloger),
        Box::new(go::GoCataloger),
        Box::new(npm::NpmCataloger),
        Box::new(python::PythonCataloger),
        Box::new(maven::MavenCataloger),
        Box::new(rpm::RpmCataloger),
    ];

    let mut all_packages = Vec::new();
    let mut ecosystems_searched = Vec::new();

    for cataloger in &catalogers {
        let matched = find_matching_files(root, cataloger.globs(), follow_links);
        if matched.is_empty() {
            continue;
        }

        ecosystems_searched.push(cataloger.name().to_string());

        tracing::info!(
            cataloger = cataloger.name(),
            files = matched.len(),
            "running cataloger"
        );

        match cataloger.catalog(root, &matched) {
            Ok(packages) => {
                tracing::info!(
                    cataloger = cataloger.name(),
                    packages = packages.len(),
                    "packages discovered"
                );
                all_packages.extend(packages);
            }
            Err(e) => {
                tracing::warn!(
                    cataloger = cataloger.name(),
                    error = %e,
                    "cataloger failed, skipping"
                );
            }
        }
    }

    if ecosystems_searched.is_empty() {
        tracing::warn!(
            "no recognized dependency files found. \
             Supported: Cargo.lock, go.sum, package-lock.json, \
             requirements.txt, pyproject.toml, uv.lock, poetry.lock, \
             Pipfile.lock, gradle.lockfile, *.rpm"
        );
    }

    // Deduplicate by PURL.
    all_packages.sort_by(|a, b| a.purl.cmp(&b.purl));
    all_packages.dedup_by(|a, b| a.purl == b.purl);

    Ok(CatalogResult {
        packages: all_packages,
        ecosystems_searched,
    })
}

/// All supported file patterns across all catalogers, for display purposes.
pub fn supported_file_patterns() -> Vec<&'static str> {
    vec![
        "lib/apk/db/installed",
        "var/lib/dpkg/status",
        "Cargo.lock",
        "go.sum",
        "package-lock.json",
        "requirements.txt",
        "pyproject.toml",
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "gradle.lockfile",
        "*.rpm",
    ]
}

/// Walk a directory and collect files matching any of the given glob-style
/// filename patterns (simple suffix/exact matching, not full glob).
fn find_matching_files(root: &Path, patterns: &[&str], follow_links: bool) -> Vec<PathBuf> {
    let mut result = Vec::new();

    let walker = walkdir::WalkDir::new(root)
        .follow_links(follow_links)
        .into_iter()
        .filter_map(|e| e.ok());

    for entry in walker {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        let path_str = entry.path().to_string_lossy();

        for pattern in patterns {
            let matches = if let Some(suffix) = pattern.strip_prefix('*') {
                // Suffix match: *.lock, *.toml, etc.
                name.ends_with(suffix)
            } else if pattern.contains('/') {
                // Path-based match.
                path_str.ends_with(pattern)
            } else {
                // Exact filename match.
                *name == **pattern
            };

            if matches {
                result.push(entry.path().to_path_buf());
                break;
            }
        }
    }

    result
}
