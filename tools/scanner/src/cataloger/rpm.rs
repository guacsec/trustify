use crate::cataloger::{Cataloger, DiscoveredPackage};
use crate::error::Error;
use std::path::{Path, PathBuf};

/// Discovers RPM packages by parsing the plaintext RPM database manifest.
///
/// Looks for `/var/lib/rpm/Packages` or the rpmdb output format. For the
/// MVP, this parses the output of `rpm -qa --queryformat` if available, or
/// scans for `.rpm` filenames.
pub struct RpmCataloger;

impl Cataloger for RpmCataloger {
    fn name(&self) -> &'static str {
        "rpm"
    }

    fn globs(&self) -> &[&str] {
        &["*.rpm"]
    }

    fn catalog(&self, _root: &Path, matched: &[PathBuf]) -> Result<Vec<DiscoveredPackage>, Error> {
        let mut packages = Vec::new();

        for path in matched {
            if let Some(pkg) = parse_rpm_filename(path) {
                packages.push(pkg);
            }
        }

        Ok(packages)
    }
}

/// Extract package info from an RPM filename.
///
/// RPM filenames follow: `name-version-release.arch.rpm`
/// This is a best-effort heuristic parser.
fn parse_rpm_filename(path: &Path) -> Option<DiscoveredPackage> {
    let stem = path.file_stem()?.to_str()?;

    // Strip `.arch` suffix (e.g., `.x86_64`, `.noarch`, `.src`).
    let without_arch = stem.rsplit_once('.').map(|(rest, _)| rest).unwrap_or(stem);

    // Split `name-version-release`: find the second-to-last `-`.
    let (name_version, _release) = without_arch.rsplit_once('-')?;
    let (name, version) = name_version.rsplit_once('-')?;

    Some(DiscoveredPackage {
        purl: format!("pkg:rpm/{name}@{version}"),
        name: name.to_string(),
        version: version.to_string(),
        source: "rpm",
        locations: vec![path.to_path_buf()],
    })
}
