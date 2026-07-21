use crate::cataloger::{DiscoveredPackage, read_file_limited};
use crate::error::Error;
use std::path::Path;

/// Maximum nesting depth for CycloneDX component recursion.
const MAX_CDX_DEPTH: usize = 64;

/// Extract PURLs from an SPDX or CycloneDX SBOM file.
pub fn catalog_sbom(path: &Path) -> Result<Vec<DiscoveredPackage>, Error> {
    let content = read_file_limited(path)
        .map_err(|e| Error::SbomParse(format!("cannot read {}: {e}", path.display())))?;

    let value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| Error::SbomParse(format!("invalid JSON in {}: {e}", path.display())))?;

    // Detect format by presence of known top-level keys.
    if value.get("spdxVersion").is_some() {
        // SPDX 2.x JSON format.
        extract_spdx2_purls(&value, path)
    } else if value.get("@graph").is_some()
        || value.get("type") == Some(&serde_json::json!("SpdxDocument"))
    {
        // SPDX 3.x JSON-LD format.
        extract_spdx3_purls(&value, path)
    } else if value.get("bomFormat").is_some() {
        extract_cyclonedx_purls(&value, path)
    } else {
        Err(Error::SbomParse(format!(
            "{}: not a recognized SPDX or CycloneDX document",
            path.display()
        )))
    }
}

/// Extract PURLs from an SPDX 2.x JSON document.
pub fn extract_spdx2_purls(
    doc: &serde_json::Value,
    path: &Path,
) -> Result<Vec<DiscoveredPackage>, Error> {
    let mut packages = Vec::new();

    let Some(pkg_array) = doc.get("packages").and_then(|v| v.as_array()) else {
        return Ok(packages);
    };

    for pkg in pkg_array {
        let name = pkg
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let version = pkg
            .get("versionInfo")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let ext_refs = pkg.get("externalRefs").and_then(|v| v.as_array());

        if let Some(refs) = ext_refs {
            for ext_ref in refs {
                let ref_type = ext_ref
                    .get("referenceType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if ref_type == "purl"
                    && let Some(purl) = ext_ref.get("referenceLocator").and_then(|v| v.as_str())
                {
                    packages.push(DiscoveredPackage {
                        purl: purl.to_string(),
                        name: name.to_string(),
                        version: version.to_string(),
                        source: "spdx",
                        locations: vec![path.to_path_buf()],
                    });
                }
            }
        }
    }

    Ok(packages)
}

/// Extract PURLs from an SPDX 3.x JSON-LD document.
///
/// SPDX 3.0+ uses a `@graph` array. Packages have
/// `"type": "software_Package"` and PURLs appear in
/// `externalIdentifier` entries with `"externalIdentifierType": "purl"`.
pub fn extract_spdx3_purls(
    doc: &serde_json::Value,
    path: &Path,
) -> Result<Vec<DiscoveredPackage>, Error> {
    let mut packages = Vec::new();

    let graph = doc
        .get("@graph")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for element in &graph {
        let el_type = element.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if !el_type.contains("Package") && !el_type.contains("package") {
            continue;
        }

        let name = element
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let version = element
            .get("software_packageVersion")
            .or_else(|| element.get("packageVersion"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let ext_ids = element.get("externalIdentifier").and_then(|v| v.as_array());

        if let Some(ids) = ext_ids {
            for ext_id in ids {
                let id_type = ext_id
                    .get("externalIdentifierType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if id_type == "purl"
                    && let Some(purl) = ext_id.get("identifier").and_then(|v| v.as_str())
                {
                    packages.push(DiscoveredPackage {
                        purl: purl.to_string(),
                        name: name.to_string(),
                        version: version.to_string(),
                        source: "spdx3",
                        locations: vec![path.to_path_buf()],
                    });
                }
            }
        }
    }

    Ok(packages)
}

/// Extract PURLs from a CycloneDX JSON document.
pub fn extract_cyclonedx_purls(
    doc: &serde_json::Value,
    path: &Path,
) -> Result<Vec<DiscoveredPackage>, Error> {
    let mut packages = Vec::new();

    // Check metadata.component.
    if let Some(component) = doc.get("metadata").and_then(|m| m.get("component")) {
        extract_cdx_component(component, path, &mut packages);
    }

    // Check top-level components array.
    if let Some(components) = doc.get("components").and_then(|v| v.as_array()) {
        for component in components {
            extract_cdx_component(component, path, &mut packages);
            extract_cdx_nested(component, path, &mut packages, 1);
        }
    }

    Ok(packages)
}

/// Extract a PURL from a single CycloneDX component.
fn extract_cdx_component(
    component: &serde_json::Value,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
) {
    let name = component
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let version = component
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if let Some(purl) = component.get("purl").and_then(|v| v.as_str()) {
        packages.push(DiscoveredPackage {
            purl: purl.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            source: "cyclonedx",
            locations: vec![path.to_path_buf()],
        });
    }
}

/// Recurse into nested `components` arrays within a CycloneDX component.
///
/// Depth-limited to prevent stack overflow on malicious inputs.
fn extract_cdx_nested(
    component: &serde_json::Value,
    path: &Path,
    packages: &mut Vec<DiscoveredPackage>,
    depth: usize,
) {
    if depth >= MAX_CDX_DEPTH {
        tracing::warn!(
            depth,
            "CycloneDX component nesting too deep, stopping recursion"
        );
        return;
    }
    if let Some(children) = component.get("components").and_then(|v| v.as_array()) {
        for child in children {
            extract_cdx_component(child, path, packages);
            extract_cdx_nested(child, path, packages, depth + 1);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_cyclonedx_sbom() {
        let cdx = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "foo", "version": "1.0", "purl": "pkg:cargo/foo@1.0"},
                {"name": "bar", "version": "2.0", "purl": "pkg:cargo/bar@2.0"},
                {"name": "no-purl", "version": "3.0"},
            ]
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.cdx.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", serde_json::to_string(&cdx).unwrap()).unwrap();

        let packages = catalog_sbom(&path).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].purl, "pkg:cargo/foo@1.0");
        assert_eq!(packages[1].purl, "pkg:cargo/bar@2.0");
    }

    #[test]
    fn parse_spdx2_sbom() {
        let spdx = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "openssl",
                    "versionInfo": "3.0.7",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:rpm/openssl@3.0.7"},
                        {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:openssl:*"}
                    ]
                },
                {
                    "name": "no-refs",
                    "versionInfo": "1.0"
                }
            ]
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.spdx.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", serde_json::to_string(&spdx).unwrap()).unwrap();

        let packages = catalog_sbom(&path).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:rpm/openssl@3.0.7");
        assert_eq!(packages[0].name, "openssl");
    }

    #[test]
    fn parse_spdx3_sbom() {
        let spdx3 = serde_json::json!({
            "@graph": [
                {
                    "type": "software_Package",
                    "name": "curl",
                    "software_packageVersion": "8.4.0",
                    "externalIdentifier": [
                        {"externalIdentifierType": "purl", "identifier": "pkg:generic/curl@8.4.0"}
                    ]
                },
                {
                    "type": "SpdxDocument",
                    "name": "doc"
                }
            ]
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.spdx3.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", serde_json::to_string(&spdx3).unwrap()).unwrap();

        let packages = catalog_sbom(&path).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:generic/curl@8.4.0");
        assert_eq!(packages[0].source, "spdx3");
    }

    #[test]
    fn unrecognized_format_errors() {
        let unknown = serde_json::json!({"foo": "bar"});

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unknown.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", serde_json::to_string(&unknown).unwrap()).unwrap();

        let result = catalog_sbom(&path);
        assert!(result.is_err());
    }
}
