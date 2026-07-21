use crate::error::Error;
use std::path::PathBuf;
use std::str::FromStr;

/// A scan target: what the scanner should analyze.
#[derive(Debug, Clone)]
pub enum Target {
    /// A directory on the local filesystem.
    Dir(PathBuf),
    /// An existing SBOM file (SPDX or CycloneDX JSON).
    Sbom(PathBuf),
    /// A single package URL for direct analysis.
    Purl(String),
    /// A container image from a registry (e.g. `registry.access.redhat.com/ubi9:latest`).
    Registry(String),
    /// A local OCI archive tarball (from `podman save` / `skopeo copy`).
    OciArchive(PathBuf),
}

impl FromStr for Target {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(path) = s.strip_prefix("dir:") {
            let p = PathBuf::from(path);
            if !p.exists() {
                return Err(Error::TargetParse(format!(
                    "directory does not exist: {}",
                    p.display()
                )));
            }
            return Ok(Self::Dir(p));
        }

        if let Some(path) = s.strip_prefix("sbom:") {
            let p = PathBuf::from(path);
            if !p.is_file() {
                return Err(Error::TargetParse(format!(
                    "SBOM file does not exist: {}",
                    p.display()
                )));
            }
            return Ok(Self::Sbom(p));
        }

        if s.starts_with("pkg:") {
            return Ok(Self::Purl(s.to_string()));
        }

        if let Some(image) = s.strip_prefix("registry:") {
            return Ok(Self::Registry(image.to_string()));
        }

        if let Some(path) = s.strip_prefix("oci-archive:") {
            let p = PathBuf::from(path);
            if !p.is_file() {
                return Err(Error::TargetParse(format!(
                    "OCI archive does not exist: {}",
                    p.display()
                )));
            }
            return Ok(Self::OciArchive(p));
        }

        // Auto-detect: if path exists as a file, treat as SBOM; if
        // directory, treat as dir scan.
        let p = PathBuf::from(s);
        if p.is_file() {
            return Ok(Self::Sbom(p));
        }
        if p.is_dir() {
            return Ok(Self::Dir(p));
        }

        // If it contains a `/` and looks like an image reference, treat
        // as registry target (e.g. `quay.io/org/image:tag`).
        if s.contains('/') && !s.contains(' ') {
            return Ok(Self::Registry(s.to_string()));
        }

        Err(Error::TargetParse(format!(
            "cannot determine target type for '{s}'. Use dir:PATH, \
             sbom:PATH, pkg:PURL, registry:IMAGE, or oci-archive:PATH"
        )))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_purl_target() {
        let target: Target = "pkg:rpm/redhat/openssl@3.0.7".parse().unwrap();
        assert!(matches!(target, Target::Purl(ref s) if s == "pkg:rpm/redhat/openssl@3.0.7"));
    }

    #[test]
    fn parse_dir_target() {
        let target: Target = "dir:.".parse().unwrap();
        assert!(matches!(target, Target::Dir(_)));
    }

    #[test]
    fn parse_nonexistent_dir_errors() {
        let result: Result<Target, _> = "dir:/nonexistent/path/xyz".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_nonexistent_sbom_errors() {
        let result: Result<Target, _> = "sbom:/nonexistent/file.json".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_target_errors() {
        let result: Result<Target, _> = "not-a-real-thing-at-all".parse();
        assert!(result.is_err());
    }

    #[test]
    fn auto_detect_directory() {
        // "." is a valid directory, should auto-detect as Dir.
        let target: Target = ".".parse().unwrap();
        assert!(matches!(target, Target::Dir(_)));
    }

    #[test]
    fn parse_registry_target() {
        let target: Target = "registry:quay.io/redhat/ubi9:latest".parse().unwrap();
        assert!(matches!(target, Target::Registry(ref s) if s == "quay.io/redhat/ubi9:latest"));
    }

    #[test]
    fn auto_detect_image_reference() {
        let target: Target = "quay.io/redhat/ubi9:latest".parse().unwrap();
        assert!(matches!(target, Target::Registry(_)));
    }

    #[test]
    fn parse_oci_archive_nonexistent_errors() {
        let result: Result<Target, _> = "oci-archive:/no/such/file.tar".parse();
        assert!(result.is_err());
    }
}
