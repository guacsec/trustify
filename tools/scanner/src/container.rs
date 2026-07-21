use crate::cataloger::{self, DiscoveredPackage};
use crate::error::Error;
use flate2::read::GzDecoder;
use oci_client::{
    Client as OciClient, Reference,
    client::{ClientConfig, ClientProtocol},
    secrets::RegistryAuth,
};
use std::path::{Path, PathBuf};
use tar::Archive;

/// Maximum total extracted size (2 GiB) to prevent disk exhaustion.
const MAX_EXTRACT_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Result of scanning a container image.
pub struct ContainerScanResult {
    /// Discovered packages.
    pub packages: Vec<DiscoveredPackage>,
    /// Ecosystems searched.
    pub ecosystems_searched: Vec<String>,
}

/// Scan a container image from a registry.
///
/// Strategy:
/// 1. Resolve the image digest.
/// 2. Try to fetch a cosign SBOM attachment (`sha256-DIGEST.sbom` tag).
/// 3. If an SBOM is found, parse it directly (most accurate).
/// 4. If no SBOM attachment, fall back to extracting filesystem layers
///    and running catalogers against the extracted root.
pub async fn scan_registry_image(
    image_ref: &str,
    follow_links: bool,
) -> Result<ContainerScanResult, Error> {
    let reference: Reference = image_ref
        .parse()
        .map_err(|e| Error::Container(format!("invalid image reference '{image_ref}': {e}")))?;

    tracing::info!(image = %reference, "pulling container image");

    let client = OciClient::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    });
    let auth = RegistryAuth::Anonymous;

    // Pull the image manifest to get the digest.
    let (_manifest, digest) = client
        .pull_image_manifest(&reference, &auth)
        .await
        .map_err(|e| Error::Container(format!("failed to pull manifest: {e}")))?;

    tracing::info!(digest = %digest, "image manifest retrieved");

    // Try cosign SBOM attachment: tag = sha256-<hex>.sbom
    let sbom_digest = digest.replace(':', "-");
    let sbom_tag = format!("{sbom_digest}.sbom");
    let sbom_ref = Reference::with_tag(
        reference.registry().to_string(),
        reference.repository().to_string(),
        sbom_tag.clone(),
    );

    tracing::info!(tag = %sbom_tag, "checking for SBOM attachment");

    match fetch_sbom_attachment(&client, &sbom_ref, &auth).await {
        Ok(sbom_bytes) => {
            tracing::info!(size = sbom_bytes.len(), "SBOM attachment found, parsing");
            let packages = parse_sbom_bytes(&sbom_bytes)?;
            return Ok(ContainerScanResult {
                packages,
                ecosystems_searched: vec!["container-sbom".to_string()],
            });
        }
        Err(e) => {
            tracing::info!(
                error = %e,
                "no SBOM attachment found, falling back to layer extraction"
            );
        }
    }

    // Fallback: extract filesystem layers and run catalogers.
    let (temp_dir, root) = pull_and_extract_layers(&client, &reference, &auth).await?;
    let result = cataloger::run_catalogers(&root, follow_links)?;

    // Keep temp_dir alive until catalogers finish.
    drop(temp_dir);

    Ok(ContainerScanResult {
        packages: result.packages,
        ecosystems_searched: {
            let mut eco = result.ecosystems_searched;
            eco.insert(0, "container".to_string());
            eco
        },
    })
}

/// Scan a local OCI archive tarball.
///
/// Extracts the archive, looks for an embedded SBOM layer (by media
/// type), otherwise extracts filesystem layers and runs catalogers.
pub async fn scan_oci_archive(
    archive_path: &Path,
    follow_links: bool,
) -> Result<ContainerScanResult, Error> {
    tracing::info!(path = %archive_path.display(), "extracting OCI archive");

    let outer_dir = tempfile::tempdir()?;
    let outer_file = std::fs::File::open(archive_path)?;
    let mut outer_tar = Archive::new(outer_file);
    outer_tar
        .unpack(outer_dir.path())
        .map_err(|e| Error::Container(format!("failed to unpack OCI archive: {e}")))?;

    // Parse index.json -> manifest -> layers.
    let index_path = outer_dir.path().join("index.json");
    let index_content = std::fs::read_to_string(&index_path)
        .map_err(|e| Error::Container(format!("missing index.json in OCI archive: {e}")))?;
    let index: serde_json::Value = serde_json::from_str(&index_content)
        .map_err(|e| Error::Container(format!("invalid index.json: {e}")))?;

    let manifest_digest = index
        .get("manifests")
        .and_then(|m| m.as_array())
        .and_then(|a| a.first())
        .and_then(|m| m.get("digest"))
        .and_then(|d| d.as_str())
        .ok_or_else(|| Error::Container("no manifests found in index.json".to_string()))?;

    let manifest_path = digest_to_blob_path(outer_dir.path(), manifest_digest);
    let manifest_content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| Error::Container(format!("cannot read manifest blob: {e}")))?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content)
        .map_err(|e| Error::Container(format!("invalid manifest: {e}")))?;

    let layers = manifest
        .get("layers")
        .and_then(|l| l.as_array())
        .cloned()
        .unwrap_or_default();

    // Check if any layer is an SBOM (by media type).
    for layer in &layers {
        let media_type = layer
            .get("mediaType")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        if is_sbom_media_type(media_type) {
            let digest = layer.get("digest").and_then(|d| d.as_str()).unwrap_or("");
            let blob_path = digest_to_blob_path(outer_dir.path(), digest);
            if let Ok(sbom_bytes) = std::fs::read(&blob_path) {
                tracing::info!(media_type, "SBOM layer found in archive, parsing");
                let packages = parse_sbom_bytes(&sbom_bytes)?;
                return Ok(ContainerScanResult {
                    packages,
                    ecosystems_searched: vec!["oci-archive-sbom".to_string()],
                });
            }
        }
    }

    // No SBOM layer found — extract filesystem layers.
    let temp_dir = tempfile::tempdir()?;
    let root = temp_dir.path().to_path_buf();

    for (i, layer) in layers.iter().enumerate() {
        let media_type = layer
            .get("mediaType")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let digest = layer.get("digest").and_then(|d| d.as_str()).unwrap_or("");

        if !media_type.contains("tar") {
            continue;
        }

        let blob_path = digest_to_blob_path(outer_dir.path(), digest);
        if !blob_path.is_file() {
            tracing::warn!(layer = i, "layer blob not found, skipping");
            continue;
        }

        tracing::info!(layer = i, "extracting filesystem layer");
        let blob = std::fs::read(&blob_path)?;
        if media_type.contains("gzip") {
            extract_tar_gz(&blob, &root)?;
        } else {
            extract_tar(&blob, &root)?;
        }
    }

    drop(outer_dir);

    let result = cataloger::run_catalogers(&root, follow_links)?;

    Ok(ContainerScanResult {
        packages: result.packages,
        ecosystems_searched: {
            let mut eco = result.ecosystems_searched;
            eco.insert(0, "oci-archive".to_string());
            eco
        },
    })
}

// -- Internal helpers --------------------------------------------------------

/// Try to fetch a cosign SBOM attachment from a registry.
async fn fetch_sbom_attachment(
    client: &OciClient,
    reference: &Reference,
    auth: &RegistryAuth,
) -> Result<Vec<u8>, Error> {
    let (manifest, _) = client
        .pull_image_manifest(reference, auth)
        .await
        .map_err(|e| Error::Container(format!("SBOM attachment not found: {e}")))?;

    if manifest.layers.is_empty() {
        return Err(Error::Container("SBOM manifest has no layers".to_string()));
    }

    // Per cosign convention, SBOM attachments have exactly one layer.
    let mut out = Vec::new();
    client
        .pull_blob(reference, &manifest.layers[0], &mut out)
        .await
        .map_err(|e| Error::Container(format!("failed to pull SBOM blob: {e}")))?;

    Ok(out)
}

/// Parse raw SBOM bytes (SPDX or CycloneDX JSON) into discovered packages.
fn parse_sbom_bytes(bytes: &[u8]) -> Result<Vec<DiscoveredPackage>, Error> {
    let content = std::str::from_utf8(bytes)
        .map_err(|e| Error::SbomParse(format!("SBOM attachment is not valid UTF-8: {e}")))?;

    let value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| Error::SbomParse(format!("SBOM attachment is not valid JSON: {e}")))?;

    // Reuse the SBOM cataloger's extraction logic.
    let path = Path::new("<container-sbom>");
    if value.get("spdxVersion").is_some() {
        crate::cataloger::sbom::extract_spdx2_purls(&value, path)
    } else if value.get("@graph").is_some()
        || value.get("type") == Some(&serde_json::json!("SpdxDocument"))
    {
        crate::cataloger::sbom::extract_spdx3_purls(&value, path)
    } else if value.get("bomFormat").is_some() {
        crate::cataloger::sbom::extract_cyclonedx_purls(&value, path)
    } else {
        Err(Error::SbomParse(
            "SBOM attachment is not a recognized SPDX or CycloneDX document".to_string(),
        ))
    }
}

/// Check if a media type indicates an SBOM document.
fn is_sbom_media_type(media_type: &str) -> bool {
    media_type.contains("spdx") || media_type.contains("cyclonedx") || media_type.contains("sbom")
}

/// Pull image layers and extract them into a temp directory.
async fn pull_and_extract_layers(
    client: &OciClient,
    reference: &Reference,
    auth: &RegistryAuth,
) -> Result<(tempfile::TempDir, PathBuf), Error> {
    let (manifest, _) = client
        .pull_image_manifest(reference, auth)
        .await
        .map_err(|e| Error::Container(format!("failed to pull manifest: {e}")))?;

    tracing::info!(
        layers = manifest.layers.len(),
        "extracting filesystem layers"
    );

    let temp_dir = tempfile::tempdir()?;
    let root = temp_dir.path().to_path_buf();

    for (i, layer) in manifest.layers.iter().enumerate() {
        let media_type = &layer.media_type;

        let is_tar_gz = media_type.contains("tar+gzip")
            || media_type.contains("tar.gzip")
            || media_type == "application/vnd.oci.image.layer.v1.tar+gzip"
            || media_type == "application/vnd.docker.image.rootfs.diff.tar.gzip";

        if !is_tar_gz {
            tracing::debug!(layer = i, media_type, "skipping non-filesystem layer");
            continue;
        }

        tracing::info!(layer = i, size = layer.size, "extracting layer");

        let mut blob = Vec::new();
        client
            .pull_blob(reference, layer, &mut blob)
            .await
            .map_err(|e| Error::Container(format!("failed to pull layer {i}: {e}")))?;

        extract_tar_gz(&blob, &root)?;
    }

    Ok((temp_dir, root))
}

/// Convert a digest like `sha256:abc123...` to a blob path.
fn digest_to_blob_path(oci_root: &Path, digest: &str) -> PathBuf {
    let (algo, hash) = digest.split_once(':').unwrap_or(("sha256", digest));
    oci_root.join("blobs").join(algo).join(hash)
}

/// Extract a gzip-compressed tar archive into a directory.
fn extract_tar_gz(data: &[u8], dest: &Path) -> Result<(), Error> {
    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);
    extract_archive(&mut archive, dest)
}

/// Extract a plain tar archive into a directory.
fn extract_tar(data: &[u8], dest: &Path) -> Result<(), Error> {
    let mut archive = Archive::new(data);
    extract_archive(&mut archive, dest)
}

/// Extract a tar archive with safety checks.
fn extract_archive<R: std::io::Read>(archive: &mut Archive<R>, dest: &Path) -> Result<(), Error> {
    let mut total_size: u64 = 0;

    for entry in archive
        .entries()
        .map_err(|e| Error::Container(format!("failed to read tar entries: {e}")))?
    {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(error = %e, "skipping unreadable tar entry");
                continue;
            }
        };

        let entry_path = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(_) => continue,
        };

        // Reject path traversal.
        if entry_path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            tracing::warn!(path = %entry_path.display(), "skipping tar entry with path traversal");
            continue;
        }

        // Handle OCI whiteout files.
        let file_name = entry_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if let Some(original) = file_name.strip_prefix(".wh.") {
            let deleted = entry_path.with_file_name(original);
            let full = dest.join(&deleted);
            if full.exists() {
                let _ = std::fs::remove_file(&full);
                let _ = std::fs::remove_dir_all(&full);
            }
            continue;
        }

        total_size += entry.size();
        if total_size > MAX_EXTRACT_SIZE {
            return Err(Error::Container(format!(
                "extracted size exceeds limit ({MAX_EXTRACT_SIZE} bytes)"
            )));
        }

        let _ = entry.unpack_in(dest);
    }

    Ok(())
}
