//! Query-time composition of source SBOMs into one SPDX 2.3 document.

use crate::Error;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque, btree_map::Entry},
    fmt::Write as _,
    str::FromStr,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use trustify_common::{cpe::Cpe as CommonCpe, purl::Purl};
use trustify_entity::{
    cpe, license, package_relates_to_package, qualified_purl,
    relationship::Relationship,
    sbom,
    sbom_external_node::{self, DiscriminatorType, ExternalType},
    sbom_file, sbom_node, sbom_node_checksum, sbom_node_cpe_ref, sbom_node_purl_ref, sbom_package,
    sbom_package_license, source_document,
};
use uuid::Uuid;

/// Maximum source SBOMs composed in one generated response.
pub const MAX_SOURCE_SBOMS: usize = 2_000;
const MAX_OUTPUT_NODES: usize = 250_000;
const MAX_OUTPUT_BYTES: usize = 128 * 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 100;

/// Filter applied to source SBOMs, including SBOMs discovered through external links.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SourceFormatFilter {
    Spdx,
    CycloneDx,
    #[default]
    Both,
}

impl SourceFormatFilter {
    fn accepts(self, sbom: &sbom::Model) -> bool {
        match sbom.labels.get("type").map(String::as_str) {
            Some("spdx") => matches!(self, Self::Spdx | Self::Both),
            Some("cyclonedx") => matches!(self, Self::CycloneDx | Self::Both),
            _ => false,
        }
    }
}

/// Per-request metadata overrides for the generated document.
#[derive(Clone, Debug, Default)]
pub struct GenerationOptions {
    pub source_formats: SourceFormatFilter,
    pub document_name: Option<String>,
    pub supplier: Option<String>,
    pub target_cpe: Option<String>,
}

/// SPDX bytes plus completeness information for the response headers.
#[derive(Clone, Debug)]
pub struct GeneratedSbom {
    pub bytes: Vec<u8>,
    pub incomplete: bool,
}

#[derive(Clone, Debug)]
struct ResolvedLink {
    external_node: NodeKey,
    targets: Vec<NodeKey>,
}

/// Compose the requested source SBOMs, including resolvable external SBOM links.
pub async fn generate_spdx<C: ConnectionTrait>(
    source_sbom_ids: &[Uuid],
    options: &GenerationOptions,
    db: &C,
) -> Result<GeneratedSbom, Error> {
    if source_sbom_ids.is_empty() {
        return Err(bad_request("at least one source SBOM is required"));
    }
    if source_sbom_ids.len() > MAX_SOURCE_SBOMS {
        return Err(payload_too_large(format!(
            "source set has {} SBOMs; maximum is {MAX_SOURCE_SBOMS}",
            source_sbom_ids.len()
        )));
    }
    validate_options(options)?;

    let (sources, links, mut diagnostics) =
        resolve_sources(source_sbom_ids, options.source_formats, db).await?;
    if sources.is_empty() {
        return Err(bad_request(
            "no source SBOMs match the requested source-format filter",
        ));
    }
    let source_ids: Vec<_> = sources.keys().copied().collect();

    let (nodes, node_ids) = fetch_nodes(&source_ids, db, &mut diagnostics).await?;
    let relationships = fetch_relationships(&source_ids, db).await?;
    let mut external_targets: HashMap<NodeKey, Vec<NodeKey>> = HashMap::new();
    for link in links {
        external_targets
            .entry(link.external_node)
            .or_default()
            .extend(link.targets);
    }

    let bytes = render_spdx(
        &sources,
        &nodes,
        &node_ids,
        &relationships,
        &external_targets,
        options,
        &mut diagnostics,
    )?;
    Ok(GeneratedSbom {
        bytes,
        incomplete: !diagnostics.is_empty(),
    })
}

fn validate_options(options: &GenerationOptions) -> Result<(), Error> {
    for (field, value) in [
        ("document_name", options.document_name.as_deref()),
        ("supplier", options.supplier.as_deref()),
        ("target_cpe", options.target_cpe.as_deref()),
    ] {
        if let Some(value) = value
            && (value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control))
        {
            return Err(bad_request(format!("invalid {field} override")));
        }
    }
    if let Some(cpe) = options.target_cpe.as_deref()
        && CommonCpe::from_str(cpe).is_err()
    {
        return Err(bad_request("target_cpe must be a valid CPE"));
    }
    Ok(())
}

fn bad_request(message: impl Into<String>) -> Error {
    Error::BadRequest {
        msg: message.into(),
        status: actix_http::StatusCode::BAD_REQUEST,
    }
}

fn payload_too_large(message: impl Into<String>) -> Error {
    Error::BadRequest {
        msg: message.into(),
        status: actix_http::StatusCode::PAYLOAD_TOO_LARGE,
    }
}

async fn resolve_sources<C: ConnectionTrait>(
    initial_ids: &[Uuid],
    source_formats: SourceFormatFilter,
    db: &C,
) -> Result<(BTreeMap<Uuid, sbom::Model>, Vec<ResolvedLink>, Vec<String>), Error> {
    let unique_ids: HashSet<_> = initial_ids.iter().copied().collect();
    let initial: Vec<_> = sbom::Entity::find()
        .filter(sbom::Column::SbomId.is_in(unique_ids.iter().copied().collect::<Vec<_>>()))
        .all(db)
        .await?;
    if initial.len() != unique_ids.len() {
        return Err(bad_request("one or more source SBOM IDs do not exist"));
    }

    let mut sources = BTreeMap::new();
    let mut pending = VecDeque::new();
    for model in initial {
        if source_formats.accepts(&model) {
            pending.push_back(model.sbom_id);
            sources.insert(model.sbom_id, model);
        }
    }

    let mut links = Vec::new();
    let mut diagnostics = Vec::new();
    while let Some(source_id) = pending.pop_front() {
        let external_nodes = sbom_external_node::Entity::find()
            .filter(sbom_external_node::Column::SbomId.eq(source_id))
            .all(db)
            .await?;
        for external in external_nodes {
            let targets = resolve_external_targets(&external, db).await?;
            if targets.is_empty() {
                diagnostics.push(format!(
                    "unresolved {:?} link in SBOM {source_id}",
                    external.external_type
                ));
                continue;
            }

            let target_ids: Vec<_> = targets.iter().map(|(id, _)| *id).collect();
            let target_sboms = sbom::Entity::find()
                .filter(sbom::Column::SbomId.is_in(target_ids))
                .all(db)
                .await?
                .into_iter()
                .map(|model| (model.sbom_id, model))
                .collect::<HashMap<_, _>>();
            let mut included_targets = Vec::new();
            for (target_id, target_node_id) in targets {
                let Some(target) = target_sboms.get(&target_id) else {
                    continue;
                };
                if !source_formats.accepts(target) {
                    diagnostics.push(format!(
                        "external SBOM {target_id} is excluded by the source-format filter"
                    ));
                    continue;
                }
                if let Entry::Vacant(entry) = sources.entry(target_id) {
                    entry.insert(target.clone());
                    pending.push_back(target_id);
                }
                included_targets.push(NodeKey {
                    sbom_id: target_id,
                    node_id: target_node_id,
                });
            }
            if included_targets.is_empty() {
                diagnostics.push(format!(
                    "external {:?} link in SBOM {source_id} has no included target",
                    external.external_type
                ));
            } else {
                links.push(ResolvedLink {
                    external_node: NodeKey {
                        sbom_id: source_id,
                        node_id: external.node_id,
                    },
                    targets: included_targets,
                });
            }
            if sources.len() > MAX_SOURCE_SBOMS {
                return Err(payload_too_large(format!(
                    "external SBOM closure exceeds {MAX_SOURCE_SBOMS} documents"
                )));
            }
        }
    }
    Ok((sources, links, diagnostics))
}

async fn resolve_external_targets<C: ConnectionTrait>(
    external: &sbom_external_node::Model,
    db: &C,
) -> Result<Vec<(Uuid, String)>, Error> {
    if let Some(target) = external.target_sbom_id {
        return Ok(vec![(target, external.external_node_ref.clone())]);
    }
    match external.external_type {
        ExternalType::SPDX => {
            let Some(value) = external.discriminator_value.as_deref() else {
                return Ok(Vec::new());
            };
            let source_documents = match external.discriminator_type {
                Some(DiscriminatorType::Sha256) => {
                    source_document::Entity::find()
                        .filter(source_document::Column::Sha256.eq(value))
                        .all(db)
                        .await?
                }
                Some(DiscriminatorType::Sha384) => {
                    source_document::Entity::find()
                        .filter(source_document::Column::Sha384.eq(value))
                        .all(db)
                        .await?
                }
                Some(DiscriminatorType::Sha512) => {
                    source_document::Entity::find()
                        .filter(source_document::Column::Sha512.eq(value))
                        .all(db)
                        .await?
                }
                _ => return Ok(Vec::new()),
            };
            let source_ids: Vec<_> = source_documents
                .into_iter()
                .map(|source| source.id)
                .collect();
            Ok(sbom::Entity::find()
                .filter(sbom::Column::SourceDocumentId.is_in(source_ids))
                .all(db)
                .await?
                .into_iter()
                .map(|target| (target.sbom_id, external.external_node_ref.clone()))
                .collect())
        }
        ExternalType::CycloneDx => {
            let Some(version) = external.discriminator_value.as_deref() else {
                return Ok(Vec::new());
            };
            let document_ids = cyclonedx_document_ids(&external.external_doc_ref, version);
            Ok(sbom::Entity::find()
                .filter(sbom::Column::DocumentId.is_in(document_ids))
                .order_by_desc(sbom::Column::Published)
                .all(db)
                .await?
                .into_iter()
                .map(|target| (target.sbom_id, external.external_node_ref.clone()))
                .collect())
        }
        ExternalType::RedHatProductComponent => {
            let local_checksums = sbom_node_checksum::Entity::find()
                .filter(sbom_node_checksum::Column::SbomId.eq(external.sbom_id))
                .filter(sbom_node_checksum::Column::NodeId.eq(&external.external_node_ref))
                .all(db)
                .await?;
            let mut targets = BTreeSet::new();
            for checksum in local_checksums {
                let matches = sbom_node_checksum::Entity::find()
                    .filter(sbom_node_checksum::Column::SbomId.ne(external.sbom_id))
                    .filter(sbom_node_checksum::Column::Type.eq(&checksum.r#type))
                    .filter(sbom_node_checksum::Column::Value.eq(&checksum.value))
                    .all(db)
                    .await?;
                targets.extend(
                    matches
                        .into_iter()
                        .map(|matched| (matched.sbom_id, matched.node_id)),
                );
            }
            Ok(targets.into_iter().collect())
        }
    }
}

fn cyclonedx_document_ids(serial: &str, version: &str) -> Vec<String> {
    let document_id = format!("{serial}/{version}");
    if document_id.starts_with("urn:cdx:") {
        vec![document_id]
    } else {
        vec![document_id.clone(), format!("urn:cdx:{document_id}")]
    }
}

#[derive(Clone, Debug)]
struct NodeData {
    key: NodeKey,
    kind: NodeKind,
    name: String,
    version: Option<String>,
    group: Option<String>,
    purls: BTreeSet<String>,
    cpes: BTreeSet<String>,
    checksums: BTreeSet<(String, String)>,
    declared_licenses: BTreeSet<String>,
    concluded_licenses: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum NodeKind {
    Package,
    File,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct NodeKey {
    sbom_id: Uuid,
    node_id: String,
}

#[derive(Clone, Debug)]
struct ComposedNode {
    kind: NodeKind,
    name: String,
    version: Option<String>,
    group: Option<String>,
    purls: BTreeSet<String>,
    cpes: BTreeSet<String>,
    checksums: BTreeSet<(String, String)>,
    declared_licenses: BTreeSet<String>,
    concluded_licenses: BTreeSet<String>,
    source_keys: Vec<NodeKey>,
}

async fn fetch_nodes<C: ConnectionTrait>(
    source_ids: &[Uuid],
    db: &C,
    diagnostics: &mut Vec<String>,
) -> Result<(Vec<ComposedNode>, HashMap<NodeKey, String>), Error> {
    let nodes = sbom_node::Entity::find()
        .filter(sbom_node::Column::SbomId.is_in(source_ids.to_vec()))
        .limit(MAX_OUTPUT_NODES as u64 + 1)
        .all(db)
        .await?;
    if nodes.len() > MAX_OUTPUT_NODES {
        return Err(payload_too_large(format!(
            "source documents contain more than {MAX_OUTPUT_NODES} nodes"
        )));
    }
    let names: HashMap<_, _> = nodes
        .iter()
        .map(|node| {
            (
                NodeKey {
                    sbom_id: node.sbom_id,
                    node_id: node.node_id.clone(),
                },
                node.name.clone(),
            )
        })
        .collect();

    let packages = sbom_package::Entity::find()
        .filter(sbom_package::Column::SbomId.is_in(source_ids.to_vec()))
        .limit(MAX_OUTPUT_NODES as u64 + 1)
        .all(db)
        .await?;
    if packages.len() > MAX_OUTPUT_NODES {
        return Err(payload_too_large(format!(
            "source documents contain more than {MAX_OUTPUT_NODES} package/file nodes"
        )));
    }
    let remaining = MAX_OUTPUT_NODES - packages.len();
    let files = sbom_file::Entity::find()
        .filter(sbom_file::Column::SbomId.is_in(source_ids.to_vec()))
        .limit(remaining as u64 + 1)
        .all(db)
        .await?;
    if files.len() > remaining {
        return Err(payload_too_large(format!(
            "source documents contain more than {MAX_OUTPUT_NODES} package/file nodes"
        )));
    }
    let mut raw_nodes = Vec::with_capacity(packages.len() + files.len());
    for package in packages {
        let key = NodeKey {
            sbom_id: package.sbom_id,
            node_id: package.node_id.clone(),
        };
        raw_nodes.push(NodeData {
            name: names
                .get(&key)
                .cloned()
                .unwrap_or_else(|| package.node_id.clone()),
            key,
            kind: NodeKind::Package,
            version: package.version,
            group: package.group,
            purls: BTreeSet::new(),
            cpes: BTreeSet::new(),
            checksums: BTreeSet::new(),
            declared_licenses: BTreeSet::new(),
            concluded_licenses: BTreeSet::new(),
        });
    }
    for file in files {
        let key = NodeKey {
            sbom_id: file.sbom_id,
            node_id: file.node_id.clone(),
        };
        raw_nodes.push(NodeData {
            name: names
                .get(&key)
                .cloned()
                .unwrap_or_else(|| file.node_id.clone()),
            key,
            kind: NodeKind::File,
            version: None,
            group: None,
            purls: BTreeSet::new(),
            cpes: BTreeSet::new(),
            checksums: BTreeSet::new(),
            declared_licenses: BTreeSet::new(),
            concluded_licenses: BTreeSet::new(),
        });
    }
    if raw_nodes.len() > MAX_OUTPUT_NODES {
        return Err(payload_too_large(format!(
            "source documents contain {} package/file nodes; limit is {MAX_OUTPUT_NODES}",
            raw_nodes.len()
        )));
    }
    raw_nodes.sort_by(|a, b| a.key.cmp(&b.key));

    let node_index: HashMap<NodeKey, usize> = raw_nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.key.clone(), index))
        .collect();
    let purl_refs = sbom_node_purl_ref::Entity::find()
        .filter(sbom_node_purl_ref::Column::SbomId.is_in(source_ids.to_vec()))
        .find_also_related(qualified_purl::Entity)
        .all(db)
        .await?;
    for (reference, purl) in purl_refs {
        let Some(purl) = purl else { continue };
        let key = NodeKey {
            sbom_id: reference.sbom_id,
            node_id: reference.node_id,
        };
        if let Some(index) = node_index.get(&key).copied() {
            let purl: Purl = purl.purl.into();
            raw_nodes[index].purls.insert(purl.to_string());
        }
    }

    let cpe_refs = sbom_node_cpe_ref::Entity::find()
        .filter(sbom_node_cpe_ref::Column::SbomId.is_in(source_ids.to_vec()))
        .find_also_related(cpe::Entity)
        .all(db)
        .await?;
    for (reference, cpe) in cpe_refs {
        let Some(cpe) = cpe else { continue };
        let key = NodeKey {
            sbom_id: reference.sbom_id,
            node_id: reference.node_id,
        };
        if let Some(index) = node_index.get(&key).copied() {
            let dto: cpe::CpeDto = cpe.into();
            match CommonCpe::try_from(dto) {
                Ok(cpe) => {
                    raw_nodes[index].cpes.insert(format!("{cpe:0}"));
                }
                Err(err) => diagnostics.push(format!("invalid stored CPE: {err}")),
            }
        }
    }

    let checksums = sbom_node_checksum::Entity::find()
        .filter(sbom_node_checksum::Column::SbomId.is_in(source_ids.to_vec()))
        .all(db)
        .await?;
    for checksum in checksums {
        let key = NodeKey {
            sbom_id: checksum.sbom_id,
            node_id: checksum.node_id,
        };
        if let Some(index) = node_index.get(&key).copied() {
            let Some(algorithm) = spdx_checksum_type(&checksum.r#type) else {
                diagnostics.push(format!(
                    "unsupported source checksum algorithm: {}",
                    checksum.r#type
                ));
                continue;
            };
            raw_nodes[index]
                .checksums
                .insert((algorithm.to_string(), checksum.value));
        }
    }

    let package_licenses = sbom_package_license::Entity::find()
        .filter(sbom_package_license::Column::SbomId.is_in(source_ids.to_vec()))
        .find_also_related(license::Entity)
        .all(db)
        .await?;
    for (reference, license) in package_licenses {
        let Some(license) = license else { continue };
        let key = NodeKey {
            sbom_id: reference.sbom_id,
            node_id: reference.node_id,
        };
        if let Some(index) = node_index.get(&key).copied() {
            let target = match reference.license_type {
                sbom_package_license::LicenseCategory::Declared => {
                    &mut raw_nodes[index].declared_licenses
                }
                sbom_package_license::LicenseCategory::Concluded => {
                    &mut raw_nodes[index].concluded_licenses
                }
            };
            target.insert(license.text);
        }
    }

    // Stable SPDX IDs are assigned after sorting and exact duplicate folding.
    let mut composed: BTreeMap<String, Vec<ComposedNode>> = BTreeMap::new();
    for node in raw_nodes {
        let identity = identity_key(&node);
        let variants = composed.entry(identity.clone()).or_default();
        let matching = variants.iter_mut().find(|existing| {
            existing.name == node.name
                && existing.version == node.version
                && existing.checksums == node.checksums
                && existing.kind == node.kind
        });
        if let Some(existing) = matching {
            existing.purls.extend(node.purls.iter().cloned());
            existing.cpes.extend(node.cpes.iter().cloned());
            existing
                .declared_licenses
                .extend(node.declared_licenses.iter().cloned());
            existing
                .concluded_licenses
                .extend(node.concluded_licenses.iter().cloned());
            existing.source_keys.push(node.key.clone());
        } else {
            if !variants.is_empty() {
                diagnostics.push(format!(
                    "conflicting component metadata for {} from SBOM {}",
                    node.name, node.key.sbom_id
                ));
            }
            variants.push(ComposedNode {
                kind: node.kind,
                name: node.name,
                version: node.version,
                group: node.group,
                purls: node.purls,
                cpes: node.cpes,
                checksums: node.checksums,
                declared_licenses: node.declared_licenses,
                concluded_licenses: node.concluded_licenses,
                source_keys: vec![node.key.clone()],
            });
        }
    }

    let mut output_nodes = Vec::new();
    let mut source_node_to_spdx = HashMap::new();
    for variants in composed.into_values() {
        for node in variants {
            let spdx_id = format!(
                "SPDXRef-{}-{}",
                match node.kind {
                    NodeKind::Package => "Package",
                    NodeKind::File => "File",
                },
                output_nodes.len() + 1
            );
            for source_key in &node.source_keys {
                source_node_to_spdx.insert(source_key.clone(), spdx_id.clone());
            }
            output_nodes.push(node);
        }
    }

    if node_index.len() != source_node_to_spdx.len() {
        diagnostics.push("some source component references were not mapped".into());
    }
    Ok((output_nodes, source_node_to_spdx))
}

async fn fetch_relationships<C: ConnectionTrait>(
    source_ids: &[Uuid],
    db: &C,
) -> Result<Vec<package_relates_to_package::Model>, Error> {
    Ok(package_relates_to_package::Entity::find()
        .filter(package_relates_to_package::Column::SbomId.is_in(source_ids.to_vec()))
        .all(db)
        .await?)
}

fn identity_key(node: &NodeData) -> String {
    let kind = match node.kind {
        NodeKind::Package => "package",
        NodeKind::File => "file",
    };
    if !node.purls.is_empty() {
        format!(
            "{kind}:purl:{}",
            node.purls.iter().cloned().collect::<Vec<_>>().join("|")
        )
    } else if !node.checksums.is_empty() {
        let checksums = node
            .checksums
            .iter()
            .map(|(kind, value)| format!("{kind}:{value}"))
            .collect::<Vec<_>>()
            .join("|");
        format!("{kind}:checksum:{checksums}")
    } else if !node.cpes.is_empty() {
        format!(
            "{kind}:cpe:{}:{}:{}",
            node.cpes.iter().cloned().collect::<Vec<_>>().join("|"),
            node.name,
            node.version.as_deref().unwrap_or_default()
        )
    } else {
        format!("{kind}:source:{}:{}", node.key.sbom_id, node.key.node_id)
    }
}

fn spdx_checksum_type(checksum_type: &str) -> Option<&'static str> {
    Some(match checksum_type {
        "MD2" => "MD2",
        "MD4" => "MD4",
        "MD5" => "MD5",
        "MD6" => "MD6",
        "SHA-1" | "SHA1" => "SHA1",
        "SHA-224" | "SHA224" => "SHA224",
        "SHA-256" | "SHA256" => "SHA256",
        "SHA-384" | "SHA384" => "SHA384",
        "SHA-512" | "SHA512" => "SHA512",
        "SHA3-256" => "SHA3-256",
        "SHA3-384" => "SHA3-384",
        "SHA3-512" => "SHA3-512",
        "BLAKE2b-256" => "BLAKE2b-256",
        "BLAKE2b-384" => "BLAKE2b-384",
        "BLAKE2b-512" => "BLAKE2b-512",
        "BLAKE3" => "BLAKE3",
        "ADLER32" => "ADLER32",
        _ => return None,
    })
}

fn render_spdx(
    sources: &BTreeMap<Uuid, sbom::Model>,
    nodes: &[ComposedNode],
    node_ids: &HashMap<NodeKey, String>,
    relationships: &[package_relates_to_package::Model],
    external_targets: &HashMap<NodeKey, Vec<NodeKey>>,
    options: &GenerationOptions,
    diagnostics: &mut Vec<String>,
) -> Result<Vec<u8>, Error> {
    let document_name = options.document_name.clone().unwrap_or_else(|| {
        options.target_cpe.as_ref().map_or_else(
            || format!("Trustify aggregate SBOM ({} sources)", sources.len()),
            |cpe| format!("Product SBOM for {cpe}"),
        )
    });

    let mut packages = Vec::new();
    let mut files = Vec::new();
    for node in nodes {
        let source_node = node
            .source_keys
            .first()
            .ok_or_else(|| Error::Data("composed SBOM node has no source provenance".into()))?;
        let spdx_id = node_ids.get(source_node).ok_or_else(|| {
            Error::Data(format!(
                "missing SPDX ID for source node {}",
                source_node.node_id
            ))
        })?;
        let source_provenance = node
            .source_keys
            .iter()
            .map(|key| format!("{}:{}", key.sbom_id, key.node_id))
            .collect::<Vec<_>>()
            .join(", ");
        let checksums: Vec<_> = node
            .checksums
            .iter()
            .map(|(algorithm, value)| json!({"algorithm": algorithm, "checksumValue": value}))
            .collect();
        let external_refs = external_references(&node.purls, &node.cpes);
        let declared = license_expression(&node.declared_licenses, diagnostics);
        let concluded = license_expression(&node.concluded_licenses, diagnostics);
        let claims = license_comment(&node.declared_licenses, &node.concluded_licenses);
        let mut comment = format!("Trustify source nodes: {source_provenance}");
        if let Some(group) = &node.group {
            let _ = write!(&mut comment, "; source package group: {group}");
        }
        if let Some(claims) = claims {
            let _ = write!(&mut comment, "; source license assertions: {claims}");
        }

        match node.kind {
            NodeKind::Package => {
                let mut package = json!({
                    "name": node.name,
                    "SPDXID": spdx_id,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false,
                    "licenseConcluded": concluded,
                    "licenseDeclared": declared,
                    "copyrightText": "NOASSERTION",
                    "supplier": "NOASSERTION",
                    "checksums": checksums,
                    "externalRefs": external_refs,
                    "comment": comment,
                });
                if let Some(version) = &node.version {
                    package["versionInfo"] = json!(version);
                }
                packages.push(package);
            }
            NodeKind::File => files.push(json!({
                "fileName": node.name,
                "SPDXID": spdx_id,
                "checksums": checksums,
                "licenseConcluded": concluded,
                "licenseInfoInFiles": [declared],
                "copyrightText": "NOASSERTION",
                "comment": comment,
            })),
        }
    }

    let product_id = "SPDXRef-Product";
    let mut product_external_refs = Vec::new();
    if let Some(product_cpe) = &options.target_cpe {
        product_external_refs.push(json!({
            "referenceCategory": "SECURITY",
            "referenceType": "cpe22Type",
            "referenceLocator": product_cpe,
        }));
    }
    let mut product = json!({
        "name": document_name.clone(),
        "SPDXID": product_id,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "supplier": options.supplier.as_ref().map_or_else(
            || "NOASSERTION".to_string(),
            |supplier| format!("Organization: {supplier}"),
        ),
        "externalRefs": product_external_refs,
        "comment": "Synthetic aggregate root; source provenance is attached to child packages.",
    });
    if options.supplier.is_none()
        && let Some(fields) = product.as_object_mut()
    {
        fields.remove("supplier");
    }
    packages.push(product);

    let mut relationship_set = BTreeSet::new();
    let mut unresolved_relationship_count = 0usize;
    for relation in relationships {
        let left_key = NodeKey {
            sbom_id: relation.sbom_id,
            node_id: relation.left_node_id.clone(),
        };
        let right_key = NodeKey {
            sbom_id: relation.sbom_id,
            node_id: relation.right_node_id.clone(),
        };
        let left = relation_targets(&left_key, sources, node_ids, external_targets);
        let right = relation_targets(&right_key, sources, node_ids, external_targets);
        if left.is_empty() || right.is_empty() {
            unresolved_relationship_count += 1;
            continue;
        }
        let (kind, reverse) = spdx_relationship_type(relation.relationship);
        for left_id in &left {
            for right_id in &right {
                let (element, related) = if reverse {
                    (right_id.as_str(), left_id.as_str())
                } else {
                    (left_id.as_str(), right_id.as_str())
                };
                relationship_set.insert((
                    element.to_string(),
                    kind.to_string(),
                    related.to_string(),
                ));
            }
        }
    }

    if unresolved_relationship_count > 0 {
        diagnostics.push(format!(
            "{unresolved_relationship_count} source relationships could not be mapped"
        ));
    }

    relationship_set.insert((
        "SPDXRef-DOCUMENT".into(),
        "DESCRIBES".into(),
        product_id.into(),
    ));
    for node in nodes {
        if let Some(spdx_id) = node.source_keys.first().and_then(|key| node_ids.get(key)) {
            relationship_set.insert((product_id.into(), "CONTAINS".into(), spdx_id.clone()));
        }
    }

    let relationships: Vec<_> = relationship_set
        .into_iter()
        .map(|(element, relationship, related)| {
            json!({
                "spdxElementId": element,
                "relationshipType": relationship,
                "relatedSpdxElement": related,
            })
        })
        .collect();
    let creators = vec!["Tool: Trustify SBOM generator".to_string()];
    let created = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| Error::Any(err.into()))?;
    let incomplete = !diagnostics.is_empty();
    let diagnostics_text = diagnostics
        .iter()
        .take(MAX_DIAGNOSTICS)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    let mut document = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document_name,
        "documentNamespace": document_namespace(sources, options, &created),
        "creationInfo": {
            "creators": creators,
            "created": created,
        },
        "packages": packages,
        "files": files,
        "relationships": relationships,
        "comment": format!(
            "Generated by Trustify from {} source SBOMs using source format filter {:?}.",
            sources.len(), options.source_formats
        ),
    });
    if incomplete {
        document["annotations"] = json!([{
            "annotationDate": created,
            "annotationType": "OTHER",
            "annotator": "Tool: Trustify SBOM generator",
            "SPDXID": "SPDXRef-DOCUMENT",
            "comment": format!("INCOMPLETE aggregate: {diagnostics_text}"),
        }]);
    }
    let mut writer = LimitedWriter::new(MAX_OUTPUT_BYTES);
    let result = serde_json::to_writer(&mut writer, &document);
    if writer.exceeded {
        return Err(payload_too_large(format!(
            "generated SPDX document exceeds the {MAX_OUTPUT_BYTES}-byte limit"
        )));
    }
    result.map_err(|err| Error::Any(anyhow::Error::from(err)))?;
    Ok(writer.bytes)
}

fn relation_targets(
    key: &NodeKey,
    sources: &BTreeMap<Uuid, sbom::Model>,
    node_ids: &HashMap<NodeKey, String>,
    external_targets: &HashMap<NodeKey, Vec<NodeKey>>,
) -> Vec<String> {
    if let Some(id) = node_ids.get(key) {
        return vec![id.clone()];
    }
    if sources
        .get(&key.sbom_id)
        .is_some_and(|source| source.node_id == key.node_id)
    {
        return vec!["SPDXRef-Product".into()];
    }
    external_targets
        .get(key)
        .into_iter()
        .flatten()
        .filter_map(|target| node_ids.get(target).cloned())
        .collect()
}

fn spdx_relationship_type(relationship: Relationship) -> (&'static str, bool) {
    match relationship {
        Relationship::Contains => ("CONTAINS", false),
        Relationship::Dependency => ("DEPENDS_ON", false),
        Relationship::DevDependency => ("DEV_DEPENDENCY_OF", true),
        Relationship::OptionalDependency => ("OPTIONAL_DEPENDENCY_OF", true),
        Relationship::ProvidedDependency => ("PROVIDED_DEPENDENCY_OF", true),
        Relationship::TestDependency => ("TEST_DEPENDENCY_OF", true),
        Relationship::RuntimeDependency => ("RUNTIME_DEPENDENCY_OF", true),
        Relationship::Example => ("EXAMPLE_OF", true),
        Relationship::Generates => ("GENERATES", false),
        Relationship::AncestorOf => ("ANCESTOR_OF", false),
        Relationship::Variant => ("VARIANT_OF", true),
        Relationship::BuildTool => ("BUILD_TOOL_OF", true),
        Relationship::DevTool => ("DEV_TOOL_OF", true),
        Relationship::Describes => ("DESCRIBES", false),
        Relationship::Package => ("PACKAGE_OF", true),
        Relationship::Undefined => ("OTHER", false),
    }
}

fn external_references(purls: &BTreeSet<String>, cpes: &BTreeSet<String>) -> Vec<Value> {
    let mut references = Vec::new();
    references.extend(purls.iter().map(|purl| {
        json!({
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        })
    }));
    references.extend(cpes.iter().map(|cpe| {
        json!({
            "referenceCategory": "SECURITY",
            "referenceType": "cpe22Type",
            "referenceLocator": cpe,
        })
    }));
    references
}

fn license_expression(licenses: &BTreeSet<String>, diagnostics: &mut Vec<String>) -> String {
    match licenses.len() {
        0 => "NOASSERTION".into(),
        1 => {
            let Some(license) = licenses.first() else {
                return "NOASSERTION".into();
            };
            if matches!(license.as_str(), "NONE" | "NOASSERTION") {
                return license.clone();
            }
            match spdx_expression::SpdxExpression::parse(license) {
                Ok(expression) => expression.to_string(),
                Err(_) => {
                    diagnostics.push(format!("unparsed source license assertion: {license}"));
                    "NOASSERTION".into()
                }
            }
        }
        _ => {
            diagnostics.push(format!(
                "multiple distinct license assertions: {}",
                licenses.iter().cloned().collect::<Vec<_>>().join(" | ")
            ));
            "NOASSERTION".into()
        }
    }
}

fn license_comment(declared: &BTreeSet<String>, concluded: &BTreeSet<String>) -> Option<String> {
    let mut claims = Vec::new();
    if !declared.is_empty() {
        claims.push(format!(
            "declared: {}",
            declared.iter().cloned().collect::<Vec<_>>().join(" | ")
        ));
    }
    if !concluded.is_empty() {
        claims.push(format!(
            "concluded: {}",
            concluded.iter().cloned().collect::<Vec<_>>().join(" | ")
        ));
    }
    (!claims.is_empty()).then(|| claims.join("; "))
}

fn document_namespace(
    sources: &BTreeMap<Uuid, sbom::Model>,
    options: &GenerationOptions,
    created: &str,
) -> String {
    let mut seed = String::new();
    for source in sources.values() {
        let _ = write!(seed, "{}:{};", source.sbom_id, source.source_document_id);
    }
    let _ = write!(
        seed,
        "{:?};{:?};{:?};{:?};{}",
        options.source_formats,
        options.document_name,
        options.supplier,
        options.target_cpe,
        created
    );
    let digest = Sha256::digest(seed.as_bytes());
    format!("https://trustify.redhat.com/sbom/{}", digest_hex(&digest))
}

fn digest_hex(digest: &[u8]) -> String {
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl LimitedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl std::io::Write for LimitedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other("serialized output limit exceeded"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclone_document_lookup_supports_stored_serial_forms() {
        assert_eq!(
            cyclonedx_document_ids("urn:uuid:1234", "2"),
            ["urn:uuid:1234/2", "urn:cdx:urn:uuid:1234/2"]
        );
        assert_eq!(
            cyclonedx_document_ids("1234", "2"),
            ["1234/2", "urn:cdx:1234/2"]
        );
    }

    #[test]
    fn checksum_names_remain_valid_spdx_algorithms() {
        for (source, expected) in [
            ("SHA3-256", "SHA3-256"),
            ("BLAKE2b-256", "BLAKE2b-256"),
            ("SHA-256", "SHA256"),
        ] {
            let algorithm = spdx_checksum_type(source).expect("supported checksum");
            assert_eq!(algorithm, expected);
            assert!(
                serde_json::from_value::<spdx_rs::models::Checksum>(serde_json::json!({
                    "algorithm": algorithm,
                    "checksumValue": "00"
                }))
                .is_ok()
            );
        }
        assert_eq!(spdx_checksum_type("unknown"), None);
    }

    #[test]
    fn namespace_includes_the_creation_timestamp() {
        let sources = BTreeMap::new();
        let options = GenerationOptions::default();
        assert_ne!(
            document_namespace(&sources, &options, "2026-01-01T00:00:00Z"),
            document_namespace(&sources, &options, "2026-01-01T00:00:01Z")
        );
    }

    #[test]
    fn limited_writer_never_exceeds_its_byte_limit() {
        let mut writer = LimitedWriter::new(4);
        let result = serde_json::to_writer(&mut writer, "123");
        assert!(result.is_err());
        assert!(writer.exceeded);
        assert!(writer.bytes.len() <= 4);
    }
}
