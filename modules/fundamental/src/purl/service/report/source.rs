//! Read-only, bounded recovery of supplier identities discarded by older ingestion.

use super::{ProviderIdentity, ReportError, SbomPurlRow};
use crate::source_document::model::SourceDocument;
use futures_util::{StreamExt, pin_mut};
use serde_json::Value;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    slice::from_ref,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::Semaphore,
    task::spawn_blocking,
    time::{Instant, timeout_at},
};
use trustify_common::{
    cpe::Cpe,
    hashing::{Contexts, Digests},
    purl::Purl,
};
use trustify_entity::{source_document, version_scheme::VersionScheme};
use trustify_module_ingestor::service::{DetectedDocument, DocumentDetector, Format};
use trustify_module_ingestor::{
    graph::advisory::{
        purl_status::PurlStatus as GraphPurlStatus,
        vers::parse_vers,
        version::{Version, VersionInfo, VersionSpec},
    },
    service::advisory::csaf::{
        util::{self, ResolveProductIdCache},
        value::{self, OnInvalidData},
    },
};
use trustify_module_storage::service::{StorageBackend, StorageKey, StorageResult};
use uuid::Uuid;

// A timed-out blocking parser cannot be cancelled. Retain its permit until it actually exits.
static SOURCE_PARSERS: Semaphore = Semaphore::const_new(2);

/// Independent source-byte, traversal and elapsed-time bounds for one report request.
#[derive(Clone, Copy)]
pub(super) struct RecoveryLimits {
    pub(super) per_document: usize,
    pub(super) per_request: usize,
    pub(super) depth: usize,
    pub(super) duration: Duration,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            per_document: super::MAX_SOURCE_BYTES,
            per_request: super::MAX_REQUEST_BYTES,
            depth: 64,
            duration: Duration::from_secs(30),
        }
    }
}

/// Source identity fields that can be compared with an already-ingested node.
struct SourceNode {
    reference: Option<String>,
    name: String,
    group: Option<String>,
    version: Option<String>,
    purls: BTreeSet<String>,
    cpes: BTreeSet<Uuid>,
    supplier: Option<ProviderIdentity>,
    describing: bool,
}

/// Only the supplier inputs survive parsing; bytes and full document trees are released.
#[derive(Default)]
pub(super) struct RecoveredSuppliers {
    explicit: HashMap<String, SupplierSet>,
    anonymous: HashMap<AnonymousKey, SupplierSet>,
    metadata_bytes: usize,
    pub(super) product: ProviderIdentity,
}

/// Alternatives share supplier strings across aliases while preserving attribution ambiguity.
type SupplierSet = BTreeSet<Option<Arc<ProviderIdentity>>>;

/// A retained anonymous-node identity, not a PURL-only or source-array-position heuristic.
#[derive(PartialEq, Eq, Hash)]
struct AnonymousKey {
    identity: [u8; 32],
    purl: String,
}

/// Tagged, length-delimited hashing avoids copying large shared attributes into every alias key.
fn identity_key(
    name: &str,
    group: Option<&str>,
    version: Option<&str>,
    cpes: &BTreeSet<Uuid>,
    describing: bool,
) -> [u8; 32] {
    let mut context = Contexts::new();
    context.update(&[u8::from(describing)]);
    for value in [Some(name), group, version] {
        if let Some(value) = value {
            context.update(&[1]);
            context.update(&(value.len() as u64).to_le_bytes());
            context.update(value.as_bytes());
        } else {
            context.update(&[0]);
        }
    }
    context.update(&(cpes.len() as u64).to_le_bytes());
    for cpe in cpes {
        context.update(cpe.as_bytes());
    }
    let mut key = [0; 32];
    key.copy_from_slice(context.finish().sha256.as_ref());
    key
}

impl RecoveredSuppliers {
    /// Index source identities once so recovery is linear rather than scanning all nodes per row.
    fn index(&mut self, node: SourceNode, sbom_id: Uuid, limit: usize) -> Result<(), ReportError> {
        let supplier_bytes = node.supplier.as_ref().map_or(0, |supplier| {
            supplier.identifiers.iter().map(String::len).sum()
        });
        let key_bytes = node.reference.as_ref().map_or_else(
            || node.purls.iter().map(|purl| purl.len() + 128).sum(),
            |reference| reference.len() + 128,
        );
        self.metadata_bytes = self
            .metadata_bytes
            .saturating_add(supplier_bytes)
            .saturating_add(key_bytes);
        if self.metadata_bytes > limit {
            return Err(ReportError::Limit {
                sbom_id,
                reason: "extracted source metadata byte limit",
            });
        }
        let supplier = node.supplier.map(Arc::new);
        if let Some(reference) = node.reference {
            self.explicit.entry(reference).or_default().insert(supplier);
        } else {
            let identity = identity_key(
                &node.name,
                node.group.as_deref(),
                node.version.as_deref(),
                &node.cpes,
                node.describing,
            );
            for purl in node.purls {
                let key = AnonymousKey { identity, purl };
                self.anonymous
                    .entry(key)
                    .or_default()
                    .insert(supplier.clone());
            }
        }
        Ok(())
    }

    /// Match exact refs first, otherwise require equivalent supplier identities among safe matches.
    pub(super) fn supplier_for(
        &self,
        row: &SbomPurlRow,
        cpes: &BTreeSet<Uuid>,
        describing: &HashSet<String>,
    ) -> Result<Option<ProviderIdentity>, ReportError> {
        let identity = identity_key(
            &row.node_name,
            row.package_group.as_deref(),
            row.package_version.as_deref(),
            cpes,
            describing.contains(row.node_id.as_ref()),
        );
        let mut intersection = None::<SupplierSet>;
        let identities = if let Some(explicit) = self.explicit.get(row.node_id.as_ref()) {
            explicit
        } else {
            for purl in row.node_purls.iter() {
                let key = AnonymousKey {
                    identity,
                    purl: purl.to_string(),
                };
                let next = self.anonymous.get(&key).ok_or(ReportError::Unavailable {
                    sbom_id: row.sbom_id,
                    reason: "source component cannot be associated with the stored node",
                })?;
                if let Some(current) = &mut intersection {
                    current.retain(|candidate| next.contains(candidate));
                } else {
                    intersection = Some(next.clone());
                }
            }
            intersection.as_ref().ok_or(ReportError::Unavailable {
                sbom_id: row.sbom_id,
                reason: "source component has no identifiers",
            })?
        };
        if identities.len() != 1 {
            return Err(ReportError::Ambiguous {
                sbom_id: row.sbom_id,
                node_id: row.node_id.to_string(),
            });
        }
        identities
            .first()
            .map(|identity| identity.as_ref().map(|identity| identity.as_ref().clone()))
            .ok_or(ReportError::Unavailable {
                sbom_id: row.sbom_id,
                reason: "source component cannot be associated with the stored node",
            })
    }
}

/// Retrieve and parse one source without re-ingestion; enforce actual streamed bytes as well as metadata.
pub(super) async fn load<S: StorageBackend>(
    sbom_id: Uuid,
    metadata: &source_document::Model,
    storage: &S,
    limits: RecoveryLimits,
    deadline: Instant,
    total_bytes: &mut usize,
) -> Result<RecoveredSuppliers, ReportError>
where
    S::Error: Into<anyhow::Error>,
{
    load_parsed(
        sbom_id,
        metadata,
        storage,
        limits,
        deadline,
        total_bytes,
        move |bytes, limits| parse(sbom_id, bytes, limits),
    )
    .await
}

/// A matched legacy row whose origin cannot be determined from its range shape alone.
pub(super) struct OriginCandidate {
    pub(super) source_id: Uuid,
    pub(super) status_id: Uuid,
    pub(super) vuln_id: String,
}

/// Origin recovery is scoped to one current advisory and deduplicated matched source rows.
pub(super) struct OriginRequest {
    pub(super) advisory_id: Uuid,
    pub(super) candidates: Vec<OriginCandidate>,
}

/// Read the retained advisory only when matched affected-before rows need an origin proof.
pub(super) async fn load_origins<S: StorageBackend>(
    sbom_id: Uuid,
    metadata: &source_document::Model,
    storage: &S,
    limits: RecoveryLimits,
    deadline: Instant,
    total_bytes: &mut usize,
    request: OriginRequest,
) -> Result<HashSet<Uuid>, ReportError>
where
    S::Error: Into<anyhow::Error>,
{
    load_parsed(
        sbom_id,
        metadata,
        storage,
        limits,
        deadline,
        total_bytes,
        move |bytes, limits| recover_origins(sbom_id, bytes, limits, request),
    )
    .await
}

/// Both SBOM and advisory recovery share byte/digest/deadline/concurrency enforcement.
async fn load_parsed<S: StorageBackend, T: Send + 'static, F>(
    sbom_id: Uuid,
    metadata: &source_document::Model,
    storage: &S,
    limits: RecoveryLimits,
    deadline: Instant,
    total_bytes: &mut usize,
    parser: F,
) -> Result<T, ReportError>
where
    S::Error: Into<anyhow::Error>,
    F: FnOnce(&[u8], RecoveryLimits) -> Result<T, ReportError> + Send + 'static,
{
    let fail = |source| ReportError::Source { sbom_id, source };
    if metadata.size < 0
        || metadata.size as u64 > limits.per_document as u64
        || metadata.size as u64 > limits.per_request.saturating_sub(*total_bytes) as u64
    {
        return Err(ReportError::Limit {
            sbom_id,
            reason: "source byte limit",
        });
    }
    // Bound in-flight byte buffers as well as uninterruptible parser tasks across requests.
    let permit = SOURCE_PARSERS
        .acquire()
        .await
        .map_err(|err| fail(err.into()))?;
    let key = SourceDocument::from_entity(metadata)
        .try_into()
        .map_err(|err| fail(anyhow::Error::from(err)))?;
    let stream = storage
        .retrieve(key)
        .await
        .map_err(|err| fail(err.into()))?
        .ok_or(ReportError::Unavailable {
            sbom_id,
            reason: "source object is missing",
        })?;
    pin_mut!(stream);
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| fail(err.into()))?;
        if chunk.len() > limits.per_document.saturating_sub(bytes.len())
            || chunk.len() > limits.per_request.saturating_sub(*total_bytes)
        {
            return Err(ReportError::Limit {
                sbom_id,
                reason: "decompressed source byte limit",
            });
        }
        *total_bytes += chunk.len();
        bytes.extend_from_slice(&chunk);
    }
    let expected = StorageKey::from_sha256(&metadata.sha256);
    let parsed = spawn_blocking(move || {
        let _permit = permit;
        if (StorageResult {
            digests: Digests::digest(&bytes),
        })
        .key()
            != expected
        {
            return Err(ReportError::Unavailable {
                sbom_id,
                reason: "source digest mismatch",
            });
        }
        parser(&bytes, limits)
    });
    timeout_at(deadline, parsed)
        .await
        .map_err(|_| ReportError::Limit {
            sbom_id,
            reason: "source parsing deadline",
        })?
        .map_err(|err| fail(err.into()))?
}

/// Reconstruct row UUIDs with existing release parsers; stated proof wins if a row has both origins.
fn recover_origins(
    sbom_id: Uuid,
    bytes: &[u8],
    limits: RecoveryLimits,
    request: OriginRequest,
) -> Result<HashSet<Uuid>, ReportError> {
    let fail = |error: anyhow::Error| ReportError::Source {
        sbom_id,
        source: error,
    };
    let DetectedDocument::Csaf(csaf) = DocumentDetector::detect_as(bytes, Format::CSAF)
        .map_err(|error| fail(error.into()))?
        .into_document()
    else {
        return Err(ReportError::Unavailable {
            sbom_id,
            reason: "statement origin requires a CSAF source",
        });
    };
    let publisher = OnInvalidData::Reject
        .validate(value::url(&csaf.document.publisher.namespace), &())
        .map_err(|error| fail(error.into()))?
        .ok_or(ReportError::Unavailable {
            sbom_id,
            reason: "publisher namespace is unavailable",
        })?;
    let redhat = publisher.host_str() == Some("www.redhat.com");
    let mut metadata = 0usize;
    let mut too_deep = false;
    util::walk_product_tree_branches(&csaf.product_tree, |parents, branch| {
        too_deep |= parents.len() > limits.depth;
        if branch.product.is_some() {
            metadata = metadata.saturating_add(
                (parents.len() + 1)
                    .saturating_mul(size_of::<usize>())
                    .saturating_add(64),
            );
        }
    });
    if too_deep || metadata > limits.per_document {
        return Err(ReportError::Limit {
            sbom_id,
            reason: "advisory origin metadata limit",
        });
    }
    let cache = ResolveProductIdCache::new(&csaf);
    let mut ids = HashMap::<&str, BTreeSet<Uuid>>::new();
    for candidate in &request.candidates {
        ids.entry(&candidate.vuln_id)
            .or_default()
            .insert(candidate.status_id);
    }
    let (mut stated, mut generated) = (HashSet::new(), HashSet::new());
    for vulnerability in &csaf.vulnerabilities {
        let Some(cve) = &vulnerability.cve else {
            continue;
        };
        let Some(status_ids) = ids.get(cve.as_str()) else {
            continue;
        };
        let Some(status) = &vulnerability.product_status else {
            continue;
        };
        for (fixed, products) in [(false, &status.known_affected), (true, &status.fixed)] {
            for product in products.iter().flat_map(|products| &products.0) {
                let product_ids = match cache.get_relationship(product) {
                    Some(relation) => vec![
                        relation.relates_to_product_reference.as_str(),
                        relation.product_reference.as_str(),
                    ],
                    None => vec![product.as_str()],
                };
                let (mut cpe, mut purls, mut ranges) =
                    (None::<Cpe>, Vec::<Purl>::new(), Vec::<VersionInfo>::new());
                for id in product_ids {
                    for branch in cache.trace_product(id) {
                        let category = serde_json::to_value(branch.category)
                            .map_err(|error| fail(error.into()))?;
                        match category.as_str() {
                            Some("product_name") => {
                                if let Some(value) =
                                    util::branch_cpe(branch, OnInvalidData::Reject, &())
                                        .map_err(|error| fail(error.into()))?
                                {
                                    cpe = Some(value.into());
                                }
                            }
                            Some("product_version_range") => {
                                ranges.extend(
                                    parse_vers(&branch.name).map_err(|error| fail(error.into()))?,
                                );
                                if let Some(value) =
                                    util::branch_purl(branch, OnInvalidData::Reject, &())
                                        .map_err(|error| fail(error.into()))?
                                {
                                    purls.push(value.into());
                                }
                            }
                            _ => {
                                if let Some(value) =
                                    util::branch_purl(branch, OnInvalidData::Reject, &())
                                        .map_err(|error| fail(error.into()))?
                                {
                                    purls.push(value.into());
                                }
                            }
                        }
                    }
                }
                for purl in purls {
                    let specs = if ranges.is_empty() {
                        vec![VersionInfo {
                            scheme: if purl.version.is_some() {
                                purl.ty.as_str().into()
                            } else {
                                VersionScheme::Generic
                            },
                            spec: VersionSpec::Exact(purl.effective_version()),
                        }]
                    } else {
                        ranges.clone()
                    };
                    for status_id in status_ids {
                        if !fixed {
                            for info in &specs {
                                stated.insert(
                                    GraphPurlStatus::new(
                                        cpe.clone(),
                                        purl.clone(),
                                        *status_id,
                                        info.clone(),
                                    )
                                    .uuid(request.advisory_id, cve.to_string()),
                                );
                            }
                        } else if redhat && ranges.is_empty() && purl.version.is_some() {
                            let info = VersionInfo {
                                scheme: purl.ty.as_str().into(),
                                spec: VersionSpec::Range(
                                    Version::Unbounded,
                                    Version::Exclusive(purl.effective_version()),
                                ),
                            };
                            generated.insert(
                                GraphPurlStatus::new(cpe.clone(), purl.clone(), *status_id, info)
                                    .uuid(request.advisory_id, cve.to_string()),
                            );
                        }
                    }
                    if stated
                        .len()
                        .saturating_add(generated.len())
                        .saturating_mul(64)
                        > limits.per_document
                    {
                        return Err(ReportError::Limit {
                            sbom_id,
                            reason: "advisory origin metadata limit",
                        });
                    }
                }
            }
        }
    }
    let mut derived = HashSet::new();
    for candidate in &request.candidates {
        if stated.contains(&candidate.source_id) {
            continue;
        }
        if generated.contains(&candidate.source_id) {
            derived.insert(candidate.source_id);
        } else {
            return Err(ReportError::Unavailable {
                sbom_id,
                reason: "statement origin cannot be reconstructed",
            });
        }
    }
    Ok(derived)
}

fn text(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn cdx_supplier(value: &Value) -> Option<ProviderIdentity> {
    let supplier = value
        .get("supplier")
        .filter(|supplier| !supplier.is_null())?;
    let mut identifiers = BTreeSet::new();
    if let Some(name) = supplier.get("name").and_then(Value::as_str) {
        identifiers.insert(format!("name:{name}"));
    }
    if let Some(urls) = supplier.get("url").and_then(Value::as_array) {
        identifiers.extend(
            urls.iter()
                .filter_map(Value::as_str)
                .map(|url| format!("namespace:{url}")),
        );
    }
    Some(ProviderIdentity {
        identifiers,
        ..Default::default()
    })
}

fn reference(node: &mut SourceNode, kind: &str, value: &str) {
    match kind {
        "purl" => {
            if let Ok(purl) = Purl::from_str(value) {
                node.purls.insert(purl.to_string());
            }
        }
        "cpe" => {
            if let Ok(cpe) = Cpe::from_str(value) {
                node.cpes.insert(cpe.uuid());
            }
        }
        _ => {}
    }
}

/// Parse through the ingestor's read-only detector, never its load/re-ingestion path.
fn parse(
    sbom_id: Uuid,
    bytes: &[u8],
    limits: RecoveryLimits,
) -> Result<RecoveredSuppliers, ReportError> {
    let fail = |err: anyhow::Error| ReportError::Source {
        sbom_id,
        source: err,
    };
    let document = DocumentDetector::detect_as(bytes, Format::SBOM)
        .map_err(|err| fail(err.into()))?
        .into_document();
    let mut result = RecoveredSuppliers::default();
    match document {
        DetectedDocument::CycloneDx(cdx) => {
            // Walk the parsed type by reference. Re-serializing the entire schema doubles its live tree
            // and instantiates serializers for unrelated model/crypto/license payloads.
            let mut pending = Vec::new();
            if let Some(root) = cdx
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.component.as_ref())
            {
                pending.push((root, true, true, 0));
            }
            pending.extend(
                cdx.components
                    .iter()
                    .flatten()
                    .map(|component| (component, false, true, 0)),
            );
            while let Some((component, describing, nested, level)) = pending.pop() {
                if level > limits.depth {
                    return Err(ReportError::Limit {
                        sbom_id,
                        reason: "component traversal depth",
                    });
                }
                // Only package suppliers enter main's ProviderSnapshot, not suppliers of files/models.
                let package = matches!(
                    component.type_.as_str(),
                    "application" | "framework" | "library" | "container" | "operating-system"
                );
                if package
                    || matches!(
                        component.type_.as_str(),
                        "machine-learning-model" | "cryptographic-asset"
                    )
                {
                    let supplier = if package {
                        cdx_supplier(&serde_json::json!({"supplier": &component.supplier}))
                    } else {
                        None
                    };
                    if describing && let Some(supplier) = &supplier {
                        result
                            .product
                            .identifiers
                            .extend(supplier.identifiers.clone());
                    }
                    let mut node = SourceNode {
                        reference: component.bom_ref.clone(),
                        name: component.name.to_string(),
                        group: if package {
                            component.group.as_ref().map(ToString::to_string)
                        } else {
                            None
                        },
                        version: if package {
                            component.version.as_ref().map(ToString::to_string)
                        } else {
                            None
                        },
                        purls: BTreeSet::new(),
                        cpes: BTreeSet::new(),
                        supplier,
                        describing,
                    };
                    if let Some(purl) = &component.purl {
                        reference(&mut node, "purl", purl.as_ref());
                    }
                    if let Some(cpe) = &component.cpe {
                        reference(&mut node, "cpe", cpe.as_ref());
                    }
                    if let Some(identity) = component
                        .evidence
                        .as_ref()
                        .and_then(|evidence| evidence.identity.as_ref())
                    {
                        let identity =
                            serde_json::to_value(identity).map_err(|err| fail(err.into()))?;
                        for identity in identity
                            .as_array()
                            .map(Vec::as_slice)
                            .unwrap_or_else(|| from_ref(&identity))
                        {
                            if let (Some(kind), Some(value)) = (
                                identity.get("field").and_then(Value::as_str),
                                identity.get("concludedValue").and_then(Value::as_str),
                            ) {
                                reference(&mut node, kind, value);
                            }
                        }
                    }
                    result.index(node, sbom_id, limits.per_document)?;
                }
                if nested {
                    pending.extend(
                        component
                            .components
                            .iter()
                            .flatten()
                            .map(|child| (child, false, true, level + 1)),
                    );
                }
                // add_component visits pedigree ancestors/variants, not descendants or their nested components.
                if let Some(pedigree) = &component.pedigree {
                    pending.extend(
                        pedigree
                            .ancestors
                            .iter()
                            .flatten()
                            .map(|child| (child, false, false, level + 1)),
                    );
                    pending.extend(
                        pedigree
                            .variants
                            .iter()
                            .flatten()
                            .map(|child| (child, false, false, level + 1)),
                    );
                }
            }
        }
        DetectedDocument::Spdx(value) => {
            let mut describes = value
                .get("documentDescribes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<HashSet<_>>();
            for relation in value
                .get("relationships")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if relation.get("relationshipType").and_then(Value::as_str) == Some("DESCRIBES")
                    && let Some(id) = relation.get("relatedSpdxElement").and_then(Value::as_str)
                {
                    describes.insert(id);
                }
            }
            for value in value
                .get("packages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let reference_id = text(value, "SPDXID");
                let supplier = value
                    .get("supplier")
                    .and_then(Value::as_str)
                    .filter(|value| !matches!(*value, "NONE" | "NOASSERTION"))
                    .map(|name| ProviderIdentity {
                        identifiers: BTreeSet::from([format!("name:{name}")]),
                        ..Default::default()
                    });
                let describing = reference_id
                    .as_deref()
                    .is_some_and(|id| describes.contains(id));
                if describing && let Some(supplier) = &supplier {
                    result
                        .product
                        .identifiers
                        .extend(supplier.identifiers.clone());
                }
                let mut node = SourceNode {
                    reference: reference_id,
                    name: text(value, "name").unwrap_or_default(),
                    group: None,
                    version: text(value, "versionInfo"),
                    purls: BTreeSet::new(),
                    cpes: BTreeSet::new(),
                    supplier,
                    describing,
                };
                for external in value
                    .get("externalRefs")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let (Some(kind), Some(value)) = (
                        external.get("referenceType").and_then(Value::as_str),
                        external.get("referenceLocator").and_then(Value::as_str),
                    ) {
                        reference(
                            &mut node,
                            if matches!(kind, "cpe22Type" | "cpe23Type") {
                                "cpe"
                            } else {
                                kind
                            },
                            value,
                        );
                    }
                }
                result.index(node, sbom_id, limits.per_document)?;
            }
        }
        _ => {
            return Err(ReportError::Unavailable {
                sbom_id,
                reason: "unsupported report source format",
            });
        }
    }
    Ok(result)
}
