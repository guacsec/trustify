//! Release-native inputs for component-local recommendation report resolution.

use super::{SbomPurlRow, StatusInfo};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, FromQueryResult, QueryFilter, QuerySelect,
};
use serde::Serialize;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
};
use tokio::time::{Instant, timeout_at};
use tracing::instrument;
use trustify_common::{db::chunk::chunked_with, purl::Purl};
use trustify_entity::{
    advisory, cpe, package_relates_to_package, relationship::Relationship, sbom, sbom_node_cpe_ref,
    source_document, version_range,
};
use trustify_module_storage::service::{StorageBackend, dispatch::DispatchBackend};
use uuid::Uuid;

/// Shared input/source limits also guard SQL projection before source recovery starts.
pub(super) const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
/// Bound both decompressed source input and retained report-input metadata across a request.
pub(super) const MAX_REQUEST_BYTES: usize = 256 * 1024 * 1024;

mod context;
mod source;

#[cfg(test)]
mod test;

/// A required report input could not be recovered safely; no partial report may be emitted.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("Required report evidence is unavailable for SBOM {sbom_id}: {reason}")]
    Unavailable { sbom_id: Uuid, reason: &'static str },
    #[error("Required report evidence could not be read for SBOM {sbom_id}")]
    Source {
        sbom_id: Uuid,
        #[source]
        source: anyhow::Error,
    },
    #[error("Supplier attribution is ambiguous for node {node_id} in SBOM {sbom_id}")]
    Ambiguous { sbom_id: Uuid, node_id: String },
    #[error("Report evidence recovery limit exceeded for SBOM {sbom_id}: {reason}")]
    Limit { sbom_id: Uuid, reason: &'static str },
    #[error("Database error while recovering report evidence")]
    Database(#[from] DbErr),
}

/// Source identifiers of a supplier; an empty identity is distinct from an absent supplier.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ProviderIdentity {
    identifiers: BTreeSet<String>,
    unavailable: bool,
}

/// Canonical provider output used by report requests; names remain available for assertion identity matching.
#[derive(Default)]
struct ResolvedProvider {
    provider: Option<String>,
    names: BTreeSet<String>,
    conflicting: bool,
}

/// Equivalent resolution inputs may share report membership, unlike a PURL alone.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct ContextKey {
    provider: Option<String>,
    scopes: Vec<(String, String, i32)>,
}

/// Shipped equivalences from main's m0002530, not a vendor-first verdict policy.
const PROVIDER_ALIASES: &[(&str, &[&str])] = &[
    (
        "https://www.redhat.com",
        &[
            "namespace:https://www.redhat.com",
            "name:red hat",
            "name:red hat, inc.",
            "name:red hat product security",
            "purl:rpm/redhat",
            "distro:rhel",
            "cpe-vendor:redhat",
        ],
    ),
    (
        "https://www.suse.com",
        &[
            "namespace:https://www.suse.com",
            "name:suse",
            "name:suse linux products gmbh",
            "purl:rpm/suse",
            "distro:sles",
            "distro:sle",
            "cpe-vendor:suse",
        ],
    ),
];

impl ProviderIdentity {
    /// CSAF namespace is retained in its identifier; issuer names are not equivalent substitutes.
    pub(super) fn from_advisory(advisory: &advisory::Model, issuer: Option<&str>) -> Self {
        match advisory.labels.get("type").map(String::as_str) {
            Some("csaf") => match advisory.identifier.rsplit_once('#') {
                Some((namespace, _)) => Self {
                    identifiers: BTreeSet::from([format!("namespace:{namespace}")]),
                    ..Default::default()
                },
                None => Self {
                    unavailable: true,
                    ..Default::default()
                },
            },
            Some("cve") => Self {
                unavailable: true,
                ..Default::default()
            },
            _ => Self {
                identifiers: issuer
                    .map(|name| BTreeSet::from([format!("name:{name}")]))
                    .unwrap_or_default(),
                ..Default::default()
            },
        }
    }

    fn resolve(&self) -> ResolvedProvider {
        let mut providers = BTreeSet::new();
        let mut fallback = BTreeSet::new();
        let mut names = BTreeSet::new();
        for identifier in &self.identifiers {
            let identifier = normalize(identifier);
            if identifier.starts_with("name:") {
                names.insert(identifier.clone());
            }
            let mapped = PROVIDER_ALIASES
                .iter()
                .filter(|(_, aliases)| aliases.contains(&identifier.as_str()))
                .map(|(provider, _)| provider.to_string())
                .collect::<Vec<_>>();
            if mapped.is_empty() {
                if let Some(namespace) = identifier.strip_prefix("namespace:") {
                    fallback.insert(namespace.to_owned());
                } else if identifier.starts_with("cve-org:") {
                    fallback.insert(identifier.clone());
                }
            } else {
                providers.extend(mapped);
            }
        }
        if providers.is_empty() {
            providers = fallback;
        }
        let conflicting = providers.len() > 1;
        ResolvedProvider {
            provider: if providers.len() == 1 {
                providers.pop_first()
            } else {
                None
            },
            names,
            conflicting,
        }
    }
}

fn normalize(value: &str) -> String {
    let value = value.trim();
    if let Some(name) = value.strip_prefix("name:") {
        let name = name.trim();
        format!(
            "name:{}",
            name.strip_prefix("Organization:")
                .unwrap_or(name)
                .trim()
                .to_lowercase()
        )
    } else {
        value.trim_end_matches('/').to_owned()
    }
}

fn relationship(component: &ResolvedProvider, assertion: &ProviderIdentity) -> u8 {
    let provider = assertion.resolve();
    if component.provider.is_some() && component.provider == provider.provider {
        0
    } else if !(component.names.is_disjoint(&provider.names)
        || component.provider.is_some() && provider.provider.is_some())
    {
        1
    } else if assertion.identifiers.is_empty() && !assertion.unavailable {
        2
    } else {
        3
    }
}

fn priority(status: &str) -> Option<u8> {
    match status {
        "affected" => Some(0),
        "fixed" => Some(1),
        "not_affected" => Some(2),
        "under_investigation" => Some(3),
        _ => None,
    }
}

/// Recovered suppliers are local to one request, never a global cache of mutable source metadata.
pub(super) struct ReportContext {
    suppliers: HashMap<(Uuid, String), Option<ProviderIdentity>>,
    products: HashMap<Uuid, ProviderIdentity>,
    node_purls: HashMap<(Uuid, String), Vec<Purl>>,
    scopes: HashMap<(Uuid, String), Vec<context::WeightedCpe>>,
    assertion_cpes: HashMap<Uuid, cpe::Model>,
    derived_sources: HashSet<Uuid>,
    source_bytes: usize,
}

/// Origin recovery needs only an advisory's retained object identity, not its full repeated metadata.
#[derive(FromQueryResult)]
struct AdvisorySource {
    id: Uuid,
    source_document_id: Uuid,
}

/// Canonical precedence: provider, directness, confidence, status, then stable evidence reference.
type EvidenceRank = (u8, bool, Reverse<i32>, u8, Uuid);

impl ReportContext {
    /// Recover only SBOMs participating in a report winner, within a single recovery budget.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub(super) async fn load<C: ConnectionTrait>(
        rows: &[SbomPurlRow],
        statuses: &HashMap<Uuid, Vec<StatusInfo>>,
        storage: &DispatchBackend,
        connection: &C,
    ) -> Result<Self, ReportError> {
        Self::load_with_limits(
            rows,
            statuses,
            storage,
            connection,
            source::RecoveryLimits::default(),
        )
        .await
    }

    async fn load_with_limits<C: ConnectionTrait, S: StorageBackend>(
        rows: &[SbomPurlRow],
        statuses: &HashMap<Uuid, Vec<StatusInfo>>,
        storage: &S,
        connection: &C,
        limits: source::RecoveryLimits,
    ) -> Result<Self, ReportError>
    where
        S::Error: Into<anyhow::Error>,
    {
        let deadline = Instant::now() + limits.duration;
        let id = rows.first().map(|row| row.sbom_id).unwrap_or_default();
        timeout_at(deadline, async {
            let mut result =
                Self::load_sources(rows, storage, connection, limits, deadline).await?;
            result.scopes = context::load(rows, connection).await?;
            for row in rows {
                result
                    .node_purls
                    .entry((row.sbom_id, row.node_id.to_string()))
                    .or_insert_with(|| row.node_purls.as_ref().clone());
            }
            let ids = statuses
                .values()
                .flatten()
                .filter_map(|info| info.context_cpe_id)
                .collect::<BTreeSet<_>>();
            for ids in chunked_with(1, ids) {
                result.assertion_cpes.extend(
                    cpe::Entity::find()
                        .filter(cpe::Column::Id.is_in(ids))
                        .all(connection)
                        .await?
                        .into_iter()
                        .map(|cpe| (cpe.id, cpe)),
                );
            }
            if !rows.is_empty() {
                let mut needed = HashMap::<Uuid, Vec<source::OriginCandidate>>::new();
                let mut seen = HashSet::new();
                for infos in statuses.values() {
                    let addressable = infos
                        .iter()
                        .filter(|info| {
                            matches!(info.status_slug.as_str(), "fixed" | "not_affected")
                        })
                        .map(|info| info.vuln_id.as_str())
                        .collect::<HashSet<_>>();
                    for info in infos.iter().filter(|info| {
                        addressable.contains(info.vuln_id.as_str())
                            && info.csaf
                            && info.status_slug == "affected"
                            && info.range.low_version.is_none()
                            && info.range.high_version.is_some()
                            && info.range.high_inclusive == Some(false)
                    }) {
                        if seen.insert(info.source_id) {
                            needed.entry(info.advisory_pk).or_default().push(
                                source::OriginCandidate {
                                    source_id: info.source_id,
                                    status_id: info.status_id,
                                    vuln_id: info.vuln_id.clone(),
                                },
                            );
                        }
                    }
                }
                let ids = needed.keys().copied().collect::<Vec<_>>();
                for ids in chunked_with(1, ids) {
                    for advisory in advisory::Entity::find()
                        .select_only()
                        .columns([advisory::Column::Id, advisory::Column::SourceDocumentId])
                        .filter(advisory::Column::Id.is_in(ids))
                        .into_model::<AdvisorySource>()
                        .all(connection)
                        .await?
                    {
                        let metadata =
                            source_document::Entity::find_by_id(advisory.source_document_id)
                                .one(connection)
                                .await?
                                .ok_or(ReportError::Unavailable {
                                    sbom_id: id,
                                    reason: "advisory source metadata is missing",
                                })?;
                        if let Some(candidates) = needed.remove(&advisory.id) {
                            let derived = source::load_origins(
                                id,
                                &metadata,
                                storage,
                                limits,
                                deadline,
                                &mut result.source_bytes,
                                source::OriginRequest {
                                    advisory_id: advisory.id,
                                    candidates,
                                },
                            )
                            .await?;
                            result.derived_sources.extend(derived);
                        }
                    }
                }
                if !needed.is_empty() {
                    return Err(ReportError::Unavailable {
                        sbom_id: id,
                        reason: "advisory origin evidence is missing",
                    });
                }
            }
            Ok(result)
        })
        .await
        .map_err(|_| ReportError::Limit {
            sbom_id: id,
            reason: "source recovery deadline",
        })?
    }

    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn load_sources<C: ConnectionTrait, S: StorageBackend>(
        rows: &[SbomPurlRow],
        storage: &S,
        connection: &C,
        limits: source::RecoveryLimits,
        deadline: Instant,
    ) -> Result<Self, ReportError>
    where
        S::Error: Into<anyhow::Error>,
    {
        let ids = rows.iter().map(|row| row.sbom_id).collect::<BTreeSet<_>>();
        let mut sboms = Vec::new();
        for ids in chunked_with(1, ids) {
            sboms.extend(
                sbom::Entity::find()
                    .filter(sbom::Column::SbomId.is_in(ids))
                    .all(connection)
                    .await?,
            );
        }
        let mut result = Self {
            suppliers: HashMap::new(),
            products: HashMap::new(),
            node_purls: HashMap::new(),
            scopes: HashMap::new(),
            assertion_cpes: HashMap::new(),
            derived_sources: HashSet::new(),
            source_bytes: 0,
        };
        let mut total_bytes = 0;
        for sbom in sboms {
            let metadata = source_document::Entity::find_by_id(sbom.source_document_id)
                .one(connection)
                .await?
                .ok_or(ReportError::Unavailable {
                    sbom_id: sbom.sbom_id,
                    reason: "source metadata is missing",
                })?;
            let recovered = source::load(
                sbom.sbom_id,
                &metadata,
                storage,
                limits,
                deadline,
                &mut total_bytes,
            )
            .await?;
            let describing = package_relates_to_package::Entity::find()
                .filter(package_relates_to_package::Column::SbomId.eq(sbom.sbom_id))
                .filter(
                    package_relates_to_package::Column::Relationship.eq(Relationship::Describes),
                )
                .all(connection)
                .await?
                .into_iter()
                .map(|row| row.right_node_id)
                .collect::<HashSet<_>>();
            let selected = rows
                .iter()
                .filter(|row| row.sbom_id == sbom.sbom_id)
                .collect::<Vec<_>>();
            let node_ids = selected
                .iter()
                .map(|row| row.node_id.clone())
                .collect::<BTreeSet<_>>();
            let mut cpes = HashMap::<String, BTreeSet<Uuid>>::new();
            for nodes in chunked_with(1, node_ids) {
                for row in sbom_node_cpe_ref::Entity::find()
                    .filter(sbom_node_cpe_ref::Column::SbomId.eq(sbom.sbom_id))
                    .filter(
                        sbom_node_cpe_ref::Column::NodeId
                            .is_in(nodes.into_iter().map(|node| node.to_string())),
                    )
                    .all(connection)
                    .await?
                {
                    cpes.entry(row.node_id).or_default().insert(row.cpe_id);
                }
            }
            let empty = BTreeSet::new();
            for row in selected {
                if result
                    .suppliers
                    .contains_key(&(row.sbom_id, row.node_id.to_string()))
                {
                    continue;
                }
                let supplier = recovered.supplier_for(
                    row,
                    cpes.get(row.node_id.as_ref()).unwrap_or(&empty),
                    &describing,
                )?;
                result
                    .suppliers
                    .insert((row.sbom_id, row.node_id.to_string()), supplier);
            }
            let mut product = recovered.product;
            product.identifiers.extend(
                sbom.suppliers
                    .into_iter()
                    .filter(|name| !matches!(name.as_str(), "NOASSERTION" | "NONE"))
                    .map(|name| format!("name:{name}")),
            );
            result.products.insert(sbom.sbom_id, product);
        }
        result.source_bytes = total_bytes;
        Ok(result)
    }

    fn component_provider(&self, key: &(Uuid, String)) -> ResolvedProvider {
        if let Some(Some(supplier)) = self.suppliers.get(key) {
            return supplier.resolve();
        }
        let mut distribution = BTreeSet::new();
        let mut packages = BTreeSet::new();
        for purl in self.node_purls.get(key).into_iter().flatten() {
            if let Some(distro) = purl.qualifiers.get("distro") {
                distribution.insert(format!("distro:{distro}"));
                distribution.insert(format!(
                    "distro:{}",
                    distro.split('-').next().unwrap_or(distro)
                ));
            }
            if let Some(namespace) = &purl.namespace {
                packages.insert(format!("purl:{}/{namespace}", purl.ty));
            }
        }
        for identifiers in [distribution, packages] {
            let provider = ProviderIdentity {
                identifiers,
                ..Default::default()
            }
            .resolve();
            if provider.provider.is_some() || provider.conflicting {
                return provider;
            }
        }
        if let Some(product) = self
            .products
            .get(&key.0)
            .filter(|product| !product.identifiers.is_empty())
        {
            return product.resolve();
        }
        let identifiers = self
            .scopes
            .get(key)
            .into_iter()
            .flatten()
            .filter(|scope| scope.confidence_is_local())
            .filter_map(|scope| {
                scope
                    .cpe
                    .vendor
                    .as_ref()
                    .map(|vendor| format!("cpe-vendor:{vendor}"))
            })
            .collect();
        ProviderIdentity {
            identifiers,
            ..Default::default()
        }
        .resolve()
    }

    /// Group only equivalent canonical provider and weighted product-context inputs.
    pub(super) fn key(&self, sbom_id: Uuid, node_id: &str) -> ContextKey {
        let key = (sbom_id, node_id.to_owned());
        ContextKey {
            provider: self.component_provider(&key).provider,
            scopes: context::key(self.scopes.get(&key).map(Vec::as_slice).unwrap_or_default()),
        }
    }

    /// Select one eligible assessment per CVE before the caller filters addressing outcomes.
    pub(super) fn resolve<'a>(
        &self,
        sbom_id: Uuid,
        node_id: &str,
        base: &Purl,
        statuses: &'a [StatusInfo],
    ) -> Result<Vec<&'a StatusInfo>, ReportError> {
        let key = (sbom_id, node_id.to_owned());
        let mut provider = self.component_provider(&key);
        // Main's report passes a canonical component_provider override, not an unresolved display name.
        provider.names.clear();
        let addressable = statuses
            .iter()
            .filter(|info| matches!(info.status_slug.as_str(), "fixed" | "not_affected"))
            .map(|info| info.vuln_id.as_str())
            .collect::<HashSet<_>>();
        let relevant = statuses
            .iter()
            .filter(|info| addressable.contains(info.vuln_id.as_str()))
            .collect::<Vec<_>>();
        let identifier_bytes = base.to_string().len();
        let mut expanded_bytes = 0usize;
        for info in &relevant {
            let bytes = identifier_bytes
                .saturating_add(info.vuln_id.len())
                .saturating_add(info.status_slug.len())
                .saturating_add(info.advisory_id.as_ref().map_or(0, String::len))
                .saturating_add(info.range.low_version.as_ref().map_or(0, String::len))
                .saturating_add(info.range.high_version.as_ref().map_or(0, String::len));
            // Group keys, range projection and reference serialization can each materialize these bytes.
            expanded_bytes = expanded_bytes
                .saturating_add(bytes.saturating_mul(3))
                .saturating_add(256);
            if expanded_bytes > MAX_REQUEST_BYTES {
                return Err(ReportError::Limit {
                    sbom_id,
                    reason: "expanded report evidence metadata byte limit",
                });
            }
        }
        let own_stream = relevant
            .iter()
            .filter(|info| {
                matches!(
                    context::stream_match(base, &info.range),
                    Some(context::StreamScope::Exact | context::StreamScope::Major)
                )
            })
            .map(|info| (info.advisory_pk, info.vuln_id.as_str()))
            .collect::<BTreeSet<_>>();
        let mut groups = BTreeMap::<_, Vec<(&StatusInfo, context::StreamScope)>>::new();
        for info in relevant
            .iter()
            .filter(|info| priority(&info.status_slug).is_some())
        {
            let Some(stream) = context::stream_match(base, &info.range) else {
                continue;
            };
            if stream == context::StreamScope::Minor
                && own_stream.contains(&(info.advisory_pk, info.vuln_id.as_str()))
            {
                continue;
            }
            let derived = self.derived_sources.contains(&info.source_id);
            let mut identifier = base.to_base();
            if derived
                || (info.csaf
                    && info.range.low_version.is_some()
                    && info.range.low_version == info.range.high_version
                    && info.range.low_inclusive == Some(true)
                    && info.range.high_inclusive == Some(true))
            {
                identifier.version = info.range.high_version.clone();
            }
            groups
                .entry((
                    &info.vuln_id,
                    info.advisory_pk,
                    &info.status_slug,
                    info.context_cpe_id,
                    identifier.to_string(),
                    derived,
                    if derived {
                        "purl_fixed_as_first_fixed_before"
                    } else {
                        stream.extractor()
                    },
                ))
                .or_default()
                .push((info, stream));
        }
        let mut selected = BTreeMap::<&str, (EvidenceRank, &StatusInfo)>::new();
        for ((vuln, _, status, context_id, identifier, derived, extractor), infos) in groups {
            let Some((info, stream)) = infos
                .iter()
                .max_by_key(|(info, stream)| (stream.confidence(), Reverse(info.source_id)))
                .copied()
            else {
                continue;
            };
            let required = stream != context::StreamScope::Exact
                && (derived || stream == context::StreamScope::Minor);
            let scope_confidence = if let Some(id) = context_id {
                let cpe = self
                    .assertion_cpes
                    .get(&id)
                    .ok_or(ReportError::Unavailable {
                        sbom_id,
                        reason: "assertion product context is missing",
                    })?;
                context::confidence_required(
                    cpe,
                    self.scopes.get(&key).map(Vec::as_slice).unwrap_or_default(),
                    required,
                )
            } else {
                if required { 0 } else { 100 }
            };
            let range_confidence =
                (stream.confidence() * if derived { 90 } else { 100 } + 50) / 100;
            let confidence = (range_confidence * scope_confidence + 50) / 100;
            if confidence == 0 {
                continue;
            }
            let ranges = infos
                .iter()
                .map(|(info, _)| ReferenceRange::from(info.range.as_ref()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let value = ReferenceValue {
                origin: if derived {
                    "publisher_policy"
                } else {
                    "stated"
                },
                identifier,
                ranges,
            };
            let reference = Uuid::new_v5(
                &info.advisory_pk,
                serde_json::json!([extractor, value, status])
                    .to_string()
                    .as_bytes(),
            );
            // Legacy ingestion also generated affected-before rows; direct statements rank first.
            let rank = (
                relationship(&provider, &info.provider),
                derived,
                Reverse(confidence),
                priority(status).unwrap_or(u8::MAX),
                reference,
            );
            let entry = selected.entry(vuln.as_str()).or_insert((rank, info));
            if rank < entry.0 {
                *entry = (rank, info);
            }
        }
        Ok(selected.into_values().map(|(_, info)| info).collect())
    }
}

/// Canonical PURL match payload, used only for the deterministic evidence reference.
#[derive(Serialize)]
struct ReferenceValue {
    origin: &'static str,
    identifier: String,
    ranges: Vec<ReferenceRange>,
}

/// Keep the canonical range ordering and omission rules, rather than sorting database row IDs.
#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct ReferenceRange {
    scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    low: Option<ReferenceBound>,
    #[serde(skip_serializing_if = "Option::is_none")]
    high: Option<ReferenceBound>,
}

/// Inclusive/exclusive bounds are part of evidence identity.
#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct ReferenceBound {
    version: String,
    inclusive: bool,
}

impl From<&version_range::Model> for ReferenceRange {
    fn from(range: &version_range::Model) -> Self {
        Self {
            scheme: range.version_scheme_id.to_string(),
            low: range.low_version.as_ref().map(|version| ReferenceBound {
                version: version.clone(),
                inclusive: range.low_inclusive.unwrap_or(false),
            }),
            high: range.high_version.as_ref().map(|version| ReferenceBound {
                version: version.clone(),
                inclusive: range.high_inclusive.unwrap_or(false),
            }),
        }
    }
}
