//! Correlation by PURL: `sbom_node_purl_ref` ↔ `purl_status`.
//!
//! Unlike digest/product_identifier which use exact value matching, PURL
//! matching requires version-range evaluation via the `version_matches()`
//! PostgreSQL function.
//!
//! Matches are additionally scoped by the [`ecosystem`] of the package: the qualifiers of the
//! advisory's PURL (e.g. the architecture of an RPM), and the stream of the release.
//!
//! RPMs are scoped by the stream of the release (e.g. `el8_6` of `1.1.1k-9.el8_6`): the stream of
//! the SBOM version must equal the stream of the matched range, or share its major (e.g. `el8`)
//! with a lower confidence. Ranges of other streams (e.g. `el9_0` for an `el8` package) are
//! dropped. Such matches are reported as `purl_stream` evidence.
//!
//! SUSE packages (`pkg:rpm/suse/…`) carry no dist tag, but a codestream at the start of the release
//! (e.g. `150600` of `3.1.4-150600.5.39.1` for SLE 15 SP6). They only match ranges of the same
//! codestream (or both have none), see [`ecosystem::rpm::suse_stream_match`].
//!
//! All other matches (not RPM, or without a stream on either side) are reported as `purl`
//! evidence.
//!
//! A default status (CVE `defaultStatus`, stored as an unbounded range) is the status of all
//! versions no other statement of the advisory lists for the package. It is only used for a node
//! if no listed statement of the same advisory, vulnerability, and package matches it, and
//! reported as `purl_default` evidence.
//!
//! Besides the stated ranges, [`rule`]s derive implied ranges from what advisories state (e.g.
//! Red Hat's "fixed in X" implies "affected before X"), or evaluate stated ranges differently (e.g.
//! a CSAF vls range, which states no versioning scheme, with the scheme of the PURL type). Those
//! are matched the same way, but reported as evidence of the rule's own type. A rule may depend on
//! a correlation option of the advisory's publisher (e.g. versionless PURLs meaning all versions),
//! which its evidence then records (`enabled_by`).

pub mod ecosystem;
pub mod rule;

#[cfg(test)]
mod test;

use self::{
    ecosystem::{Ecosystem, StreamMatch},
    rule::{RangeRule, rules},
};
use super::{Assertion, Extractor, IdentifierMatch, NodeIdentifier, NodeMatch, NodeRef};
use crate::{
    error::Error,
    model::{
        AssertionOrigin, ConfidenceFactor, ConfidenceReason, EnabledBy, IdentifierKind,
        IdentifierRef, MatchedRange, MatchedValue, combine,
    },
};
use futures_util::TryStreamExt;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, EntityTrait, FromQueryResult,
    JoinType, QueryFilter, Statement,
    sea_query::{
        Alias, CommonTableExpression, Expr, ExprTrait, Func, Order, PgFunc, PostgresQueryBuilder,
        Query, SelectStatement, SimpleExpr, UnionType, WithClause, WithQuery,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    iter,
    mem::take,
    sync::Arc,
};
use tracing::{Instrument, Span, field, info_span, instrument};
use trustify_common::{db::VersionMatches, purl::Purl};
use trustify_entity::{
    advisory, base_purl, correlation_evidence::AssertionStatus, correlation_node_class,
    purl_status, qualified_purl, query::ForNodes, sbom_node_purl_ref, status, version_range,
    version_scheme::VersionScheme, versioned_purl,
};
use uuid::Uuid;

/// Extracts correlation evidence by matching SBOM PURLs against advisory
/// `purl_status` entries via base-package identity and version-range matching.
pub struct PurlExtractor;

/// ID of the extractor, and type of the evidence matched by version range only.
const PLAIN: &str = "purl";
/// Type of the evidence matched by version range and RPM stream.
const STREAM: &str = "purl_stream";
/// Type of the evidence of a default status.
const DEFAULT: &str = "purl_default";

/// Confidence of a default status: it covers all versions not listed, which is less specific than a
/// listed version or range.
pub(crate) const DEFAULT_CONFIDENCE: f64 = 0.9;

const CONFIDENCE: f64 = 1.0;

fn map_status(slug: &str) -> Option<AssertionStatus> {
    match slug {
        "affected" => Some(AssertionStatus::Affected),
        "fixed" => Some(AssertionStatus::Fixed),
        "not_affected" => Some(AssertionStatus::NotAffected),
        "under_investigation" => Some(AssertionStatus::UnderInvestigation),
        "recommended" => Some(AssertionStatus::Recommended),
        _ => None,
    }
}

/// Candidate version ranges to match, as SQL over the stated `purl_status` rows (with their
/// joined `status`, `version_range`, and `base_purl`).
///
/// The stated candidates are the rows themselves. A [`RangeRule`] derives other candidates from
/// (some of) them.
///
/// The range (`scheme` and the bounds) must only depend on `version_range`, `base_purl`, and
/// constants. Matching evaluates `version_matches()` once per stated range and SBOM version,
/// shared by all rows (e.g. of different advisories) stating that range.
pub struct Candidates {
    /// The stated rows to derive candidates from.
    pub condition: SimpleExpr,
    /// The status (slug) of the candidate.
    pub status: SimpleExpr,
    /// The version scheme (ID) to evaluate the candidate range with.
    pub scheme: SimpleExpr,
    /// Lower bound of the candidate range, `NULL` if unbounded.
    pub low_version: SimpleExpr,
    /// Whether the lower bound is inclusive.
    pub low_inclusive: SimpleExpr,
    /// Upper bound of the candidate range, `NULL` if unbounded.
    pub high_version: SimpleExpr,
    /// Whether the upper bound is inclusive.
    pub high_inclusive: SimpleExpr,
}

impl Candidates {
    /// The stated rows, as they are.
    fn stated() -> Self {
        Self {
            condition: Expr::value(true),
            status: Expr::col((status::Entity, status::Column::Slug)),
            scheme: stated_scheme(),
            low_version: range_col(version_range::Column::LowVersion),
            low_inclusive: range_col(version_range::Column::LowInclusive),
            high_version: range_col(version_range::Column::HighVersion),
            high_inclusive: range_col(version_range::Column::HighInclusive),
        }
    }

    /// The candidate status and range, if the stated row is a candidate: one branch of the
    /// lateral union over all sources.
    fn branch(&self, source: i32) -> SelectStatement {
        Query::select()
            .expr_as(Expr::val(source), Alias::new("source"))
            .expr_as(self.status.clone(), Alias::new("slug"))
            .expr_as(self.scheme.clone(), Alias::new("range_scheme"))
            .expr_as(self.low_version.clone(), Alias::new("range_low_version"))
            .expr_as(
                self.low_inclusive.clone(),
                Alias::new("range_low_inclusive"),
            )
            .expr_as(self.high_version.clone(), Alias::new("range_high_version"))
            .expr_as(
                self.high_inclusive.clone(),
                Alias::new("range_high_inclusive"),
            )
            .and_where(self.condition.clone())
            .to_owned()
    }
}

/// `version_matches()` of a version and a range (ID, scheme, low, low inclusive, high, high
/// inclusive).
fn version_matches(version: SimpleExpr, range: [SimpleExpr; 6]) -> SimpleExpr {
    let range = Expr::cust_with_exprs("ROW($1, $2, $3, $4, $5, $6)::version_range", range);
    SimpleExpr::FunctionCall(Func::cust(VersionMatches).arg(version).arg(range))
}

/// The version scheme of the stated `version_range`.
pub fn stated_scheme() -> SimpleExpr {
    range_col(version_range::Column::VersionSchemeId)
}

/// A column of the stated `version_range`.
fn range_col(column: version_range::Column) -> SimpleExpr {
    Expr::col((version_range::Entity, column))
}

/// Where candidates come from: stated (`None`), or a rule.
type Source<'a> = Option<&'a dyn RangeRule>;

/// The stated candidates, followed by the ones of all rules.
fn sources(rules: &[Box<dyn RangeRule>]) -> impl Iterator<Item = (Source<'_>, Candidates)> {
    iter::once((None, Candidates::stated())).chain(
        rules
            .iter()
            .map(|rule| (Some(rule.as_ref()), rule.candidates())),
    )
}

/// What a stated `purl_status` row says, independent of the version it matched.
///
/// Loaded and prepared once per row, as one row matches many versions and nodes (e.g. one kernel
/// advisory row matches the kernel nodes of every SBOM).
struct Stated {
    source_id: Uuid,
    advisory_id: Uuid,
    vulnerability_id: String,
    base_purl_type: String,
    base_purl_namespace: Option<String>,
    base_purl_name: String,
    ecosystem: Ecosystem,
    /// Qualifiers of the advisory PURL, `None` without one.
    qualifiers: Option<BTreeMap<String, String>>,
    /// The original advisory PURL, or the legacy base identity.
    identifier: String,
    /// The stated provider, serialized, distinguishing statements of different providers.
    provider_key: String,
    provider: Option<crate::model::ProviderIdentity>,
    publisher_namespace: Option<String>,
    assertion_context_id: Option<Uuid>,
    is_default: bool,
}

/// The columns of [`Stated`], as loaded.
#[derive(FromQueryResult)]
struct StatedModel {
    source_id: Uuid,
    advisory_id: Uuid,
    vulnerability_id: String,
    base_purl_type: String,
    base_purl_namespace: Option<String>,
    base_purl_name: String,
    source_purl: Option<qualified_purl::CanonicalPurl>,
    source_provider: Option<serde_json::Value>,
    publisher_namespace: Option<String>,
    assertion_context_id: Option<Uuid>,
    is_default: bool,
}

impl From<StatedModel> for Stated {
    fn from(model: StatedModel) -> Self {
        let ecosystem = Ecosystem::of(&model.base_purl_type, model.base_purl_namespace.as_deref());
        let qualifiers = model
            .source_purl
            .as_ref()
            .map(|purl| purl.qualifiers.clone());
        let identifier = model
            .source_purl
            .map(Purl::from)
            .unwrap_or_else(|| Purl {
                ty: model.base_purl_type.clone(),
                namespace: model.base_purl_namespace.clone(),
                name: model.base_purl_name.clone(),
                version: None,
                qualifiers: Default::default(),
            })
            .to_string();
        let provider_key = model
            .source_provider
            .as_ref()
            .map(serde_json::Value::to_string)
            .unwrap_or_default();
        let provider = model.source_provider.map(|provider| {
            serde_json::from_value(provider).unwrap_or(crate::model::ProviderIdentity {
                unavailable: true,
                ..Default::default()
            })
        });
        Self {
            source_id: model.source_id,
            advisory_id: model.advisory_id,
            vulnerability_id: model.vulnerability_id,
            base_purl_type: model.base_purl_type,
            base_purl_namespace: model.base_purl_namespace,
            base_purl_name: model.base_purl_name,
            ecosystem,
            qualifiers,
            identifier,
            provider_key,
            provider,
            publisher_namespace: model.publisher_namespace,
            assertion_context_id: model.assertion_context_id,
            is_default: model.is_default,
        }
    }
}

/// The stated rows, by ID.
type StatedRows = HashMap<Uuid, Arc<Stated>>;

/// Stated rows of one package and range matching a version: their source's candidate status and
/// range, and the version.
#[derive(FromQueryResult)]
struct MatchRow {
    /// Index of the candidate source, see [`sources`].
    source: i32,
    /// The stated rows, which share everything else.
    status_ids: Vec<Uuid>,
    slug: String,
    range_id: Uuid,
    range_scheme: VersionScheme,
    range_low_version: Option<String>,
    range_low_inclusive: Option<bool>,
    range_high_version: Option<String>,
    range_high_inclusive: Option<bool>,
    sbom_version: String,
}

impl MatchRow {
    /// One row per stated row, with the SBOM qualifiers. Stated rows which are gone are skipped.
    ///
    /// Empty if [`group`] can't use the rows for any target ([`PurlStatusRow::is_relevant`]).
    /// That only depends on what the stated rows share (the package, the range and the
    /// version), so it is decided once.
    fn into_rows(
        self,
        stated: &StatedRows,
        sbom_qualifiers: &qualified_purl::Qualifiers,
    ) -> Vec<PurlStatusRow> {
        let matched = Arc::new(self);
        let rows = matched
            .status_ids
            .iter()
            .filter_map(|id| stated.get(id))
            .map(|stated| PurlStatusRow {
                stated: stated.clone(),
                matched: matched.clone(),
                sbom_qualifiers: sbom_qualifiers.clone(),
            })
            .collect::<Vec<_>>();
        if rows.first().is_some_and(PurlStatusRow::is_relevant) {
            rows
        } else {
            Vec::new()
        }
    }
}

/// The advisory side of a matched `purl_status`, plus the SBOM version it matched.
#[derive(Clone)]
struct PurlStatusRow {
    stated: Arc<Stated>,
    matched: Arc<MatchRow>,
    sbom_qualifiers: qualified_purl::Qualifiers,
}

impl PurlStatusRow {
    /// If [`group`] can use the row for any target: it is of the target's stream (or unscoped),
    /// and of a known status. Rows failing this are dropped before they are copied or grouped.
    fn is_relevant(&self) -> bool {
        self.stream_match().is_some() && map_status(&self.matched.slug).is_some()
    }

    /// If the qualifiers of the SBOM package are compatible with the ones of the advisory PURL.
    fn qualifiers_match(&self) -> bool {
        self.stated.qualifiers.as_ref().is_none_or(|qualifiers| {
            self.stated
                .ecosystem
                .qualifiers_match(&self.sbom_qualifiers.0, qualifiers)
        })
    }

    /// The package a listed status shadows the default of.
    fn package(&self) -> (Uuid, &str, &str, Option<&str>, &str) {
        let stated = &self.stated;
        (
            stated.advisory_id,
            stated.vulnerability_id.as_str(),
            stated.base_purl_type.as_str(),
            stated.base_purl_namespace.as_deref(),
            stated.base_purl_name.as_str(),
        )
    }

    /// Relation of the streams of the SBOM version and the range.
    fn stream_match(&self) -> Option<StreamMatch> {
        self.stated.ecosystem.stream_match(
            &self.matched.sbom_version,
            self.matched.range_low_version.as_deref(),
            self.matched.range_high_version.as_deref(),
        )
    }

    /// The matched version range.
    fn range(&self) -> MatchedRange {
        let matched = &self.matched;
        version_range::Model {
            id: matched.range_id,
            version_scheme_id: matched.range_scheme,
            low_version: matched.range_low_version.clone(),
            low_inclusive: matched.range_low_inclusive,
            high_version: matched.range_high_version.clone(),
            high_inclusive: matched.range_high_inclusive,
        }
        .into()
    }
}

#[derive(FromQueryResult)]
struct PurlStatusMatch {
    versioned_purl_id: Uuid,
    #[sea_orm(nested)]
    matched: MatchRow,
}

#[derive(FromQueryResult)]
struct AdvisoryPurlMatch {
    sbom_id: Uuid,
    node_id: String,
    sbom_qualifiers: qualified_purl::Qualifiers,
    #[sea_orm(nested)]
    matched: MatchRow,
}

/// Group the matching `purl_status` rows by target and assertion, merging their version ranges.
///
/// Several ranges (e.g. of different product streams) of the same vulnerability may match. They
/// result in the same evidence row, which therefore lists all of them, in a stable order.
///
/// Rows of a different RPM stream are dropped. Rows of another minor of the same major are only
/// used as a fallback: if the advisory states nothing about the vulnerability in the target's own
/// stream. The others are grouped by their evidence type too: the rule's for derived rows,
/// otherwise [`StreamMatch::extractor`]. The confidence of a group is the best of its ranges. This
/// is evaluated here, on the rows already loaded by `version_matches`, as it also determines the
/// type and confidence.
fn group<'a, K: Ord + Clone>(
    rows: impl IntoIterator<Item = (K, Source<'a>, PurlStatusRow)>,
) -> impl Iterator<Item = (K, Assertion)> {
    /// The merged rows of one assertion.
    struct Group {
        status: AssertionStatus,
        source_provider: Option<crate::model::ProviderIdentity>,
        origin: AssertionOrigin,
        confidence: f64,
        factors: Vec<ConfidenceFactor>,
        ranges: BTreeSet<MatchedRange>,
        enabled_by: Option<EnabledBy>,
        requires_context: bool,
        source_assertions: BTreeSet<super::SourceAssertionRef>,
    }

    let mut groups = BTreeMap::<
        (
            K,
            &'static str,
            Uuid,
            String,
            String,
            String,
            Option<Uuid>,
            String,
        ),
        Group,
    >::new();
    let rows = rows
        .into_iter()
        .filter_map(|(target, source, row)| {
            if !row.qualifiers_match() {
                return None;
            }
            let status = map_status(&row.matched.slug)?;
            let stream = row.stream_match()?;
            Some((target, source, row, status, stream))
        })
        .collect::<Vec<_>>();
    // the vulnerabilities an advisory states something about in a target's own stream
    let own_stream = rows
        .iter()
        .filter(|(.., stream)| matches!(stream, StreamMatch::Exact | StreamMatch::Major))
        .map(|(target, _, row, ..)| {
            (
                target.clone(),
                row.stated.advisory_id,
                row.stated.vulnerability_id.clone(),
                row.stated.provider_key.clone(),
            )
        })
        .collect::<BTreeSet<_>>();

    // the packages of a target with a listed status, shadowing their defaults
    let listed = rows
        .iter()
        .filter(|(_, source, row, ..)| {
            !row.stated.is_default
                && source.is_none_or(|rule| rule.origin() == AssertionOrigin::Stated)
        })
        .map(|(target, _, row, ..)| {
            (
                target.clone(),
                row.package(),
                row.stated.provider_key.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let shadowed = rows
        .iter()
        .map(|(target, _, row, ..)| {
            row.stated.is_default
                && listed.contains(&(
                    target.clone(),
                    row.package(),
                    row.stated.provider_key.clone(),
                ))
        })
        .collect::<Vec<_>>();

    for ((target, source, row, status, stream), shadowed) in rows.into_iter().zip(shadowed) {
        if shadowed {
            continue;
        }
        if stream == StreamMatch::Minor
            && own_stream.contains(&(
                target.clone(),
                row.stated.advisory_id,
                row.stated.vulnerability_id.clone(),
                row.stated.provider_key.clone(),
            ))
        {
            continue;
        }
        let (extractor, factors) = match source {
            None if row.stated.is_default => (
                DEFAULT,
                vec![
                    stream.factor(),
                    ConfidenceFactor::new(ConfidenceReason::DefaultStatus, DEFAULT_CONFIDENCE),
                ],
            ),
            None => (stream.extractor(), vec![stream.factor()]),
            Some(rule) => (
                rule.id(),
                vec![
                    stream.factor(),
                    ConfidenceFactor::new(
                        ConfidenceReason::Rule {
                            rule: rule.id().to_string(),
                        },
                        rule.confidence(),
                    ),
                ],
            ),
        };
        // rounded, so that e.g. 0.8 × 0.9 is stored as 0.72
        let confidence = combine(&factors);
        let origin = match source {
            Some(rule) => rule.origin(),
            None if row.stated.is_default => AssertionOrigin::Default,
            None => AssertionOrigin::Stated,
        };
        let enabled_by =
            source.and_then(|rule| rule.enabled_by(row.stated.publisher_namespace.as_deref()));
        // an equal RPM stream puts the node into the statement's product already, another minor
        // only applies within the product
        let requires_context = match stream {
            StreamMatch::Exact => false,
            StreamMatch::Minor => true,
            StreamMatch::Major | StreamMatch::Unscoped => {
                source.is_some_and(|rule| rule.requires_context())
            }
        };
        let stated = row.stated.clone();
        let slug = row.matched.slug.clone();
        let range = row.range();
        let entry = groups
            .entry((
                target,
                extractor,
                stated.advisory_id,
                stated.vulnerability_id.clone(),
                slug,
                stated.identifier.clone(),
                stated.assertion_context_id,
                stated.provider_key.clone(),
            ))
            .or_insert_with(|| Group {
                status,
                source_provider: stated.provider.clone(),
                origin,
                confidence,
                factors: factors.clone(),
                ranges: BTreeSet::new(),
                enabled_by,
                requires_context,
                source_assertions: BTreeSet::new(),
            });
        // the best range of the group decides its confidence
        if confidence > entry.confidence {
            entry.confidence = confidence;
            entry.factors = factors;
        }
        entry.ranges.insert(range);
        entry
            .source_assertions
            .insert(super::SourceAssertionRef::Purl(stated.source_id));
    }

    // An assertion requiring a context, without one, is dropped by any scoping (see
    // `context::scope`). Those are most of the rows of a package with many products (e.g. a
    // kernel's minor stream fallbacks), so they are dropped here, before being copied for targets.
    // They are only dropped after grouping, as they still shadow defaults and other streams.
    groups
        .into_iter()
        .filter(|((.., context_id, _), group)| !group.requires_context || context_id.is_some())
        .map(
            |(
                (target, extractor, advisory_id, vulnerability_id, _, identifier, context_id, _),
                group,
            )| {
                (
                    target,
                    Assertion {
                        extractor,
                        advisory_id,
                        vulnerability_id,
                        status: group.status,
                        confidence: group.confidence,
                        factors: group.factors,
                        matched_value: MatchedValue {
                            source_provider: group.source_provider,
                            origin: group.origin,
                            identifier,
                            ranges: group.ranges.into_iter().collect(),
                            enabled_by: group.enabled_by,
                        },
                        context_id,
                        requires_context: group.requires_context,
                        version_range_id: None,
                        source_assertions: group.source_assertions,
                    },
                )
            },
        )
}

#[async_trait::async_trait]
impl Extractor for PurlExtractor {
    fn id(&self) -> &'static str {
        PLAIN
    }

    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn sbom_identifiers(
        &self,
        sbom_id: Uuid,
        nodes: Option<&[&str]>,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        // joined instead of `load_one`, which binds one parameter per ref and exceeds the
        // parameter limit for large SBOMs
        let purl_refs = sbom_node_purl_ref::Entity::find()
            .filter(sbom_node_purl_ref::Column::SbomId.eq(sbom_id))
            .for_nodes(nodes)
            .find_also_related(qualified_purl::Entity)
            .all(tx)
            .instrument(info_span!("loading purl refs"))
            .await?;

        Ok(purl_refs
            .into_iter()
            .filter_map(|(purl_ref, qp)| {
                Some(NodeIdentifier {
                    identifier: IdentifierRef {
                        kind: IdentifierKind::Purl,
                        value: Purl::from(qp?.purl).to_string(),
                    },
                    node: NodeRef {
                        sbom_id: purl_ref.sbom_id,
                        node_id: purl_ref.node_id,
                    },
                })
            })
            .collect())
    }

    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn match_identifiers(
        &self,
        identifiers: &[IdentifierRef],
        tx: &DatabaseTransaction,
    ) -> Result<Vec<IdentifierMatch>, Error> {
        match_batched(identifiers, BATCH, tx).await
    }

    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn match_advisory(
        &self,
        advisory_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeMatch>, Error> {
        let rules = rules(tx).await?;
        let sources = sources(&rules).collect::<Vec<_>>();
        load_advisory_purl_matches(advisory_id, &sources, tx).await
    }
}

/// The source of a row, by its index in the statement's sources.
fn source_of<'a>(sources: &[(Source<'a>, Candidates)], index: i32) -> Result<Source<'a>, Error> {
    usize::try_from(index)
        .ok()
        .and_then(|i| sources.get(i))
        .map(|(source, _)| *source)
        .ok_or(Error::CandidateSource(index))
}

/// Versioned PURLs matched per statement, bounding the rows loaded at once.
const BATCH: usize = 1000;

/// Match identifiers in batches of about `batch_size` versioned PURLs.
///
/// [`group`] only relates rows of the same target, and each target has a single versioned PURL,
/// so batches can be grouped independently. All versions of a package share a batch, as the
/// statement scans the stated rows per package. The ones [`group`] drops regardless of the target
/// (another stream, or an unknown status) are dropped right after loading, before they are copied
/// for each target of their versioned PURL.
async fn match_batched(
    identifiers: &[IdentifierRef],
    batch_size: usize,
    tx: &DatabaseTransaction,
) -> Result<Vec<IdentifierMatch>, Error> {
    // Versions share candidate lookups, but each input retains its own qualifiers.
    let mut vp_map = VersionTargets::new();
    let mut packages = BTreeMap::<Uuid, BTreeSet<Uuid>>::new();
    for (idx, identifier) in identifiers.iter().enumerate() {
        if identifier.kind != IdentifierKind::Purl {
            continue;
        }
        let Ok(purl) = identifier.value.parse::<Purl>() else {
            continue;
        };
        if purl.version.is_none() {
            continue;
        }
        let version = purl.version_uuid();
        packages
            .entry(purl.package_uuid())
            .or_default()
            .insert(version);
        vp_map
            .entry(version)
            .or_default()
            .push((idx, qualified_purl::Qualifiers(purl.qualifiers)));
    }

    if vp_map.is_empty() {
        return Ok(Vec::new());
    }

    let rules = rules(tx).await?;
    let sources = sources(&rules).collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut batch = Vec::with_capacity(batch_size.min(vp_map.len()));
    let mut packages = packages.into_values().peekable();
    while let Some(versions) = packages.next() {
        batch.extend(versions);
        if batch.len() < batch_size && packages.peek().is_some() {
            continue;
        }
        result.extend(match_batch(take(&mut batch), &vp_map, &sources, tx).await?);
    }
    Ok(result)
}

/// The identifiers of each versioned PURL: their index and qualifiers.
type VersionTargets = HashMap<Uuid, Vec<(usize, qualified_purl::Qualifiers)>>;

/// Match one batch of versioned PURLs, and group the rows per identifier.
#[instrument(
    skip_all,
    fields(
        versions = versions.len(),
        rows = field::Empty,
        statuses = field::Empty,
        grouped = field::Empty,
        matches = field::Empty,
    ),
    err(level = tracing::Level::INFO)
)]
async fn match_batch(
    versions: Vec<Uuid>,
    vp_map: &VersionTargets,
    sources: &[(Source<'_>, Candidates)],
    tx: &DatabaseTransaction,
) -> Result<Vec<IdentifierMatch>, Error> {
    let rows = load_purl_status_matches(versions, sources, tx).await?;
    let ids = rows
        .iter()
        .flat_map(|row| row.matched.status_ids.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let stated = load_stated(
        Expr::col((purl_status::Entity, purl_status::Column::Id)).eq(ids_param(&ids)),
        tx,
    )
    .await?;
    let span = Span::current();
    span.record("rows", rows.len());
    span.record("statuses", ids.len());

    // the stated rows of each versioned PURL, without the qualifiers of a target
    let mut versions = HashMap::<Uuid, Vec<_>>::new();
    for row in rows {
        let source = source_of(sources, row.matched.source)?;
        let entry = versions.entry(row.versioned_purl_id).or_default();
        for status in row
            .matched
            .into_rows(&stated, &qualified_purl::Qualifiers::default())
        {
            entry.push((source, status));
        }
    }

    // `group` only relates the rows of one target, and only depends on its versioned PURL and
    // matched qualifiers: group once per distinct pair, and one pair at a time, as copying all rows for
    // all targets at once doesn't fit into memory (e.g. 15M rows for the kernel of a RHEL SBOM).
    let mut grouped = 0;
    let mut result = Vec::new();
    for (version, rows) in versions {
        let mut by_qualifiers = BTreeMap::<_, Vec<usize>>::new();
        for (idx, qualifiers) in vp_map.get(&version).map(Vec::as_slice).unwrap_or_default() {
            by_qualifiers
                .entry(Ecosystem::matched_qualifiers(&qualifiers.0))
                .or_default()
                .push(*idx);
        }
        for (qualifiers, indices) in by_qualifiers {
            grouped += rows.len();
            let assertions = group(rows.iter().map(|(source, status)| {
                let mut status = status.clone();
                status.sbom_qualifiers = qualified_purl::Qualifiers(qualifiers.clone());
                ((), *source, status)
            }))
            .map(|((), assertion)| assertion)
            .collect::<Vec<_>>();
            for idx in indices {
                result.extend(assertions.iter().map(|assertion| IdentifierMatch {
                    index: idx,
                    assertion: assertion.clone(),
                }));
            }
        }
    }
    span.record("grouped", grouped);

    span.record("matches", result.len());
    Ok(result)
}

// ponytail: ad-hoc PURLs not in DB won't match; add fallback with literal version_matches when needed

/// Load the candidates of all sources matching any of the given versioned_purl IDs, in a single
/// statement.
///
/// 1. `candidate`: one scan over the stated rows of the versions' packages, evaluating every
///    source (lateral union). The rows are grouped by stated range and candidate, as many rows
///    (e.g. one per advisory of a kernel) state the same range.
/// 2. `matched`: `version_matches()` once per group and SBOM version.
/// 3. The rows of the matching groups, by primary key.
async fn load_purl_status_matches(
    versioned_purl_ids: Vec<Uuid>,
    sources: &[(Source<'_>, Candidates)],
    connection: &impl ConnectionTrait,
) -> Result<Vec<PurlStatusMatch>, Error> {
    let Some(query) = purl_status_matches(&Scope::Versions(versioned_purl_ids), sources) else {
        return Ok(Vec::new());
    };
    let (sql, values) = query.build(PostgresQueryBuilder);
    Ok(
        PurlStatusMatch::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            values,
        ))
        .all(connection)
        .instrument(info_span!("loading purl status matches"))
        .await?,
    )
}

/// What a PURL match statement matches the stated rows against.
enum Scope {
    /// The given versioned PURLs (SBOM direction).
    Versions(Vec<Uuid>),
    /// The versioned PURLs of all SBOM nodes, for the rows of one advisory (advisory direction).
    Advisory(Uuid),
}

/// The statement of [`load_purl_status_matches`] and [`load_advisory_purl_matches`], `None`
/// without sources.
///
/// 1. `candidate`: one scan over the stated rows in scope, evaluating every source (lateral
///    union). The rows are grouped by stated range and candidate, as many rows (e.g. one per
///    advisory of a kernel) state the same range.
/// 2. `matched`: `version_matches()` once per group and version, skipping ranges of another
///    RPM stream first.
/// 3. The rows of the matching groups, by primary key. For an advisory, joined with the SBOM
///    nodes of each matched version.
fn purl_status_matches(scope: &Scope, sources: &[(Source<'_>, Candidates)]) -> Option<WithQuery> {
    let candidate = Alias::new("candidate");
    let matched = Alias::new("matched");
    let source = Alias::new("candidate_source");
    let range = [
        "range_scheme",
        "range_low_version",
        "range_low_inclusive",
        "range_high_version",
        "range_high_inclusive",
    ];

    let union = sources
        .iter()
        .zip(0..)
        .map(|((_, candidates), index)| candidates.branch(index))
        .reduce(|mut union, branch| {
            union.union(UnionType::All, branch);
            union
        })?;

    let mut candidates = Query::select();
    candidates
        .column((purl_status::Entity, purl_status::Column::BasePurlId))
        .expr_as(range_col(version_range::Column::Id), Alias::new("range_id"))
        .columns(
            ["source", "slug"]
                .into_iter()
                .chain(range)
                .map(|column| (source.clone(), Alias::new(column))),
        )
        .expr_as(
            Func::cust(Alias::new("array_agg"))
                .arg(Expr::col((purl_status::Entity, purl_status::Column::Id))),
            Alias::new("status_ids"),
        )
        .from(purl_status::Entity)
        .inner_join(
            base_purl::Entity,
            Expr::col((base_purl::Entity, base_purl::Column::Id))
                .equals((purl_status::Entity, purl_status::Column::BasePurlId)),
        )
        .inner_join(
            version_range::Entity,
            Expr::col((version_range::Entity, version_range::Column::Id))
                .equals((purl_status::Entity, purl_status::Column::VersionRangeId)),
        )
        .inner_join(
            status::Entity,
            Expr::col((status::Entity, status::Column::Id))
                .equals((purl_status::Entity, purl_status::Column::StatusId)),
        )
        .join_lateral(JoinType::InnerJoin, union, source.clone(), Expr::val(true))
        .and_where(scope.stated())
        .add_group_by(
            [
                Expr::col((purl_status::Entity, purl_status::Column::BasePurlId)),
                range_col(version_range::Column::Id),
            ]
            .into_iter()
            .chain(
                ["source", "slug"]
                    .into_iter()
                    .chain(range)
                    .map(|column| Expr::col((source.clone(), Alias::new(column)))),
            ),
        );

    let column = |table: &Alias, name: &str| Expr::col((table.clone(), Alias::new(name)));
    let mut matches = Query::select();
    matches
        .expr_as(
            Expr::col((versioned_purl::Entity, versioned_purl::Column::Id)),
            Alias::new("versioned_purl_id"),
        )
        .expr_as(
            Expr::col((versioned_purl::Entity, versioned_purl::Column::Version)),
            Alias::new("sbom_version"),
        )
        .columns(
            ["range_id", "source", "slug", "status_ids"]
                .into_iter()
                .chain(range)
                .map(|name| (candidate.clone(), Alias::new(name))),
        )
        .from(candidate.clone())
        .inner_join(
            versioned_purl::Entity,
            Expr::col((versioned_purl::Entity, versioned_purl::Column::BasePurlId))
                .equals((candidate.clone(), purl_status::Column::BasePurlId)),
        )
        .inner_join(
            base_purl::Entity,
            Expr::col((base_purl::Entity, base_purl::Column::Id))
                .equals((candidate.clone(), purl_status::Column::BasePurlId)),
        )
        .and_where(scope.versions())
        // Ranges of another stream, which [`group`] would drop anyway, before the costly match.
        .and_where(
            Ecosystem::is_rpm(
                Expr::col((base_purl::Entity, base_purl::Column::Type)),
                Expr::col((base_purl::Entity, base_purl::Column::Namespace)),
            )
            .and(ecosystem::rpm::other_stream(
                Expr::col((versioned_purl::Entity, versioned_purl::Column::Version)),
                Expr::cust_with_exprs(
                    "coalesce($1, $2)",
                    [
                        column(&candidate, "range_high_version"),
                        column(&candidate, "range_low_version"),
                    ],
                ),
            ))
            .not(),
        )
        .and_where(version_matches(
            Expr::col((versioned_purl::Entity, versioned_purl::Column::Version)),
            [
                column(&candidate, "range_id"),
                column(&candidate, "range_scheme"),
                column(&candidate, "range_low_version"),
                column(&candidate, "range_low_inclusive"),
                column(&candidate, "range_high_version"),
                column(&candidate, "range_high_inclusive"),
            ],
        ));

    // One row per matched group, with its stated rows' IDs: they are expanded, and their own
    // columns loaded once per row (see [`load_stated`]), as each one matches many versions and
    // nodes.
    let mut rows = Query::select();
    rows.columns(
        ["source", "sbom_version", "range_id", "slug", "status_ids"]
            .into_iter()
            .chain(range)
            .map(|name| (matched.clone(), Alias::new(name))),
    )
    .from(matched.clone());
    scope.targets(&mut rows, &matched);

    Some(
        rows.with(
            WithClause::new()
                .cte(
                    CommonTableExpression::new()
                        .query(candidates)
                        .table_name(candidate)
                        .to_owned(),
                )
                .cte(
                    CommonTableExpression::new()
                        .query(matches)
                        .table_name(matched)
                        .to_owned(),
                )
                .to_owned(),
        ),
    )
}

impl Scope {
    /// The stated rows in scope.
    fn stated(&self) -> SimpleExpr {
        match self {
            Self::Versions(ids) => {
                Expr::col((purl_status::Entity, purl_status::Column::BasePurlId)).in_subquery(
                    Query::select()
                        .column(versioned_purl::Column::BasePurlId)
                        .from(versioned_purl::Entity)
                        .and_where(Expr::col(versioned_purl::Column::Id).eq(ids_param(ids)))
                        .to_owned(),
                )
            }
            Self::Advisory(id) => {
                Expr::col((purl_status::Entity, purl_status::Column::AdvisoryId)).eq(*id)
            }
        }
    }

    /// The versioned PURLs in scope, of the packages of the stated rows.
    fn versions(&self) -> SimpleExpr {
        let version = Expr::col((versioned_purl::Entity, versioned_purl::Column::Id));
        match self {
            Self::Versions(ids) => version.eq(ids_param(ids)),
            // only versions of SBOM nodes, before evaluating ranges for them
            Self::Advisory(_) => Expr::exists(
                Query::select()
                    .expr(Expr::val(1))
                    .from(qualified_purl::Entity)
                    .inner_join(
                        sbom_node_purl_ref::Entity,
                        Expr::col((
                            sbom_node_purl_ref::Entity,
                            sbom_node_purl_ref::Column::QualifiedPurlId,
                        ))
                        .equals((qualified_purl::Entity, qualified_purl::Column::Id)),
                    )
                    .and_where(
                        Expr::col((
                            qualified_purl::Entity,
                            qualified_purl::Column::VersionedPurlId,
                        ))
                        .equals((versioned_purl::Entity, versioned_purl::Column::Id)),
                    )
                    .to_owned(),
            ),
        }
    }

    /// Select the targets of the matched rows: the versioned PURL, or the SBOM nodes with their
    /// qualifiers.
    fn targets(&self, rows: &mut SelectStatement, matched: &Alias) {
        match self {
            Self::Versions(_) => {
                rows.column((matched.clone(), Alias::new("versioned_purl_id")));
            }
            Self::Advisory(_) => {
                let sbom_purl = Alias::new("sbom_purl");
                rows.join_as(
                    JoinType::InnerJoin,
                    qualified_purl::Entity,
                    sbom_purl.clone(),
                    Expr::col((sbom_purl.clone(), qualified_purl::Column::VersionedPurlId))
                        .equals((matched.clone(), Alias::new("versioned_purl_id"))),
                )
                .inner_join(
                    sbom_node_purl_ref::Entity,
                    Expr::col((
                        sbom_node_purl_ref::Entity,
                        sbom_node_purl_ref::Column::QualifiedPurlId,
                    ))
                    .equals((sbom_purl.clone(), qualified_purl::Column::Id)),
                )
                // only the representative of a node's class, if the SBOM has classes
                .join(
                    JoinType::LeftJoin,
                    correlation_node_class::Entity,
                    Expr::col((
                        correlation_node_class::Entity,
                        correlation_node_class::Column::SbomId,
                    ))
                    .equals((
                        sbom_node_purl_ref::Entity,
                        sbom_node_purl_ref::Column::SbomId,
                    ))
                    .and(
                        Expr::col((
                            correlation_node_class::Entity,
                            correlation_node_class::Column::NodeId,
                        ))
                        .equals((
                            sbom_node_purl_ref::Entity,
                            sbom_node_purl_ref::Column::NodeId,
                        )),
                    ),
                )
                .and_where(
                    Expr::col((
                        correlation_node_class::Entity,
                        correlation_node_class::Column::NodeId,
                    ))
                    .is_null()
                    .or(Expr::col((
                        correlation_node_class::Entity,
                        correlation_node_class::Column::RepresentativeNodeId,
                    ))
                    .equals((
                        correlation_node_class::Entity,
                        correlation_node_class::Column::NodeId,
                    ))),
                )
                .columns([
                    (
                        sbom_node_purl_ref::Entity,
                        sbom_node_purl_ref::Column::SbomId,
                    ),
                    (
                        sbom_node_purl_ref::Entity,
                        sbom_node_purl_ref::Column::NodeId,
                    ),
                ])
                .expr_as(
                    Expr::col((sbom_purl, qualified_purl::Column::Qualifiers)),
                    Alias::new("sbom_qualifiers"),
                )
                // grouped per node while reading
                .order_by(
                    (
                        sbom_node_purl_ref::Entity,
                        sbom_node_purl_ref::Column::SbomId,
                    ),
                    Order::Asc,
                )
                .order_by(
                    (
                        sbom_node_purl_ref::Entity,
                        sbom_node_purl_ref::Column::NodeId,
                    ),
                    Order::Asc,
                );
            }
        }
    }
}

/// Load the stated rows matching a condition on `purl_status`.
async fn load_stated(
    condition: SimpleExpr,
    connection: &impl ConnectionTrait,
) -> Result<StatedRows, Error> {
    let assertion_purl = Alias::new("assertion_purl");
    let mut query = Query::select();
    query
        .expr_as(
            Expr::col((purl_status::Entity, purl_status::Column::Id)),
            Alias::new("source_id"),
        )
        .columns([
            (purl_status::Entity, purl_status::Column::AdvisoryId),
            (purl_status::Entity, purl_status::Column::VulnerabilityId),
            (purl_status::Entity, purl_status::Column::IsDefault),
            (purl_status::Entity, purl_status::Column::SourceProvider),
            (purl_status::Entity, purl_status::Column::AssertionContextId),
        ])
        .expr_as(
            Expr::col((base_purl::Entity, base_purl::Column::Type)),
            Alias::new("base_purl_type"),
        )
        .expr_as(
            Expr::col((base_purl::Entity, base_purl::Column::Namespace)),
            Alias::new("base_purl_namespace"),
        )
        .expr_as(
            Expr::col((base_purl::Entity, base_purl::Column::Name)),
            Alias::new("base_purl_name"),
        )
        .expr_as(
            Expr::col((assertion_purl.clone(), qualified_purl::Column::Purl)),
            Alias::new("source_purl"),
        )
        .column((advisory::Entity, advisory::Column::PublisherNamespace))
        .from(purl_status::Entity)
        .inner_join(
            base_purl::Entity,
            Expr::col((base_purl::Entity, base_purl::Column::Id))
                .equals((purl_status::Entity, purl_status::Column::BasePurlId)),
        )
        .inner_join(
            advisory::Entity,
            Expr::col((advisory::Entity, advisory::Column::Id))
                .equals((purl_status::Entity, purl_status::Column::AdvisoryId)),
        )
        .join_as(
            JoinType::LeftJoin,
            qualified_purl::Entity,
            assertion_purl.clone(),
            Expr::col((assertion_purl, qualified_purl::Column::Id))
                .equals((purl_status::Entity, purl_status::Column::QualifiedPurlId)),
        )
        .and_where(condition);
    let (sql, values) = query.build(PostgresQueryBuilder);
    Ok(
        StatedModel::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            values,
        ))
        .all(connection)
        .instrument(info_span!("loading stated purl rows"))
        .await?
        .into_iter()
        .map(|model| (model.source_id, Arc::new(Stated::from(model))))
        .collect(),
    )
}

/// A single array parameter, as the number of IDs is unbounded.
fn ids_param(ids: &[Uuid]) -> SimpleExpr {
    SimpleExpr::FunctionCall(PgFunc::any(ids.to_vec()))
}

/// Match the candidates of all sources of an advisory's PURL-based assertions against the SBOM
/// nodes, in a single statement.
///
/// The rows are read ordered by node and grouped per node, as [`group`] only relates rows of the
/// same target. This bounds the rows held at once by those of one node: a kernel advisory matches
/// millions of (row, node) pairs across SBOMs, which collapse into far fewer assertions.
async fn load_advisory_purl_matches(
    advisory_id: Uuid,
    sources: &[(Source<'_>, Candidates)],
    tx: &DatabaseTransaction,
) -> Result<Vec<NodeMatch>, Error> {
    let Some(query) = purl_status_matches(&Scope::Advisory(advisory_id), sources) else {
        return Ok(Vec::new());
    };
    let (sql, values) = query.build(PostgresQueryBuilder);
    let span = info_span!(
        "loading advisory purl matches",
        rows = field::Empty,
        largest_node = field::Empty,
        matches = field::Empty
    );
    async {
        let stated = load_stated(
            Expr::col((purl_status::Entity, purl_status::Column::AdvisoryId)).eq(advisory_id),
            tx,
        )
        .await?;
        let mut stream = AdvisoryPurlMatch::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            values,
        ))
        .stream(tx)
        .await?;

        let mut result = Vec::new();
        let mut node = None::<NodeRef>;
        let mut rows = Vec::new();
        let (mut total, mut largest) = (0_u64, 0_usize);
        let mut flush = |rows: &mut Vec<_>, result: &mut Vec<NodeMatch>| {
            largest = largest.max(rows.len());
            result.extend(group(take(rows)).map(|(node, assertion)| NodeMatch { node, assertion }));
        };
        while let Some(row) = stream.try_next().await? {
            total += 1;
            let target = NodeRef {
                sbom_id: row.sbom_id,
                node_id: row.node_id,
            };
            if node.as_ref() != Some(&target) {
                flush(&mut rows, &mut result);
                node = Some(target.clone());
            }
            let source = source_of(sources, row.matched.source)?;
            rows.extend(
                row.matched
                    .into_rows(&stated, &row.sbom_qualifiers)
                    .into_iter()
                    .map(|status| (target.clone(), source, status)),
            );
        }
        flush(&mut rows, &mut result);

        let span = Span::current();
        span.record("rows", total);
        span.record("largest_node", largest);
        span.record("matches", result.len());
        Ok(result)
    }
    .instrument(span)
    .await
}
