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
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, FromQueryResult, JoinType,
    LoaderTrait, QueryFilter, QuerySelect, RelationTrait,
    sea_query::{Alias, Expr, Func, SimpleExpr},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    iter,
};
use tracing::{Instrument, info_span, instrument};
use trustify_common::{db::VersionMatches, purl::Purl};
use trustify_entity::{
    advisory, base_purl, correlation_evidence::AssertionStatus, purl_status, qualified_purl,
    sbom_node_purl_ref, status, version_range, version_scheme::VersionScheme, versioned_purl,
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
const DEFAULT_CONFIDENCE: f64 = 0.9;

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
/// joined `status` and `version_range`).
///
/// The stated candidates are the rows themselves. A [`RangeRule`] derives other candidates from
/// (some of) them.
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

    /// `version_matches()` of the SBOM version and the candidate range.
    fn version_matches(&self) -> SimpleExpr {
        let range = Expr::cust_with_exprs(
            "ROW($1, $2, $3, $4, $5, $6)::version_range",
            [
                range_col(version_range::Column::Id),
                self.scheme.clone(),
                self.low_version.clone(),
                self.low_inclusive.clone(),
                self.high_version.clone(),
                self.high_inclusive.clone(),
            ],
        );
        SimpleExpr::FunctionCall(
            Func::cust(VersionMatches)
                .arg(Expr::col((
                    versioned_purl::Entity,
                    versioned_purl::Column::Version,
                )))
                .arg(range),
        )
    }

    /// Select the columns of [`PurlStatusRow`], and filter by the candidate's condition and range.
    fn select<S: QuerySelect + QueryFilter>(&self, query: S) -> S {
        query
            .column_as(purl_status::Column::AdvisoryId, "advisory_id")
            .column_as(purl_status::Column::VulnerabilityId, "vulnerability_id")
            .column_as(self.status.clone(), "slug")
            .column_as(base_purl::Column::Type, "base_purl_type")
            .column_as(base_purl::Column::Namespace, "base_purl_namespace")
            .column_as(base_purl::Column::Name, "base_purl_name")
            .column_as(
                Expr::col((Alias::new("assertion_purl"), qualified_purl::Column::Purl)),
                "source_purl",
            )
            .column_as(advisory::Column::PublisherNamespace, "publisher_namespace")
            .column_as(
                purl_status::Column::AssertionContextId,
                "assertion_context_id",
            )
            .column_as(version_range::Column::Id, "range_id")
            .column_as(self.scheme.clone(), "range_scheme")
            .column_as(self.low_version.clone(), "range_low_version")
            .column_as(self.low_inclusive.clone(), "range_low_inclusive")
            .column_as(self.high_version.clone(), "range_high_version")
            .column_as(self.high_inclusive.clone(), "range_high_inclusive")
            .column_as(purl_status::Column::IsDefault, "is_default")
            .column_as(purl_status::Column::SourceProvider, "source_provider")
            .column_as(versioned_purl::Column::Version, "sbom_version")
            .filter(self.condition.clone())
            .filter(self.version_matches())
    }
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

/// The advisory side of a matched `purl_status`, plus the SBOM version it matched.
#[derive(Clone, FromQueryResult)]
struct PurlStatusRow {
    advisory_id: Uuid,
    vulnerability_id: String,
    slug: String,
    base_purl_type: String,
    base_purl_namespace: Option<String>,
    base_purl_name: String,
    source_purl: Option<qualified_purl::CanonicalPurl>,
    source_provider: Option<serde_json::Value>,
    sbom_qualifiers: qualified_purl::Qualifiers,
    publisher_namespace: Option<String>,
    assertion_context_id: Option<Uuid>,
    range_id: Uuid,
    range_scheme: VersionScheme,
    range_low_version: Option<String>,
    range_low_inclusive: Option<bool>,
    range_high_version: Option<String>,
    range_high_inclusive: Option<bool>,
    is_default: bool,
    sbom_version: String,
}

impl PurlStatusRow {
    /// If the qualifiers of the SBOM package are compatible with the ones of the advisory PURL.
    fn qualifiers_match(&self) -> bool {
        self.source_purl.as_ref().is_none_or(|purl| {
            self.ecosystem()
                .qualifiers_match(&self.sbom_qualifiers.0, &purl.qualifiers)
        })
    }

    /// The package a listed status shadows the default of.
    fn package(&self) -> (Uuid, &str, &str, Option<&str>, &str) {
        (
            self.advisory_id,
            self.vulnerability_id.as_str(),
            self.base_purl_type.as_str(),
            self.base_purl_namespace.as_deref(),
            self.base_purl_name.as_str(),
        )
    }

    /// The ecosystem of the advisory's package.
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::of(&self.base_purl_type, self.base_purl_namespace.as_deref())
    }

    /// Relation of the streams of the SBOM version and the range.
    fn stream_match(&self) -> Option<StreamMatch> {
        self.ecosystem().stream_match(
            &self.sbom_version,
            self.range_low_version.as_deref(),
            self.range_high_version.as_deref(),
        )
    }

    /// The original advisory PURL (or legacy base identity), and the matched version range.
    fn into_match(self) -> (String, MatchedRange) {
        let purl = self.source_purl.map(Purl::from).unwrap_or_else(|| Purl {
            ty: self.base_purl_type,
            namespace: self.base_purl_namespace,
            name: self.base_purl_name,
            version: None,
            qualifiers: Default::default(),
        });
        let range = version_range::Model {
            id: self.range_id,
            version_scheme_id: self.range_scheme,
            low_version: self.range_low_version,
            low_inclusive: self.range_low_inclusive,
            high_version: self.range_high_version,
            high_inclusive: self.range_high_inclusive,
        };
        (purl.to_string(), range.into())
    }
}

#[derive(FromQueryResult)]
struct PurlStatusMatch {
    versioned_purl_id: Uuid,
    #[sea_orm(nested)]
    status: PurlStatusRow,
}

#[derive(FromQueryResult)]
struct AdvisoryPurlMatch {
    sbom_id: Uuid,
    node_id: String,
    #[sea_orm(nested)]
    status: PurlStatusRow,
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
            let status = map_status(&row.slug)?;
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
                row.advisory_id,
                row.vulnerability_id.clone(),
                row.source_provider
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            )
        })
        .collect::<BTreeSet<_>>();

    // the packages of a target with a listed status, shadowing their defaults
    let listed = rows
        .iter()
        .filter(|(_, source, row, ..)| {
            !row.is_default && source.is_none_or(|rule| rule.origin() == AssertionOrigin::Stated)
        })
        .map(|(target, _, row, ..)| {
            (
                target.clone(),
                row.package(),
                row.source_provider
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            )
        })
        .collect::<BTreeSet<_>>();
    let shadowed = rows
        .iter()
        .map(|(target, _, row, ..)| {
            row.is_default
                && listed.contains(&(
                    target.clone(),
                    row.package(),
                    row.source_provider
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
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
                row.advisory_id,
                row.vulnerability_id.clone(),
                row.source_provider
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            ))
        {
            continue;
        }
        let (extractor, factors) = match source {
            None if row.is_default => (
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
            None if row.is_default => AssertionOrigin::Default,
            None => AssertionOrigin::Stated,
        };
        let enabled_by =
            source.and_then(|rule| rule.enabled_by(row.publisher_namespace.as_deref()));
        // an equal RPM stream puts the node into the statement's product already, another minor
        // only applies within the product
        let requires_context = match stream {
            StreamMatch::Exact => false,
            StreamMatch::Minor => true,
            StreamMatch::Major | StreamMatch::Unscoped => {
                source.is_some_and(|rule| rule.requires_context())
            }
        };
        let (advisory_id, vulnerability_id, slug, context_id) = (
            row.advisory_id,
            row.vulnerability_id.clone(),
            row.slug.clone(),
            row.assertion_context_id,
        );
        let row_provider_key = row
            .source_provider
            .as_ref()
            .map(serde_json::Value::to_string)
            .unwrap_or_default();
        let source_provider = row.source_provider.clone().map(|p| {
            serde_json::from_value(p).unwrap_or(crate::model::ProviderIdentity {
                unavailable: true,
                ..Default::default()
            })
        });
        let (identifier, range) = row.into_match();
        let entry = groups
            .entry((
                target,
                extractor,
                advisory_id,
                vulnerability_id,
                slug,
                identifier,
                context_id,
                row_provider_key,
            ))
            .or_insert_with(|| Group {
                status,
                source_provider,
                origin,
                confidence,
                factors: factors.clone(),
                ranges: BTreeSet::new(),
                enabled_by,
                requires_context,
            });
        // the best range of the group decides its confidence
        if confidence > entry.confidence {
            entry.confidence = confidence;
            entry.factors = factors;
        }
        entry.ranges.insert(range);
    }

    groups.into_iter().map(
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
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        let purl_refs = sbom_node_purl_ref::Entity::find()
            .filter(sbom_node_purl_ref::Column::SbomId.eq(sbom_id))
            .all(tx)
            .instrument(info_span!("loading purl refs"))
            .await?;

        let qualified_purls = purl_refs
            .load_one(qualified_purl::Entity, tx)
            .instrument(info_span!("loading qualified purls"))
            .await?;

        Ok(purl_refs
            .into_iter()
            .zip(qualified_purls)
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
        // Versions share candidate lookups, but each input retains its own qualifiers.
        let mut vp_map = HashMap::<Uuid, Vec<(usize, qualified_purl::Qualifiers)>>::new();
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
            vp_map
                .entry(purl.version_uuid())
                .or_default()
                .push((idx, qualified_purl::Qualifiers(purl.qualifiers)));
        }

        if vp_map.is_empty() {
            return Ok(Vec::new());
        }

        let vp_ids: Vec<_> = vp_map.keys().copied().collect();
        let rules = rules(tx).await?;
        let mut rows = Vec::new();
        for (source, candidates) in sources(&rules) {
            for chunk in vp_ids.chunks(5000) {
                rows.extend(
                    load_purl_status_matches(chunk, &candidates, tx)
                        .await?
                        .into_iter()
                        .map(|row| (source, row)),
                );
            }
        }

        let targets = rows.into_iter().flat_map(|(source, row)| {
            let indices = vp_map
                .get(&row.versioned_purl_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            indices.iter().map(move |(idx, qualifiers)| {
                let mut status = row.status.clone();
                status.sbom_qualifiers = qualifiers.clone();
                (*idx, source, status)
            })
        });

        Ok(group(targets)
            .map(|(index, assertion)| IdentifierMatch { index, assertion })
            .collect())
    }

    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn match_advisory(
        &self,
        advisory_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeMatch>, Error> {
        let rules = rules(tx).await?;
        let mut rows = Vec::new();
        for (source, candidates) in sources(&rules) {
            rows.extend(
                load_advisory_purl_matches(advisory_id, &candidates, tx)
                    .await?
                    .into_iter()
                    .map(|row| {
                        (
                            NodeRef {
                                sbom_id: row.sbom_id,
                                node_id: row.node_id,
                            },
                            source,
                            row.status,
                        )
                    }),
            );
        }

        Ok(group(rows)
            .map(|(node, assertion)| NodeMatch { node, assertion })
            .collect())
    }
}

// ponytail: ad-hoc PURLs not in DB won't match; add fallback with literal version_matches when needed

/// Load the candidates matching any of the given versioned_purl IDs via version-range evaluation.
///
/// Join chain: versioned_purl → base_purl → purl_status → version_range + status,
/// filtered by the candidates' condition and `version_matches()`.
async fn load_purl_status_matches(
    versioned_purl_ids: &[Uuid],
    candidates: &Candidates,
    connection: &impl ConnectionTrait,
) -> Result<Vec<PurlStatusMatch>, Error> {
    Ok(candidates
        .select(versioned_purl::Entity::find().select_only())
        .column_as(versioned_purl::Column::Id, "versioned_purl_id")
        // replaced by the qualifiers of each input
        .column_as(Expr::cust("'{}'::jsonb"), "sbom_qualifiers")
        .join(
            JoinType::InnerJoin,
            versioned_purl::Relation::BasePurl.def(),
        )
        .join(JoinType::InnerJoin, base_purl::Relation::PurlStatus.def())
        .join(
            JoinType::InnerJoin,
            purl_status::Relation::VersionRange.def(),
        )
        .join(JoinType::InnerJoin, purl_status::Relation::Status.def())
        .join(JoinType::InnerJoin, purl_status::Relation::Advisory.def())
        .join_as(
            JoinType::LeftJoin,
            purl_status::Relation::QualifiedPurl.def(),
            Alias::new("assertion_purl"),
        )
        .filter(versioned_purl::Column::Id.is_in(versioned_purl_ids.iter().copied()))
        .into_model::<PurlStatusMatch>()
        .all(connection)
        .instrument(info_span!("loading purl status matches"))
        .await?)
}

/// Load SBOM nodes matching the candidates of an advisory's PURL-based assertions.
///
/// Join chain: purl_status → base_purl → versioned_purl → qualified_purl → sbom_node_purl_ref,
/// plus purl_status → version_range + status, filtered by the candidates' condition and
/// `version_matches()`.
async fn load_advisory_purl_matches(
    advisory_id: Uuid,
    candidates: &Candidates,
    connection: &impl ConnectionTrait,
) -> Result<Vec<AdvisoryPurlMatch>, Error> {
    Ok(candidates
        .select(purl_status::Entity::find().select_only())
        .column_as(sbom_node_purl_ref::Column::SbomId, "sbom_id")
        .column_as(sbom_node_purl_ref::Column::NodeId, "node_id")
        .column_as(qualified_purl::Column::Qualifiers, "sbom_qualifiers")
        .join(
            JoinType::InnerJoin,
            purl_status::Relation::VersionRange.def(),
        )
        .join(JoinType::InnerJoin, purl_status::Relation::Status.def())
        .join(JoinType::InnerJoin, purl_status::Relation::Advisory.def())
        .join_as(
            JoinType::LeftJoin,
            purl_status::Relation::QualifiedPurl.def(),
            Alias::new("assertion_purl"),
        )
        .join(JoinType::InnerJoin, purl_status::Relation::BasePurl.def())
        .join(
            JoinType::InnerJoin,
            base_purl::Relation::VersionedPurls.def(),
        )
        .join(
            JoinType::InnerJoin,
            versioned_purl::Relation::QualifiedPurl.def(),
        )
        .join(
            JoinType::InnerJoin,
            qualified_purl::Relation::SbomNode.def(),
        )
        .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
        .into_model::<AdvisoryPurlMatch>()
        .all(connection)
        .instrument(info_span!("loading advisory purl matches"))
        .await?)
}
