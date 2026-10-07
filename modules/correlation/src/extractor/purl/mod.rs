//! Correlation by PURL: `sbom_node_purl_ref` ↔ `purl_status`.
//!
//! Unlike digest/product_identifier which use exact value matching, PURL
//! matching requires version-range evaluation via the `version_matches()`
//! PostgreSQL function.
//!
//! RPM matches are additionally scoped by the stream of the release (e.g. `el8_6` of
//! `1.1.1k-9.el8_6`): the stream of the SBOM version must equal the stream of the matched range,
//! or share its major (e.g. `el8`) with a lower confidence. Ranges of other streams (e.g. `el9_0`
//! for an `el8` package) are dropped. Such matches are reported as `purl_stream` evidence.
//!
//! All other matches (not RPM, or without a stream on either side) are reported as `purl`
//! evidence.
//!
//! Besides the stated ranges, [`rule`]s derive implied ranges from what advisories state (e.g.
//! Red Hat's "fixed in X" implies "affected before X"). Those are matched the same way, but
//! reported as evidence of the rule's own type.

pub mod rule;
pub mod stream;

#[cfg(test)]
mod test;

use self::{
    rule::{RangeRule, rules},
    stream::StreamMatch,
};
use super::{Assertion, Extractor, IdentifierMatch, NodeIdentifier, NodeMatch, NodeRef};
use crate::{
    error::Error,
    model::{IdentifierKind, IdentifierRef, MatchedRange, MatchedValue},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, FromQueryResult, JoinType,
    LoaderTrait, QueryFilter, QuerySelect, RelationTrait,
    sea_query::{Expr, Func, SimpleExpr},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    iter,
};
use tracing::{Instrument, info_span, instrument};
use trustify_common::{db::VersionMatches, purl::Purl, rpm::Evr};
use trustify_entity::{
    base_purl, correlation_evidence::AssertionStatus, purl_status, qualified_purl,
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
            status: Expr::col((status::Entity, status::Column::Slug)).into(),
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
                range_col(version_range::Column::VersionSchemeId),
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
            .column_as(version_range::Column::Id, "range_id")
            .column_as(version_range::Column::VersionSchemeId, "range_scheme")
            .column_as(self.low_version.clone(), "range_low_version")
            .column_as(self.low_inclusive.clone(), "range_low_inclusive")
            .column_as(self.high_version.clone(), "range_high_version")
            .column_as(self.high_inclusive.clone(), "range_high_inclusive")
            .column_as(versioned_purl::Column::Version, "sbom_version")
            .filter(self.condition.clone())
            .filter(self.version_matches())
    }
}

/// A column of the stated `version_range`.
fn range_col(column: version_range::Column) -> SimpleExpr {
    Expr::col((version_range::Entity, column)).into()
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
    range_id: Uuid,
    range_scheme: VersionScheme,
    range_low_version: Option<String>,
    range_low_inclusive: Option<bool>,
    range_high_version: Option<String>,
    range_high_inclusive: Option<bool>,
    sbom_version: String,
}

impl PurlStatusRow {
    /// Relation of the RPM streams of the SBOM version and the range.
    ///
    /// The range's stream is taken from its upper bound, falling back to the lower one.
    fn stream_match(&self) -> Option<StreamMatch> {
        if self.range_scheme != VersionScheme::Rpm {
            return Some(StreamMatch::Unscoped);
        }
        let sbom = Evr::parse(&self.sbom_version).stream();
        let range = self
            .range_high_version
            .as_deref()
            .or(self.range_low_version.as_deref())
            .and_then(|version| Evr::parse(version).stream());
        stream::stream_match(sbom, range)
    }

    /// The base PURL, e.g. `pkg:rpm/redhat/bind`, and the matched version range.
    fn into_match(self) -> (String, MatchedRange) {
        let purl = Purl {
            ty: self.base_purl_type,
            namespace: self.base_purl_namespace,
            name: self.base_purl_name,
            version: None,
            qualifiers: Default::default(),
        };
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
/// Rows of a different RPM stream are dropped. The others are grouped by their evidence type too:
/// the rule's for derived rows, otherwise [`StreamMatch::extractor`]. The confidence of a group is
/// the best of its ranges. This is evaluated here, on the rows already loaded by
/// `version_matches`, as it also determines the type and confidence.
fn group<'a, K: Ord>(
    rows: impl IntoIterator<Item = (K, Source<'a>, PurlStatusRow)>,
) -> impl Iterator<Item = (K, Assertion)> {
    let mut groups = BTreeMap::<
        (K, &'static str, Uuid, String, String, String),
        (AssertionStatus, f64, BTreeSet<MatchedRange>),
    >::new();
    for (target, source, row) in rows {
        let Some(status) = map_status(&row.slug) else {
            continue;
        };
        let Some(stream) = row.stream_match() else {
            continue;
        };
        let (extractor, confidence) = match source {
            None => (stream.extractor(), stream.confidence()),
            // rounded, so that e.g. 0.8 × 0.9 is stored as 0.72
            Some(rule) => (
                rule.id(),
                (stream.confidence() * rule.confidence() * 100.0).round() / 100.0,
            ),
        };
        let (advisory_id, vulnerability_id, slug) = (
            row.advisory_id,
            row.vulnerability_id.clone(),
            row.slug.clone(),
        );
        let (identifier, range) = row.into_match();
        let entry = groups
            .entry((
                target,
                extractor,
                advisory_id,
                vulnerability_id,
                slug,
                identifier,
            ))
            .or_insert_with(|| (status, confidence, BTreeSet::new()));
        entry.1 = entry.1.max(confidence);
        entry.2.insert(range);
    }

    groups.into_iter().map(
        |(
            (target, extractor, advisory_id, vulnerability_id, _, identifier),
            (status, confidence, ranges),
        )| {
            (
                target,
                Assertion {
                    extractor,
                    advisory_id,
                    vulnerability_id,
                    status,
                    confidence,
                    matched_value: MatchedValue {
                        identifier,
                        ranges: ranges.into_iter().collect(),
                    },
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
        // versioned_purl_id -> [input indices]
        let mut vp_map = HashMap::<Uuid, Vec<usize>>::new();
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
            vp_map.entry(purl.version_uuid()).or_default().push(idx);
        }

        if vp_map.is_empty() {
            return Ok(Vec::new());
        }

        let vp_ids: Vec<_> = vp_map.keys().copied().collect();
        let rules = rules();
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
            indices
                .iter()
                .map(move |&idx| (idx, source, row.status.clone()))
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
        let rules = rules();
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

// ponytail: context_cpe_id ignored — all purl_status matches included; add CPE context filtering when needed
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
        .join(
            JoinType::InnerJoin,
            purl_status::Relation::VersionRange.def(),
        )
        .join(JoinType::InnerJoin, purl_status::Relation::Status.def())
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
