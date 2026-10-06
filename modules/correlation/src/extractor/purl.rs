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

use super::{Assertion, Extractor, IdentifierMatch, NodeIdentifier, NodeMatch, NodeRef};
use crate::{
    error::Error,
    model::{IdentifierKind, IdentifierRef, MatchedRange, MatchedValue},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, FromQueryResult, JoinType,
    LoaderTrait, QueryFilter, QuerySelect, RelationTrait,
    sea_query::{Asterisk, Expr, Func, SimpleExpr},
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tracing::{Instrument, info_span, instrument};
use trustify_common::{
    db::VersionMatches,
    purl::Purl,
    rpm::{Evr, stream_major},
};
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

/// How the RPM stream of an SBOM version relates to the stream of a matched range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMatch {
    /// Both streams are equal (e.g. `el8_6` and `el8_6`).
    Exact,
    /// Both share the major, and one of them is just the major (e.g. `el8` and `el8_6`).
    Major,
    /// At least one side has no stream, so it can't be scoped.
    Unscoped,
}

impl StreamMatch {
    /// Confidence of a match, depending on how the streams relate.
    pub fn confidence(self) -> f64 {
        match self {
            Self::Exact | Self::Unscoped => CONFIDENCE,
            Self::Major => 0.8,
        }
    }

    /// Type of the evidence: only scoped matches are stream evidence.
    pub fn extractor(self) -> &'static str {
        match self {
            Self::Exact | Self::Major => STREAM,
            Self::Unscoped => PLAIN,
        }
    }
}

/// Compare the streams of an SBOM version and a range, `None` if they belong to different streams.
fn stream_match(sbom: Option<&str>, range: Option<&str>) -> Option<StreamMatch> {
    let (Some(sbom), Some(range)) = (sbom, range) else {
        return Some(StreamMatch::Unscoped);
    };

    if sbom == range {
        return Some(StreamMatch::Exact);
    }

    let (sbom_major, range_major) = (stream_major(sbom), stream_major(range));
    if sbom_major == range_major && (sbom == sbom_major || range == range_major) {
        Some(StreamMatch::Major)
    } else {
        None
    }
}

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

fn version_matches_filter() -> SimpleExpr {
    SimpleExpr::FunctionCall(
        Func::cust(VersionMatches)
            .arg(Expr::col((
                versioned_purl::Entity,
                versioned_purl::Column::Version,
            )))
            .arg(Expr::col((version_range::Entity, Asterisk))),
    )
}

/// Select the columns of [`PurlStatusRow`], the matched advisory side of a `purl_status`.
fn select_purl_status<S: QuerySelect>(query: S) -> S {
    query
        .column_as(purl_status::Column::AdvisoryId, "advisory_id")
        .column_as(purl_status::Column::VulnerabilityId, "vulnerability_id")
        .column_as(status::Column::Slug, "slug")
        .column_as(base_purl::Column::Type, "base_purl_type")
        .column_as(base_purl::Column::Namespace, "base_purl_namespace")
        .column_as(base_purl::Column::Name, "base_purl_name")
        .column_as(version_range::Column::Id, "range_id")
        .column_as(version_range::Column::VersionSchemeId, "range_scheme")
        .column_as(version_range::Column::LowVersion, "range_low_version")
        .column_as(version_range::Column::LowInclusive, "range_low_inclusive")
        .column_as(version_range::Column::HighVersion, "range_high_version")
        .column_as(version_range::Column::HighInclusive, "range_high_inclusive")
        .column_as(versioned_purl::Column::Version, "sbom_version")
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
        stream_match(sbom, range)
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
/// Rows of a different RPM stream are dropped. The others are grouped by their evidence type
/// ([`StreamMatch::extractor`]) too, and the confidence of a group is the best of its ranges. This
/// is evaluated here, on the rows already loaded by `version_matches`, as it also determines the
/// type and confidence.
fn group<K: Ord>(
    rows: impl IntoIterator<Item = (K, PurlStatusRow)>,
) -> impl Iterator<Item = (K, Assertion)> {
    let mut groups = BTreeMap::<
        (K, &'static str, Uuid, String, String, String),
        (AssertionStatus, f64, BTreeSet<MatchedRange>),
    >::new();
    for (target, row) in rows {
        let Some(status) = map_status(&row.slug) else {
            continue;
        };
        let Some(stream) = row.stream_match() else {
            continue;
        };
        let (extractor, confidence) = (stream.extractor(), stream.confidence());
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
        let mut rows = Vec::new();
        for chunk in vp_ids.chunks(5000) {
            rows.extend(load_purl_status_matches(chunk, tx).await?);
        }

        let targets = rows.into_iter().flat_map(|row| {
            let indices = vp_map
                .get(&row.versioned_purl_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            indices.iter().map(move |&idx| (idx, row.status.clone()))
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
        let rows = load_advisory_purl_matches(advisory_id, tx).await?;

        Ok(group(rows.into_iter().map(|row| {
            (
                NodeRef {
                    sbom_id: row.sbom_id,
                    node_id: row.node_id,
                },
                row.status,
            )
        }))
        .map(|(node, assertion)| NodeMatch { node, assertion })
        .collect())
    }
}

// ponytail: context_cpe_id ignored — all purl_status matches included; add CPE context filtering when needed
// ponytail: ad-hoc PURLs not in DB won't match; add fallback with literal version_matches when needed

/// Load purl_status rows matching any of the given versioned_purl IDs via
/// version-range evaluation.
///
/// Join chain: versioned_purl → base_purl → purl_status → version_range + status,
/// filtered by `version_matches(versioned_purl.version, version_range.*)`.
async fn load_purl_status_matches(
    versioned_purl_ids: &[Uuid],
    connection: &impl ConnectionTrait,
) -> Result<Vec<PurlStatusMatch>, Error> {
    Ok(
        select_purl_status(versioned_purl::Entity::find().select_only())
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
            .filter(version_matches_filter())
            .into_model::<PurlStatusMatch>()
            .all(connection)
            .instrument(info_span!("loading purl status matches"))
            .await?,
    )
}

/// Load SBOM nodes matching an advisory's PURL-based assertions.
///
/// Join chain: purl_status → base_purl → versioned_purl → qualified_purl → sbom_node_purl_ref,
/// plus purl_status → version_range + status, filtered by `version_matches`.
async fn load_advisory_purl_matches(
    advisory_id: Uuid,
    connection: &impl ConnectionTrait,
) -> Result<Vec<AdvisoryPurlMatch>, Error> {
    Ok(
        select_purl_status(purl_status::Entity::find().select_only())
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
            .filter(version_matches_filter())
            .into_model::<AdvisoryPurlMatch>()
            .all(connection)
            .instrument(info_span!("loading advisory purl matches"))
            .await?,
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{extractor::Extractors, model::RangeBound};
    use rstest::rstest;
    use sea_orm::TransactionTrait;
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::correlation_evidence;
    use trustify_test_context::TrustifyContext;

    const S5_SBOM: &str =
        "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json";
    const S5_VEX: &str = "scenarios/S5_positive_baseline_openssl_el8/vex/CVE-2023-0215.json.xz";

    fn extractors() -> Extractors {
        Extractors::new(vec![Box::new(PurlExtractor)])
    }

    async fn extract_for_sbom(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<usize> {
        let tx = ctx.db.begin().await?;
        let count = extractors().extract_for_sbom(sbom_id, &tx).await?;
        tx.commit().await?;
        Ok(count)
    }

    async fn extract_for_advisory(
        ctx: &TrustifyContext,
        advisory_id: Uuid,
    ) -> anyhow::Result<usize> {
        let tx = ctx.db.begin().await?;
        let count = extractors().extract_for_advisory(advisory_id, &tx).await?;
        tx.commit().await?;
        Ok(count)
    }

    /// (node, vulnerability, type, status, confidence, matched value)
    type Evidence = (
        String,
        String,
        String,
        AssertionStatus,
        f64,
        Option<MatchedValue>,
    );

    /// All PURL evidence of an SBOM, sorted.
    async fn load_evidence(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<Vec<Evidence>> {
        let mut evidence = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(correlation_evidence::Column::Extractor.is_in([PLAIN, STREAM]))
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|e| {
                Ok((
                    e.node_id,
                    e.vulnerability_id,
                    e.extractor,
                    e.status,
                    e.confidence,
                    e.matched_value
                        .map(serde_json::from_value::<MatchedValue>)
                        .transpose()?,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        evidence.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));
        Ok(evidence)
    }

    /// Ranges of the given scheme, fixed in the given versions (exclusive upper bounds).
    fn fixed_in(scheme: &str, versions: &[&str]) -> Vec<MatchedRange> {
        versions
            .iter()
            .map(|fixed| MatchedRange {
                scheme: scheme.into(),
                low: None,
                high: Some(RangeBound {
                    version: (*fixed).into(),
                    inclusive: false,
                }),
            })
            .collect()
    }

    #[rstest]
    #[case(Some("el8_6"), Some("el8_6"), Some(StreamMatch::Exact))]
    #[case(Some("fc39"), Some("fc39"), Some(StreamMatch::Exact))]
    #[case(Some("el8"), Some("el8_6"), Some(StreamMatch::Major))]
    #[case(Some("el8_6"), Some("el8"), Some(StreamMatch::Major))]
    #[case(Some("el8_6"), Some("el8_7"), None)]
    #[case(Some("el8"), Some("el9"), None)]
    #[case(Some("el8"), Some("fc8"), None)]
    #[case(Some("el8"), None, Some(StreamMatch::Unscoped))]
    #[case(None, Some("el8"), Some(StreamMatch::Unscoped))]
    #[case(None, None, Some(StreamMatch::Unscoped))]
    #[test_log::test]
    fn stream_matching(
        #[case] sbom: Option<&str>,
        #[case] range: Option<&str>,
        #[case] expected: Option<StreamMatch>,
    ) {
        assert_eq!(stream_match(sbom, range), expected);
    }

    /// Both directions must find matches and produce the same evidence rows.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn extract_both_directions(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx.ingest_document(S5_SBOM).await?;
        let advisory = ctx.ingest_document(S5_VEX).await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;
        let advisory_id = Uuid::parse_str(&advisory.id)?;

        assert!(extract_for_sbom(ctx, sbom_id).await? > 0);
        let from_sbom = load_evidence(ctx, sbom_id).await?;
        assert!(!from_sbom.is_empty());

        correlation_evidence::Entity::delete_many()
            .exec(&ctx.db)
            .await?;

        assert!(extract_for_advisory(ctx, advisory_id).await? > 0);
        assert_eq!(load_evidence(ctx, sbom_id).await?, from_sbom);

        Ok(())
    }

    /// An `el8` package only matches the `el8_*` ranges (sharing the major only), not the `el9_*`
    /// ones, and is reported as stream evidence.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn stream_match_major(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx.ingest_document(S5_SBOM).await?;
        ctx.ingest_document(S5_VEX).await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        assert!(extract_for_sbom(ctx, sbom_id).await? > 0);

        assert_eq!(
            load_evidence(ctx, sbom_id).await?,
            vec![(
                "pkg-openssl".to_string(),
                "CVE-2023-0215".to_string(),
                STREAM.to_string(),
                AssertionStatus::Affected,
                0.8,
                Some(MatchedValue {
                    identifier: "pkg:rpm/redhat/openssl".into(),
                    ranges: fixed_in("rpm", &["1:1.1.1k-9.el8_6", "1:1.1.1k-9.el8_7"]),
                }),
            )]
        );

        Ok(())
    }

    /// An `el8_2` package only matches the `el8_2` range, not the GA (`el8_7`) one.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn stream_match_exact(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document(
                "scenarios/S9_substream_openssl_el8/sbom_openssl_el8.2_below-fix.cdx.json",
            )
            .await?;
        ctx.ingest_document("scenarios/S9_substream_openssl_el8/vex/CVE-2023-0286.json.xz")
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        assert!(extract_for_sbom(ctx, sbom_id).await? > 0);

        assert_eq!(
            load_evidence(ctx, sbom_id).await?,
            vec![(
                "pkg-openssl".to_string(),
                "CVE-2023-0286".to_string(),
                STREAM.to_string(),
                AssertionStatus::Affected,
                1.0,
                Some(MatchedValue {
                    identifier: "pkg:rpm/redhat/openssl".into(),
                    ranges: fixed_in("rpm", &["1:1.1.1c-21.el8_2"]),
                }),
            )]
        );

        Ok(())
    }

    /// A non-RPM package is matched by version range only, and reported as plain evidence.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn plain_match(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document(
                "scenarios/S6_positive_baseline_osv_urllib3/sbom_urllib3_affected.cdx.json",
            )
            .await?;
        ctx.ingest_document(
            "scenarios/S6_positive_baseline_osv_urllib3/osv/GHSA-g4mx-q9vg-27p4.json",
        )
        .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        assert!(extract_for_sbom(ctx, sbom_id).await? > 0);

        assert_eq!(
            load_evidence(ctx, sbom_id).await?,
            vec![(
                "pkg-urllib3".to_string(),
                "CVE-2023-45803".to_string(),
                PLAIN.to_string(),
                AssertionStatus::Affected,
                1.0,
                Some(MatchedValue {
                    identifier: "pkg:pypi/urllib3".into(),
                    ranges: vec![
                        MatchedRange {
                            scheme: "generic".into(),
                            low: Some(RangeBound {
                                version: "1.26.17".into(),
                                inclusive: true,
                            }),
                            high: Some(RangeBound {
                                version: "1.26.17".into(),
                                inclusive: true,
                            }),
                        },
                        MatchedRange {
                            scheme: "python".into(),
                            low: Some(RangeBound {
                                version: "0".into(),
                                inclusive: true,
                            }),
                            high: Some(RangeBound {
                                version: "1.26.18".into(),
                                inclusive: false,
                            }),
                        },
                    ],
                }),
            )]
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn no_match_without_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx.ingest_document(S5_SBOM).await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        let count = extract_for_sbom(ctx, sbom_id).await?;
        assert_eq!(count, 0, "no advisory means no matches");

        Ok(())
    }
}
