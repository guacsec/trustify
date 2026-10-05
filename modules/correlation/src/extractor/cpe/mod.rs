//! Correlation by CPE: `sbom_node_cpe_ref` ↔ `advisory_vulnerability_cpe`.
//!
//! Advisory CPEs are patterns (wildcards, version ranges), SBOM CPEs are concrete. A component
//! matches when the advisory CPE is a superset of the SBOM CPE: each advisory attribute is either
//! ANY, or equal to the SBOM attribute (case-insensitive, with `*`/`?` wildcards within values).
//! An SBOM attribute that is ANY where the advisory has a value does not match. The SBOM CPE must
//! have a concrete version, which must equal the advisory's version, or, if that is ANY, be in the
//! assertion's version range (if any).
//!
//! The matching runs in the database (see `MATCH_CONDITION`), returning only actual matches.

use super::{Assertion, Extractor, IdentifierMatch, NodeIdentifier, NodeMatch, NodeRef};
use crate::{
    error::Error,
    model::{IdentifierKind, IdentifierRef},
};
use sea_orm::{
    ActiveEnum, ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, EntityTrait,
    FromQueryResult, LoaderTrait, QueryFilter, Statement, TryIntoModel,
};
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
};
use tracing::{Instrument, info_span, instrument};
use trustify_common::cpe::Cpe;
use trustify_entity::{
    correlation_evidence::AssertionStatus, cpe, sbom_node_cpe_ref, version_range,
};
use uuid::Uuid;

/// Extracts correlation evidence by matching SBOM CPEs against advisory CPE patterns.
pub struct CpeExtractor;

/// How the SBOM version satisfied the advisory CPE, determining the confidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionCheck {
    /// The advisory CPE carries a version, which the SBOM version equals.
    Exact,
    /// The advisory CPE version is ANY, the SBOM version is in the assertion's version range.
    Range,
    /// The advisory CPE version is ANY, without a version range: all versions match.
    Any,
}

impl VersionCheck {
    /// Confidence of a match, depending on how the version was established.
    pub fn confidence(self) -> f64 {
        match self {
            Self::Exact => 0.8,
            Self::Range => 0.7,
            Self::Any => 0.5,
        }
    }
}

/// Matching an SBOM CPE (`sc`) against an advisory CPE (`ac`) of an assertion (`a`), with the
/// assertion's version range (`vr`, `LEFT JOIN`ed). Candidates are joined by the lowercase product.
const MATCH_CONDITION: &str = r#"
    cpe_attribute_matches(ac.part, sc.part)
    AND cpe_attribute_matches(ac.vendor, sc.vendor)
    AND cpe_attribute_matches(ac."update", sc."update")
    AND cpe_attribute_matches(ac.edition, sc.edition)
    AND cpe_attribute_matches(ac.language, sc.language)
    AND cpe_attribute_matches(ac.sw_edition, sc.sw_edition)
    AND cpe_attribute_matches(ac.target_sw, sc.target_sw)
    AND cpe_attribute_matches(ac.target_hw, sc.target_hw)
    AND cpe_attribute_matches(ac.other, sc.other)
    AND sc.version IS NOT NULL AND sc.version <> '*'
    AND CASE
        WHEN ac.version IS NULL THEN false
        WHEN ac.version <> '*' THEN cpe_attribute_matches(ac.version, sc.version)
        WHEN a.version_range_id IS NOT NULL THEN version_matches(sc.version, vr)
        ELSE true
    END
"#;

/// The assertion columns of a match, see [`AssertionRow`].
const ASSERTION_COLUMNS: &str = r#"
    a.advisory_id,
    a.vulnerability_id,
    a.status::text AS status,
    a.cpe_id,
    a.version_range_id,
    CASE
        WHEN ac.version <> '*' THEN 'exact'
        WHEN a.version_range_id IS NOT NULL THEN 'range'
        ELSE 'any'
    END AS version_check
"#;

/// The advisory side of a match.
#[derive(FromQueryResult)]
struct AssertionRow {
    advisory_id: Uuid,
    vulnerability_id: String,
    status: String,
    cpe_id: Uuid,
    version_range_id: Option<Uuid>,
    version_check: String,
}

/// A match of an identifier passed to [`Extractor::match_identifiers`].
#[derive(FromQueryResult)]
struct IdentifierRow {
    /// Index into the identifiers.
    i: i64,
    #[sea_orm(nested)]
    assertion: AssertionRow,
}

/// A match of an SBOM node, for [`Extractor::match_advisory`].
#[derive(FromQueryResult)]
struct NodeRow {
    sbom_id: Uuid,
    node_id: String,
    #[sea_orm(nested)]
    assertion: AssertionRow,
}

#[async_trait::async_trait]
impl Extractor for CpeExtractor {
    fn id(&self) -> &'static str {
        "cpe"
    }

    /// The CPEs of the nodes of an SBOM, as CPE 2.3 formatted strings.
    ///
    /// The stored CPE's `Display` form is a CPE 2.2 URI which can't be parsed back for all
    /// values, so the CPE 2.3 form is used instead, which is also what users know.
    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn sbom_identifiers(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        let cpe_refs = sbom_node_cpe_ref::Entity::find()
            .filter(sbom_node_cpe_ref::Column::SbomId.eq(sbom_id))
            .all(tx)
            .instrument(info_span!("loading cpe refs"))
            .await?;

        let cpes = cpe_refs
            .load_one(cpe::Entity, tx)
            .instrument(info_span!("loading cpes"))
            .await?;

        Ok(cpe_refs
            .into_iter()
            .zip(cpes)
            .filter_map(|(cpe_ref, cpe)| {
                Some(NodeIdentifier {
                    identifier: IdentifierRef {
                        kind: IdentifierKind::Cpe,
                        value: format_cpe23(&cpe?),
                    },
                    node: NodeRef {
                        sbom_id: cpe_ref.sbom_id,
                        node_id: cpe_ref.node_id,
                    },
                })
            })
            .collect())
    }

    /// Match CPEs against the advisory CPE patterns, in the database.
    ///
    /// The identifiers are parsed and converted into their stored form (the representation of the
    /// `cpe` table: `*` for ANY, `NULL` for NA). They are passed as a single JSONB parameter and
    /// expanded into rows using `jsonb_to_recordset`, which supports `NULL` values (array
    /// parameters don't) and needs no chunking.
    ///
    /// The query joins them with the advisory CPEs of the same (lowercase) product, using
    /// `idx_cpe_lower_product`, and the assertions using those CPEs. The `MATCH_CONDITION`
    /// filters out non-matching pairs, so only actual matches are loaded. The advisory side value
    /// of each match, for presentation, is loaded afterwards for the matched CPEs and ranges only.
    ///
    /// Also used by the ad-hoc identifier query, with CPEs which might not be stored.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn match_identifiers(
        &self,
        identifiers: &[IdentifierRef],
        tx: &DatabaseTransaction,
    ) -> Result<Vec<IdentifierMatch>, Error> {
        // the identifiers in their stored form
        let mut sbom_cpes = Vec::new();
        for (index, identifier) in identifiers.iter().enumerate() {
            if identifier.kind != IdentifierKind::Cpe {
                continue;
            }
            let Some(cpe) = Cpe::from_str(&identifier.value)
                .inspect_err(|err| {
                    tracing::debug!(value = identifier.value, "ignoring invalid CPE: {err}")
                })
                .ok()
            else {
                continue;
            };
            let c = cpe::ActiveModel::from_cpe(cpe).try_into_model()?;
            sbom_cpes.push(json!({
                "i": index,
                "part": c.part,
                "vendor": c.vendor,
                "product": c.product,
                "version": c.version,
                "update": c.update,
                "edition": c.edition,
                "language": c.language,
                "sw_edition": c.sw_edition,
                "target_sw": c.target_sw,
                "target_hw": c.target_hw,
                "other": c.other,
            }));
        }

        if sbom_cpes.is_empty() {
            return Ok(Vec::new());
        }

        // a single bind parameter, no need to chunk
        let rows = IdentifierRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                r#"
WITH sc AS (
    SELECT * FROM jsonb_to_recordset($1) AS t(
        i int8, part text, vendor text, product text, version text, "update" text, edition text,
        language text, sw_edition text, target_sw text, target_hw text, other text
    )
)
SELECT sc.i, {ASSERTION_COLUMNS}
FROM sc
JOIN cpe ac ON lower(ac.product) = lower(sc.product)
JOIN advisory_vulnerability_cpe a ON a.cpe_id = ac.id
LEFT JOIN version_range vr ON vr.id = a.version_range_id
WHERE {MATCH_CONDITION}
"#
            ),
            [serde_json::Value::from(sbom_cpes).into()],
        ))
        .all(tx)
        .instrument(info_span!("matching cpes"))
        .await?;

        let matched_values = matched_values(rows.iter().map(|r| &r.assertion), tx).await?;

        rows.into_iter()
            .filter_map(|row| {
                let index = usize::try_from(row.i).ok()?;
                Some(
                    assertion(row.assertion, &matched_values)
                        .map(|assertion| IdentifierMatch { index, assertion }),
                )
            })
            .collect()
    }

    /// Match the CPE patterns of an advisory against the CPEs of all SBOMs, in the database.
    ///
    /// The same matching as [`Self::match_identifiers`], starting from the other side: the
    /// advisory's assertions and CPEs, joined with all stored CPEs of the same (lowercase)
    /// product, and the SBOM nodes referencing them. Only actual matches are loaded, not every
    /// component sharing a product with the advisory.
    ///
    /// Both directions must produce the same matches (and so the same evidence IDs), which is why
    /// they share `MATCH_CONDITION`.
    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn match_advisory(
        &self,
        advisory_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeMatch>, Error> {
        let rows = NodeRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                r#"
SELECT r.sbom_id, r.node_id, {ASSERTION_COLUMNS}
FROM advisory_vulnerability_cpe a
JOIN cpe ac ON ac.id = a.cpe_id
JOIN cpe sc ON lower(sc.product) = lower(ac.product)
JOIN sbom_node_cpe_ref r ON r.cpe_id = sc.id
LEFT JOIN version_range vr ON vr.id = a.version_range_id
WHERE a.advisory_id = $1 AND {MATCH_CONDITION}
"#
            ),
            [advisory_id.into()],
        ))
        .all(tx)
        .instrument(info_span!("matching cpes"))
        .await?;

        let matched_values = matched_values(rows.iter().map(|r| &r.assertion), tx).await?;

        rows.into_iter()
            .map(|row| {
                Ok(NodeMatch {
                    node: NodeRef {
                        sbom_id: row.sbom_id,
                        node_id: row.node_id,
                    },
                    assertion: assertion(row.assertion, &matched_values)?,
                })
            })
            .collect()
    }
}

/// Turn a matched row into an assertion.
fn assertion(
    row: AssertionRow,
    matched_values: &HashMap<(Uuid, Option<Uuid>), String>,
) -> Result<Assertion, Error> {
    let check = match row.version_check.as_str() {
        "exact" => VersionCheck::Exact,
        "range" => VersionCheck::Range,
        _ => VersionCheck::Any,
    };
    Ok(Assertion {
        status: AssertionStatus::try_from_value(&row.status)?,
        confidence: check.confidence(),
        matched_value: matched_values
            .get(&(row.cpe_id, row.version_range_id))
            .cloned()
            .unwrap_or_default(),
        advisory_id: row.advisory_id,
        vulnerability_id: row.vulnerability_id,
    })
}

/// The advisory side values of the matches, for presentation, keyed by CPE and version range ID.
async fn matched_values(
    rows: impl IntoIterator<Item = &AssertionRow>,
    connection: &impl ConnectionTrait,
) -> Result<HashMap<(Uuid, Option<Uuid>), String>, Error> {
    let keys = rows
        .into_iter()
        .map(|r| (r.cpe_id, r.version_range_id))
        .collect::<BTreeSet<_>>();
    if keys.is_empty() {
        return Ok(HashMap::new());
    }

    let cpes = cpe::Entity::find()
        .filter(cpe::Column::Id.is_in(keys.iter().map(|(cpe, _)| *cpe).collect::<BTreeSet<_>>()))
        .all(connection)
        .instrument(info_span!("loading matched cpes"))
        .await?
        .into_iter()
        .map(|c| (c.id, c))
        .collect::<HashMap<_, _>>();

    let ranges = version_range::Entity::find()
        .filter(
            version_range::Column::Id
                .is_in(keys.iter().filter_map(|(_, r)| *r).collect::<BTreeSet<_>>()),
        )
        .all(connection)
        .instrument(info_span!("loading matched version ranges"))
        .await?
        .into_iter()
        .map(|r| (r.id, r))
        .collect::<HashMap<_, _>>();

    Ok(keys
        .into_iter()
        .filter_map(|(cpe_id, range_id)| {
            let cpe = format_cpe23(cpes.get(&cpe_id)?);
            let value = match range_id.and_then(|id| ranges.get(&id)) {
                Some(range) => format!("{cpe} {}", format_range(range)),
                None => cpe,
            };
            Some(((cpe_id, range_id), value))
        })
        .collect())
}

/// Format a version range for presentation, e.g. `semver:[1.0.0,4.10.0)`.
fn format_range(range: &version_range::Model) -> String {
    let low = range.low_version.as_deref().unwrap_or("*");
    let high = range.high_version.as_deref().unwrap_or("*");
    let open = if range.low_inclusive == Some(true) {
        '['
    } else {
        '('
    };
    let close = if range.high_inclusive == Some(true) {
        ']'
    } else {
        ')'
    };
    format!("{}:{open}{low},{high}{close}", range.version_scheme_id)
}

/// Format a stored CPE as CPE 2.3 formatted string, including the extended attributes.
fn format_cpe23(model: &cpe::Model) -> String {
    fn component(value: &Option<String>) -> String {
        match value.as_deref() {
            None => "-".to_string(),
            Some("*") => "*".to_string(),
            Some(value) => {
                let mut result = String::with_capacity(value.len());
                for c in value.chars() {
                    // keep wildcards, escape other special characters
                    if !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '*' | '?')) {
                        result.push('\\');
                    }
                    result.push(c);
                }
                result
            }
        }
    }

    let part = model
        .part
        .as_deref()
        .filter(|p| !p.is_empty())
        .unwrap_or("*");
    let components = [
        &model.vendor,
        &model.product,
        &model.version,
        &model.update,
        &model.edition,
        &model.language,
        &model.sw_edition,
        &model.target_sw,
        &model.target_hw,
        &model.other,
    ]
    .map(component);

    format!("cpe:2.3:{part}:{}", components.join(":"))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::extractor::Extractors;
    use sea_orm::{QueryOrder, TransactionTrait};
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::advisory_vulnerability_cpe;
    use trustify_entity::{correlation_evidence, correlation_evidence::AssertionStatus};
    use trustify_test_context::TrustifyContext;

    const SBOM: &str = "cyclonedx/cpe_edge_cases.json";
    const WAGO: &str = "scenarios/S20_cpe_range_wago/vex/vde-2025-081.json";
    const BECKHOFF: &str = "scenarios/S21_cpe_extended_attributes_beckhoff/vex/vde-2025-092.json";
    const PHOENIX: &str = "scenarios/S22_cpe_third_party_openssl_phoenix/vex/vde-2025-056.json";

    fn extractors() -> Extractors {
        Extractors::new(vec![Box::new(CpeExtractor)])
    }

    /// Evidence of an SBOM: (node, vulnerability, status, confidence, matched value), sorted.
    async fn evidence(
        ctx: &TrustifyContext,
        sbom_id: Uuid,
    ) -> anyhow::Result<Vec<(String, String, AssertionStatus, f64, String)>> {
        Ok(correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(correlation_evidence::Column::Extractor.eq("cpe"))
            .order_by_asc(correlation_evidence::Column::NodeId)
            .order_by_asc(correlation_evidence::Column::VulnerabilityId)
            .order_by_asc(correlation_evidence::Column::MatchedValue)
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|e| {
                (
                    e.node_id,
                    e.vulnerability_id,
                    e.status,
                    e.confidence,
                    e.matched_value.unwrap_or_default(),
                )
            })
            .collect())
    }

    async fn ingest_all(ctx: &TrustifyContext) -> anyhow::Result<(Uuid, Vec<Uuid>)> {
        let sbom = ctx.ingest_document(SBOM).await?;
        let mut advisories = Vec::new();
        for advisory in [WAGO, BECKHOFF, PHOENIX] {
            advisories.push(Uuid::parse_str(&ctx.ingest_document(advisory).await?.id)?);
        }
        Ok((Uuid::parse_str(&sbom.id)?, advisories))
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

    fn expected() -> Vec<(String, String, AssertionStatus, f64, String)> {
        const WAGO_RANGE: &str =
            "cpe:2.3:o:wago:wago_os_linux:*:*:*:*:*:*:*:* semver:[1.0.0,4.10.0)";
        const WAGO_FIXED: &str = "cpe:2.3:o:wago:wago_os_linux:4.10.0:*:*:*:*:*:*:*";
        const WAGO_HARDENED_RANGE: &str =
            "cpe:2.3:o:wago:wago_os_linux_hardened:*:*:*:*:*:*:*:* semver:[1.0.0,4.10.0(70))";
        const MDP_ARM32: &str = "cpe:2.3:a:beckhoff:MDP.dll:1.7.0.0:*:*:*:*:*:arm32:*";
        const MDP_X86: &str = "cpe:2.3:a:beckhoff:MDP.dll:1.7.0.0:*:*:*:*:*:x86:*";

        let mut result = Vec::new();
        for (node, vulns, status, confidence, matched) in [
            (
                "mdp-arm32",
                BECKHOFF_CVES,
                AssertionStatus::Fixed,
                0.8,
                MDP_ARM32,
            ),
            (
                "mdp-x86",
                BECKHOFF_CVES,
                AssertionStatus::Fixed,
                0.8,
                MDP_X86,
            ),
            (
                "wago-os-affected",
                WAGO_CVES,
                AssertionStatus::Affected,
                0.7,
                WAGO_RANGE,
            ),
            (
                "wago-os-fixed",
                WAGO_CVES,
                AssertionStatus::Fixed,
                0.8,
                WAGO_FIXED,
            ),
            (
                "wago-os-hardened",
                WAGO_CVES,
                AssertionStatus::Affected,
                0.7,
                WAGO_HARDENED_RANGE,
            ),
        ] {
            for vuln in vulns {
                result.push((
                    node.to_string(),
                    vuln.to_string(),
                    status,
                    confidence,
                    matched.to_string(),
                ));
            }
        }
        result
    }

    const WAGO_CVES: [&str; 3] = ["CVE-2025-41700", "CVE-2025-41738", "CVE-2025-41739"];
    const BECKHOFF_CVES: [&str; 3] = ["CVE-2025-41726", "CVE-2025-41727", "CVE-2025-41728"];

    /// In range, exact version, out of range, extended attributes, SBOM ANY attributes, and a
    /// version the range's scheme can't compare (`V1.2.1.S0`), which must not match or fail.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn match_from_sbom(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let (sbom_id, _) = ingest_all(ctx).await?;

        extract_for_sbom(ctx, sbom_id).await?;

        assert_eq!(evidence(ctx, sbom_id).await?, expected());

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn match_from_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let (sbom_id, advisories) = ingest_all(ctx).await?;

        for advisory_id in advisories {
            extract_for_advisory(ctx, advisory_id).await?;
        }

        assert_eq!(evidence(ctx, sbom_id).await?, expected());

        Ok(())
    }

    /// Both directions must produce the same evidence rows (same deterministic IDs).
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn both_directions_produce_same_evidence(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let (sbom_id, advisories) = ingest_all(ctx).await?;

        let load = || async {
            let mut ids = correlation_evidence::Entity::find()
                .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
                .all(&ctx.db)
                .await?
                .into_iter()
                .map(|e| e.id)
                .collect::<Vec<_>>();
            ids.sort();
            Ok::<_, anyhow::Error>(ids)
        };

        extract_for_sbom(ctx, sbom_id).await?;
        let from_sbom = load().await?;

        for advisory_id in advisories {
            extract_for_advisory(ctx, advisory_id).await?;
        }
        assert_eq!(from_sbom, load().await?);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn no_match_without_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx.ingest_document(SBOM).await?;

        let count = extract_for_sbom(ctx, Uuid::parse_str(&sbom.id)?).await?;
        assert_eq!(count, 0);

        Ok(())
    }

    /// For relationships, only the component side (firmware) yields CPE assertions, not the
    /// platform (hardware) it is installed on.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn relationship_platform_excluded(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let advisory_id = Uuid::parse_str(&ctx.ingest_document(PHOENIX).await?.id)?;

        let rows = advisory_vulnerability_cpe::Entity::find()
            .filter(advisory_vulnerability_cpe::Column::AdvisoryId.eq(advisory_id))
            .all(&ctx.db)
            .await?;
        let mut cpes = rows
            .load_one(cpe::Entity, &ctx.db)
            .await?
            .into_iter()
            .flatten()
            .map(|c| format_cpe23(&c))
            .collect::<Vec<_>>();
        cpes.sort();
        cpes.dedup();

        assert_eq!(
            cpes,
            [
                "cpe:2.3:o:phoenix_contact:charx_sec3xxx_firmware:2026.0.3:*:*:*:*:*:*:*",
                "cpe:2.3:o:phoenix_contact:plcnext_firmware:*:*:*:*:*:*:*:*",
            ]
        );

        Ok(())
    }

    /// The ad-hoc query uses the same matching.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn query(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let (_, advisories) = ingest_all(ctx).await?;

        let tx = ctx.db.begin().await?;
        let mut result = extractors()
            .query(
                &IdentifierRef {
                    kind: IdentifierKind::Cpe,
                    value: "cpe:2.3:o:wago:wago_os_linux:4.8.9:*:*:*:*:*:*:*".into(),
                },
                &tx,
            )
            .await?;
        result.sort_by(|a, b| a.vulnerability_id.cmp(&b.vulnerability_id));

        assert_eq!(
            result,
            WAGO_CVES
                .into_iter()
                .map(|vuln| Assertion {
                    advisory_id: advisories[0],
                    vulnerability_id: vuln.to_string(),
                    status: AssertionStatus::Affected,
                    confidence: 0.7,
                    matched_value:
                        "cpe:2.3:o:wago:wago_os_linux:*:*:*:*:*:*:*:* semver:[1.0.0,4.10.0)"
                            .to_string(),
                })
                .collect::<Vec<_>>()
        );

        Ok(())
    }

    /// The matching rules, evaluated by the database. Each case gets an assertion of its own
    /// (`case-<n>`), all SBOM CPEs are matched in one go.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn matching_rules(ctx: &TrustifyContext) -> anyhow::Result<()> {
        use sea_orm::{ActiveModelTrait, Set};

        struct Case {
            advisory: &'static str,
            /// semver range `[low, high)`
            range: Option<(&'static str, &'static str)>,
            sbom: &'static str,
            expected: Option<VersionCheck>,
        }
        let case = |advisory, range, sbom, expected| Case {
            advisory,
            range,
            sbom,
            expected,
        };

        let cases = [
            // exact version
            case(
                "cpe:2.3:o:wago:wago_os_linux:4.10.0:*:*:*:*:*:*:*",
                None,
                "cpe:2.3:o:wago:wago_os_linux:4.10.0:*:*:*:*:*:*:*",
                Some(VersionCheck::Exact),
            ),
            case(
                "cpe:2.3:o:wago:wago_os_linux:4.10.0:*:*:*:*:*:*:*",
                None,
                "cpe:2.3:o:wago:wago_os_linux:4.8.9:*:*:*:*:*:*:*",
                None,
            ),
            // version ANY, with a range (in, out) and without
            case(
                "cpe:2.3:o:wago:wago_os_linux:*:*:*:*:*:*:*:*",
                Some(("1.0.0", "4.10.0")),
                "cpe:2.3:o:wago:wago_os_linux:4.8.9:*:*:*:*:*:*:*",
                Some(VersionCheck::Range),
            ),
            case(
                "cpe:2.3:o:wago:wago_os_linux:*:*:*:*:*:*:*:*",
                Some(("1.0.0", "4.10.0")),
                "cpe:2.3:o:wago:wago_os_linux:4.10.0:*:*:*:*:*:*:*",
                None,
            ),
            case(
                "cpe:2.3:h:phoenix_contact:axc_f_1152:*:*:*:*:*:*:*:*",
                None,
                "cpe:2.3:h:phoenix_contact:axc_f_1152:1:*:*:*:*:*:*:*",
                Some(VersionCheck::Any),
            ),
            // the SBOM must have a concrete version
            case(
                "cpe:2.3:o:wago:wago_os_linux_x:*:*:*:*:*:*:*:*",
                None,
                "cpe:2.3:o:wago:wago_os_linux_x:*:*:*:*:*:*:*:*",
                None,
            ),
            // different vendor, product or part
            case(
                "cpe:2.3:o:wago:os_a:*:*:*:*:*:*:*:*",
                None,
                "cpe:2.3:o:other:os_a:4.8.9:*:*:*:*:*:*:*",
                None,
            ),
            case(
                "cpe:2.3:o:wago:os_b:*:*:*:*:*:*:*:*",
                None,
                "cpe:2.3:o:wago:os_b_hardened:4.8.9:*:*:*:*:*:*:*",
                None,
            ),
            case(
                "cpe:2.3:o:wago:os_c:*:*:*:*:*:*:*:*",
                None,
                "cpe:2.3:a:wago:os_c:4.8.9:*:*:*:*:*:*:*",
                None,
            ),
            // case-insensitive
            case(
                "cpe:2.3:a:beckhoff:MDP.dll:1.2.4.0:*:*:*:*:*:x86:*",
                None,
                "cpe:2.3:a:beckhoff:mdp.dll:1.2.4.0:*:*:*:*:*:X86:*",
                Some(VersionCheck::Exact),
            ),
            // extended attributes: different, SBOM ANY (strict superset), advisory ANY
            case(
                "cpe:2.3:a:beckhoff:mdp_a.dll:1.2.4.0:*:*:*:*:*:x86:*",
                None,
                "cpe:2.3:a:beckhoff:mdp_a.dll:1.2.4.0:*:*:*:*:*:arm32:*",
                None,
            ),
            case(
                "cpe:2.3:a:beckhoff:mdp_b.dll:1.2.4.0:*:*:*:*:*:x86:*",
                None,
                "cpe:2.3:a:beckhoff:mdp_b.dll:1.2.4.0:*:*:*:*:*:*:*",
                None,
            ),
            case(
                "cpe:2.3:a:beckhoff:ipc_diag:2.4.5:*:*:*:*:Windows:*:*",
                None,
                "cpe:2.3:a:beckhoff:ipc_diag:2.4.5:*:*:*:*:windows:x64:*",
                Some(VersionCheck::Exact),
            ),
            // not applicable only matches not applicable
            case(
                "cpe:2.3:a:openssl:openssl_a:3.0.14:-:*:*:*:*:*:*",
                None,
                "cpe:2.3:a:openssl:openssl_a:3.0.14:-:*:*:*:*:*:*",
                Some(VersionCheck::Exact),
            ),
            case(
                "cpe:2.3:a:openssl:openssl_b:3.0.14:-:*:*:*:*:*:*",
                None,
                "cpe:2.3:a:openssl:openssl_b:3.0.14:*:*:*:*:*:*:*",
                None,
            ),
            // wildcards inside values, and LIKE metacharacters taken literally
            case(
                "cpe:2.3:a:openssl:openssl_c:3.0.*:*:*:*:*:*:*:*",
                None,
                "cpe:2.3:a:openssl:openssl_c:3.0.14:*:*:*:*:*:*:*",
                Some(VersionCheck::Exact),
            ),
            case(
                "cpe:2.3:a:vendor:product_d:1.0:*:*:*:*:*:*:*",
                None,
                "cpe:2.3:a:vendor:product_d:1x0:*:*:*:*:*:*:*",
                None,
            ),
            // CPE 2.2 URI
            case(
                "cpe:/o:suse:sles:12:sp2",
                None,
                "cpe:2.3:o:suse:sles:12:sp2:*:*:*:*:*:*",
                Some(VersionCheck::Exact),
            ),
        ];

        let advisory_id = Uuid::parse_str(&ctx.ingest_document(WAGO).await?.id)?;

        for (
            n,
            Case {
                advisory, range, ..
            },
        ) in cases.iter().enumerate()
        {
            let cpe = Cpe::from_str(advisory)?;
            let cpe_id = cpe.uuid();
            cpe::Entity::insert(cpe::ActiveModel::from_cpe(cpe))
                .on_conflict_do_nothing()
                .exec(&ctx.db)
                .await?;

            let version_range_id = match range {
                Some((low, high)) => {
                    let id = Uuid::new_v4();
                    version_range::ActiveModel {
                        id: Set(id),
                        version_scheme_id: Set(
                            trustify_entity::version_scheme::VersionScheme::Semver,
                        ),
                        low_version: Set(Some(low.to_string())),
                        low_inclusive: Set(Some(true)),
                        high_version: Set(Some(high.to_string())),
                        high_inclusive: Set(Some(false)),
                    }
                    .insert(&ctx.db)
                    .await?;
                    Some(id)
                }
                None => None,
            };

            advisory_vulnerability_cpe::ActiveModel {
                id: Set(Uuid::new_v4()),
                advisory_id: Set(advisory_id),
                vulnerability_id: Set(format!("case-{n}")),
                status: Set(AssertionStatus::Affected),
                cpe_id: Set(cpe_id),
                version_range_id: Set(version_range_id),
            }
            .insert(&ctx.db)
            .await?;
        }

        let identifiers = cases
            .iter()
            .map(|Case { sbom, .. }| IdentifierRef {
                kind: IdentifierKind::Cpe,
                value: sbom.to_string(),
            })
            .collect::<Vec<_>>();

        let tx = ctx.db.begin().await?;
        let matches = CpeExtractor.match_identifiers(&identifiers, &tx).await?;

        // only the case's own assertion is of interest, not other cases sharing a product
        let actual = (0..cases.len())
            .map(|n| {
                let confidence = matches
                    .iter()
                    .find(|m| m.index == n && m.assertion.vulnerability_id == format!("case-{n}"))
                    .map(|m| m.assertion.confidence);
                (n, confidence)
            })
            .collect::<Vec<_>>();
        let expected = cases
            .iter()
            .enumerate()
            .map(|(n, Case { expected, .. })| (n, expected.map(VersionCheck::confidence)))
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);

        Ok(())
    }
}
