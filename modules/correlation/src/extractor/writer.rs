use super::{Assertion, NodeRef, context::ContextLink};
use crate::error::Error;
use sea_orm::{ActiveEnum, ActiveValue::Set, ConnectionTrait, EntityTrait};
use std::collections::BTreeMap;
use tracing::{Instrument, info_span};
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{correlation_evidence, correlation_evidence_context};
use uuid::Uuid;

/// Root namespace for evidence IDs, combined with the evidence type.
const EVIDENCE_NAMESPACE: Uuid = Uuid::from_bytes([
    0xd1, 0x9e, 0x57, 0xa3, 0x2b, 0x4c, 0x6d, 0x8e, 0x9f, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06,
]);

/// A piece of evidence, with the contexts it was matched in.
struct Pending {
    node: NodeRef,
    assertion: Assertion,
    links: Vec<ContextLink>,
}

/// Collects evidence and writes it to `correlation_evidence`, and its contexts to
/// `correlation_evidence_context`.
///
/// Each piece of evidence is stored under the type of its [`Assertion::extractor`]. Assertions
/// resulting in the same evidence (e.g. the same statement in several products) are merged: the
/// best confidence, all version ranges, and all contexts.
#[derive(Default)]
pub struct EvidenceWriter {
    evidence: BTreeMap<Uuid, Pending>,
}

impl EvidenceWriter {
    /// Create a new, empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one piece of evidence, linking a node to an assertion, without a context.
    pub fn add(&mut self, node: &NodeRef, assertion: Assertion) -> Result<(), Error> {
        self.add_in_context(node, assertion, Vec::new())
    }

    /// Add one piece of evidence, linking a node to an assertion, matched in the given contexts.
    pub fn add_in_context(
        &mut self,
        node: &NodeRef,
        assertion: Assertion,
        links: Vec<ContextLink>,
    ) -> Result<(), Error> {
        let id = Self::evidence_id(node, &assertion);
        match self.evidence.get_mut(&id) {
            Some(pending) => {
                pending.assertion.confidence =
                    pending.assertion.confidence.max(assertion.confidence);
                let ranges = &mut pending.assertion.matched_value.ranges;
                ranges.extend(assertion.matched_value.ranges);
                ranges.sort();
                ranges.dedup();
                pending.links.extend(links);
            }
            None => {
                self.evidence.insert(
                    id,
                    Pending {
                        node: node.clone(),
                        assertion,
                        links,
                    },
                );
            }
        }
        Ok(())
    }

    /// Deterministic ID per (evidence type, sbom, node, advisory, vulnerability, status, identifier).
    ///
    /// The status is part of it, as one evidence type may find conflicting statements (e.g. of
    /// different products) for the same node.
    fn evidence_id(node: &NodeRef, assertion: &Assertion) -> Uuid {
        let namespace = Uuid::new_v5(&EVIDENCE_NAMESPACE, assertion.extractor.as_bytes());
        let mut id = Uuid::new_v5(&namespace, node.sbom_id.as_bytes());
        id = Uuid::new_v5(&id, node.node_id.as_bytes());
        id = Uuid::new_v5(&id, assertion.advisory_id.as_bytes());
        id = Uuid::new_v5(&id, assertion.vulnerability_id.as_bytes());
        id = Uuid::new_v5(&id, assertion.status.to_value().as_bytes());
        // PURL evidence preserves each original qualified identifier. Other extractors retain
        // their existing grouping (e.g. several CPE patterns contributing to one assertion).
        if assertion.extractor.starts_with("purl") && !assertion.matched_value.identifier.is_empty()
        {
            id = Uuid::new_v5(&id, assertion.matched_value.identifier.as_bytes());
        }
        if let Some(provider) = &assertion.matched_value.source_provider {
            id = Uuid::new_v5(&id, serde_json::json!(provider).to_string().as_bytes());
        }
        id
    }

    /// Insert all collected evidence and its contexts, ignoring already existing rows.
    ///
    /// Returns the number of evidence entries produced.
    pub async fn write(self, connection: &impl ConnectionTrait) -> Result<usize, Error> {
        let count = self.evidence.len();

        let mut models = Vec::with_capacity(count);
        let mut links = Vec::new();
        // ordered by ID: consistent lock ordering
        for (id, pending) in self.evidence {
            let Pending {
                node,
                assertion,
                links: contexts,
            } = pending;
            let matched_value =
                serde_json::to_value(&assertion.matched_value).map_err(Error::MatchedValue)?;
            for link in contexts {
                links.push(correlation_evidence_context::ActiveModel {
                    evidence_id: Set(id),
                    context_id: Set(link.context_id),
                    source: Set(link.source),
                    distance: Set(link.distance),
                    node_identifier: Set(link.node_identifier),
                    context_identifier: Set(link.context_identifier),
                    confidence: Set(link.confidence),
                });
            }
            models.push(correlation_evidence::ActiveModel {
                id: Set(id),
                sbom_id: Set(node.sbom_id),
                node_id: Set(node.node_id),
                advisory_id: Set(assertion.advisory_id),
                vulnerability_id: Set(assertion.vulnerability_id),
                status: Set(assertion.status),
                confidence: Set(assertion.confidence),
                extractor: Set(assertion.extractor.to_string()),
                matched_value: Set(Some(matched_value)),
                created_at: Set(time::OffsetDateTime::now_utc()),
            });
        }

        for batch in &models.chunked() {
            correlation_evidence::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .instrument(info_span!("inserting evidence"))
                .await?;
        }
        for batch in &links.chunked() {
            correlation_evidence_context::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .instrument(info_span!("inserting evidence contexts"))
                .await?;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::MatchedValue;
    use trustify_entity::correlation_evidence::AssertionStatus;

    /// The evidence ID must stay stable, as existing rows are de-duplicated by it.
    #[test]
    fn evidence_id_is_stable() {
        let node = NodeRef {
            sbom_id: Uuid::nil(),
            node_id: "node".into(),
        };
        let assertion = Assertion {
            extractor: "digest",
            advisory_id: Uuid::nil(),
            vulnerability_id: "CVE-0000-0001".into(),
            status: AssertionStatus::Affected,
            confidence: 1.0,
            matched_value: MatchedValue::default(),
            context_id: None,
            requires_context: false,
        };

        assert_eq!(
            EvidenceWriter::evidence_id(&node, &assertion),
            Uuid::parse_str("370bbae1-96e7-5dc2-9688-c98f1be1c28c").unwrap()
        );

        // another status of the same evidence type is another piece of evidence
        let not_affected = Assertion {
            status: AssertionStatus::NotAffected,
            ..assertion.clone()
        };
        assert_ne!(
            EvidenceWriter::evidence_id(&node, &assertion),
            EvidenceWriter::evidence_id(&node, &not_affected)
        );

        // Distinct source identifiers must not lose their provenance by being merged.
        let mut writer = EvidenceWriter::new();
        for identifier in [
            "pkg:rpm/redhat/firefox",
            "pkg:rpm/redhat/firefox?rpmmod=firefox:flatpak",
        ] {
            writer
                .add(
                    &node,
                    Assertion {
                        extractor: "purl",
                        matched_value: MatchedValue::new(identifier),
                        ..assertion.clone()
                    },
                )
                .unwrap();
        }
        assert_eq!(writer.evidence.len(), 2);
    }

    /// The same assertion in several contexts (products) is one piece of evidence: with the best
    /// confidence, all ranges, and all contexts.
    #[test]
    fn merge_contexts() {
        use crate::{
            extractor::context::ContextLink,
            model::{MatchedRange, RangeBound},
        };
        use trustify_entity::correlation_evidence_context::ContextSource;

        let node = NodeRef {
            sbom_id: Uuid::nil(),
            node_id: "node".into(),
        };
        let range = |version: &str| MatchedRange {
            scheme: "rpm".into(),
            low: None,
            high: Some(RangeBound {
                version: version.into(),
                inclusive: false,
            }),
        };
        let assertion = |context: u128, confidence: f64, version: &str| Assertion {
            extractor: "purl",
            advisory_id: Uuid::nil(),
            vulnerability_id: "CVE-0000-0001".into(),
            status: AssertionStatus::Affected,
            confidence,
            matched_value: MatchedValue {
                source_provider: None,
                origin: crate::model::AssertionOrigin::Stated,
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: vec![range(version)],
                enabled_by: None,
            },
            context_id: Some(Uuid::from_u128(context)),
            requires_context: false,
        };
        let link = |context: u128, confidence: f64| ContextLink {
            context_id: Uuid::from_u128(context),
            source: ContextSource::Describing,
            distance: 0,
            node_identifier: format!("cpe:{context}"),
            context_identifier: format!("cpe:{context}"),
            confidence,
        };

        let mut writer = EvidenceWriter::new();
        writer
            .add_in_context(&node, assertion(1, 0.8, "2"), vec![link(1, 0.8)])
            .unwrap();
        writer
            .add_in_context(&node, assertion(2, 0.9, "1"), vec![link(2, 0.9)])
            .unwrap();

        let [pending] = writer
            .evidence
            .into_values()
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        assert_eq!(pending.assertion.confidence, 0.9);
        assert_eq!(
            pending.assertion.matched_value.ranges,
            [range("1"), range("2")]
        );
        assert_eq!(pending.links, [link(1, 0.8), link(2, 0.9)]);
    }
}
