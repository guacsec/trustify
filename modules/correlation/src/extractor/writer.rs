use super::{Assertion, NodeRef};
use crate::error::Error;
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use tracing::{Instrument, info_span};
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::correlation_evidence;
use uuid::Uuid;

/// Root namespace for evidence IDs, combined with the evidence type.
const EVIDENCE_NAMESPACE: Uuid = Uuid::from_bytes([
    0xd1, 0x9e, 0x57, 0xa3, 0x2b, 0x4c, 0x6d, 0x8e, 0x9f, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06,
]);

/// Collects evidence and writes it to `correlation_evidence`.
///
/// Each piece of evidence is stored under the type of its [`Assertion::extractor`].
#[derive(Default)]
pub struct EvidenceWriter {
    models: Vec<correlation_evidence::ActiveModel>,
}

impl EvidenceWriter {
    /// Create a new, empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one piece of evidence, linking a node to an assertion.
    pub fn add(&mut self, node: &NodeRef, assertion: Assertion) -> Result<(), Error> {
        let id = Self::evidence_id(node, &assertion);
        let matched_value =
            serde_json::to_value(&assertion.matched_value).map_err(Error::MatchedValue)?;
        self.models.push(correlation_evidence::ActiveModel {
            id: Set(id),
            sbom_id: Set(node.sbom_id),
            node_id: Set(node.node_id.clone()),
            advisory_id: Set(assertion.advisory_id),
            vulnerability_id: Set(assertion.vulnerability_id),
            status: Set(assertion.status),
            confidence: Set(assertion.confidence),
            extractor: Set(assertion.extractor.to_string()),
            matched_value: Set(Some(matched_value)),
            created_at: Set(time::OffsetDateTime::now_utc()),
        });
        Ok(())
    }

    /// Deterministic ID per (evidence type, sbom, node, advisory, vulnerability).
    fn evidence_id(node: &NodeRef, assertion: &Assertion) -> Uuid {
        let namespace = Uuid::new_v5(&EVIDENCE_NAMESPACE, assertion.extractor.as_bytes());
        let mut id = Uuid::new_v5(&namespace, node.sbom_id.as_bytes());
        id = Uuid::new_v5(&id, node.node_id.as_bytes());
        id = Uuid::new_v5(&id, assertion.advisory_id.as_bytes());
        Uuid::new_v5(&id, assertion.vulnerability_id.as_bytes())
    }

    /// Insert all collected evidence, ignoring already existing rows.
    ///
    /// Returns the number of evidence entries produced (before de-duplication).
    pub async fn write(mut self, connection: &impl ConnectionTrait) -> Result<usize, Error> {
        let count = self.models.len();

        // consistent lock ordering
        self.models.sort_by_key(|m| *m.id.as_ref());

        for batch in &self.models.chunked() {
            correlation_evidence::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .instrument(info_span!("inserting evidence"))
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
        };

        assert_eq!(
            EvidenceWriter::evidence_id(&node, &assertion),
            Uuid::parse_str("39e5eccd-4581-5359-91a0-028bb920c39d").unwrap()
        );
    }
}
