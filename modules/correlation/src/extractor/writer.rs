use super::{Assertion, NodeRef};
use crate::error::Error;
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use tracing::{Instrument, info_span};
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::correlation_evidence;
use uuid::Uuid;

/// Root namespace for evidence IDs, combined with the extractor ID.
const EVIDENCE_NAMESPACE: Uuid = Uuid::from_bytes([
    0xd1, 0x9e, 0x57, 0xa3, 0x2b, 0x4c, 0x6d, 0x8e, 0x9f, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06,
]);

/// Collects evidence of a single extractor and writes it to `correlation_evidence`.
pub struct EvidenceWriter {
    extractor: &'static str,
    namespace: Uuid,
    models: Vec<correlation_evidence::ActiveModel>,
}

impl EvidenceWriter {
    /// Create a new writer for the extractor with the given ID.
    pub fn new(extractor: &'static str) -> Self {
        Self {
            extractor,
            namespace: Uuid::new_v5(&EVIDENCE_NAMESPACE, extractor.as_bytes()),
            models: Vec::new(),
        }
    }

    /// Add one piece of evidence, linking a node to an assertion.
    pub fn add(&mut self, node: &NodeRef, assertion: Assertion) {
        let id = self.evidence_id(node, &assertion);
        self.models.push(correlation_evidence::ActiveModel {
            id: Set(id),
            sbom_id: Set(node.sbom_id),
            node_id: Set(node.node_id.clone()),
            advisory_id: Set(assertion.advisory_id),
            vulnerability_id: Set(assertion.vulnerability_id),
            status: Set(assertion.status),
            confidence: Set(assertion.confidence),
            extractor: Set(self.extractor.to_string()),
            matched_value: Set(Some(assertion.matched_value)),
            created_at: Set(time::OffsetDateTime::now_utc()),
        });
    }

    /// Deterministic ID per (extractor, sbom, node, advisory, vulnerability).
    fn evidence_id(&self, node: &NodeRef, assertion: &Assertion) -> Uuid {
        let mut id = Uuid::new_v5(&self.namespace, node.sbom_id.as_bytes());
        id = Uuid::new_v5(&id, node.node_id.as_bytes());
        id = Uuid::new_v5(&id, assertion.advisory_id.as_bytes());
        Uuid::new_v5(&id, assertion.vulnerability_id.as_bytes())
    }

    /// Insert all collected evidence, ignoring already existing rows.
    ///
    /// Returns the number of evidence entries produced (before de-duplication).
    pub async fn write(mut self, connection: &impl ConnectionTrait) -> Result<u64, Error> {
        let count = self.models.len() as u64;

        // consistent lock ordering
        self.models.sort_by_key(|m| *m.id.as_ref());

        for batch in &self.models.chunked() {
            correlation_evidence::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .instrument(info_span!("inserting evidence", extractor = self.extractor))
                .await?;
        }

        Ok(count)
    }
}
