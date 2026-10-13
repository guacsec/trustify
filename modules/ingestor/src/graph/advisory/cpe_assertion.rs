//! CPE assertions of advisories (`advisory_vulnerability_cpe`): the status of a CPE (pattern),
//! optionally within a version range and in a product (context), as the correlation engine's CPE
//! extractor matches them.

use crate::graph::{advisory::version::VersionInfo, cpe::CpeCreator};
use sea_orm::{ActiveEnum, ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use std::collections::BTreeMap;
use trustify_common::{cpe::Cpe, db::chunk::EntityChunkedIter};
use trustify_entity::{
    advisory_vulnerability_cpe, correlation_evidence::AssertionStatus, version_range,
};
use uuid::Uuid;

/// Namespace of the IDs of `advisory_vulnerability_cpe` rows.
const NAMESPACE: Uuid = Uuid::from_bytes([
    0x5c, 0x1e, 0x8b, 0x3f, 0x92, 0x7d, 0x4a, 0x06, 0xb4, 0x2e, 0x61, 0xc9, 0x0f, 0xd8, 0x37, 0xa5,
]);

/// A CPE assertion of an advisory's vulnerability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpeAssertion {
    pub vulnerability_id: String,
    pub cpe: Cpe,
    /// The version range, `None` for the version of the CPE (or all versions, if ANY).
    pub range: Option<VersionInfo>,
    pub status: AssertionStatus,
    /// The product the assertion is stated in, see [`super::context`].
    pub context: Option<Uuid>,
    /// Whether it is the default status: of all versions no other assertion lists.
    pub default: bool,
}

impl CpeAssertion {
    /// The deterministic ID of the row.
    pub fn uuid(&self, advisory_id: Uuid) -> Uuid {
        let mut id = Uuid::new_v5(&NAMESPACE, advisory_id.as_bytes());
        id = Uuid::new_v5(&id, self.vulnerability_id.as_bytes());
        id = Uuid::new_v5(&id, self.cpe.uuid().as_bytes());
        id = Uuid::new_v5(
            &id,
            self.range
                .as_ref()
                .map(VersionInfo::uuid)
                .unwrap_or_default()
                .as_bytes(),
        );
        id = Uuid::new_v5(&id, self.status.to_value().as_bytes());
        // without a context or default, the ID is the same as before they existed
        if let Some(context) = self.context {
            id = Uuid::new_v5(&id, context.as_bytes());
        }
        if self.default {
            id = Uuid::new_v5(&id, b"default");
        }
        id
    }
}

/// Creates the CPE assertions of an advisory in batch, with their CPEs and version ranges.
///
/// The assertion contexts must exist when creating.
#[derive(Debug)]
pub struct CpeAssertionCreator {
    advisory_id: Uuid,
    assertions: BTreeMap<Uuid, CpeAssertion>,
}

impl CpeAssertionCreator {
    pub fn new(advisory_id: Uuid) -> Self {
        Self {
            advisory_id,
            assertions: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, assertion: CpeAssertion) {
        self.assertions
            .entry(assertion.uuid(self.advisory_id))
            .or_insert(assertion);
    }

    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        if self.assertions.is_empty() {
            return Ok(());
        }

        let mut cpes = CpeCreator::new();
        let mut version_ranges = BTreeMap::new();
        let mut rows = Vec::with_capacity(self.assertions.len());

        // the map is ordered by ID, keeping the lock order stable
        for (id, assertion) in self.assertions {
            let version_range_id = assertion.range.as_ref().map(|range| {
                let id = range.uuid();
                version_ranges
                    .entry(id)
                    .or_insert_with(|| range.clone().into_active_model());
                id
            });
            rows.push(advisory_vulnerability_cpe::ActiveModel {
                id: Set(id),
                advisory_id: Set(self.advisory_id),
                vulnerability_id: Set(assertion.vulnerability_id),
                status: Set(assertion.status),
                cpe_id: Set(assertion.cpe.uuid()),
                version_range_id: Set(version_range_id),
                assertion_context_id: Set(assertion.context),
                is_default: Set(assertion.default),
            });
            cpes.add(assertion.cpe);
        }

        cpes.create(db).await?;

        for batch in &version_ranges.into_values().chunked() {
            version_range::Entity::insert_many(batch)
                .on_conflict(OnConflict::new().do_nothing().to_owned())
                .try_insert()
                .exec_without_returning(db)
                .await?;
        }

        for batch in &rows.into_iter().chunked() {
            advisory_vulnerability_cpe::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(db)
                .await?;
        }

        Ok(())
    }
}
