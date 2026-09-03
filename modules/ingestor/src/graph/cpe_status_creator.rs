use crate::graph::{
    advisory::{cpe_status::CpeStatus, version::VersionInfo},
    error::Error,
};
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use sea_query::OnConflict;
use std::collections::BTreeMap;
use std::str::FromStr;
use tracing::instrument;
use trustify_common::{cpe::Cpe, db::chunk::EntityChunkedIter};
use trustify_entity::{cpe_status, status::Status, version_range};
use uuid::Uuid;

/// Input data for creating a CPE status entry
#[derive(Clone, Debug)]
pub struct CpeStatusEntry {
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    /// The vendor/product identity CPE. Its version component does not need
    /// to be pre-normalized to ANY -- [`CpeStatusEntry`] callers are expected
    /// to pass whatever CPE they have; normalization happens upstream in the
    /// CVE loader via [`Cpe::with_any_version`].
    pub cpe: Cpe,
    pub status: String,
    pub version_info: VersionInfo,
    pub context_cpe: Option<Cpe>,
}

/// Creator for batch insertion of CPE statuses.
///
/// Mirrors [`crate::graph::purl::status_creator::PurlStatusCreator`], keyed
/// by `cpe_id` instead of `base_purl_id`.
#[derive(Default)]
pub struct CpeStatusCreator {
    entries: Vec<CpeStatusEntry>,
}

impl CpeStatusCreator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a CPE status entry to be created
    pub fn add(&mut self, entry: CpeStatusEntry) {
        self.entries.push(entry);
    }

    /// Create all collected CPE statuses in batches
    #[instrument(skip_all, fields(num = self.entries.len()), err(level=tracing::Level::INFO))]
    pub async fn create<C>(self, connection: &C) -> Result<(), Error>
    where
        C: ConnectionTrait,
    {
        if self.entries.is_empty() {
            return Ok(());
        }

        // Deduplicate and build ActiveModels
        let mut version_ranges = BTreeMap::new();
        let mut cpe_statuses = BTreeMap::new();

        for entry in self.entries {
            let status = Status::from_str(&entry.status)
                .map_err(|_| Error::InvalidStatus(entry.status.clone()))?;

            let cpe_status = CpeStatus {
                cpe: entry.cpe.clone(),
                context_cpe: entry.context_cpe.clone(),
                status,
                info: entry.version_info.clone(),
            };

            let uuid = cpe_status.uuid(entry.advisory_id, entry.vulnerability_id.clone());
            let cpe_id = entry.cpe.uuid();
            let version_range_id = entry.version_info.uuid();
            let context_cpe_id = entry.context_cpe.as_ref().map(|cpe| cpe.uuid());

            // Deduplicate version ranges
            version_ranges
                .entry(version_range_id)
                .or_insert_with(|| entry.version_info.clone().into_active_model());

            // Deduplicate cpe_statuses by UUID
            cpe_statuses
                .entry(uuid)
                .or_insert_with(|| cpe_status::ActiveModel {
                    id: Set(uuid),
                    advisory_id: Set(entry.advisory_id),
                    vulnerability_id: Set(entry.vulnerability_id.clone()),
                    status: Set(status),
                    cpe_id: Set(cpe_id),
                    version_range_id: Set(version_range_id),
                    context_cpe_id: Set(context_cpe_id),
                });
        }

        // Batch insert version ranges
        for batch in &version_ranges.into_values().chunked() {
            version_range::Entity::insert_many(batch)
                .on_conflict(OnConflict::new().do_nothing().to_owned())
                .do_nothing()
                .exec_without_returning(connection)
                .await?;
        }

        // Batch insert cpe_statuses
        for batch in &cpe_statuses.into_values().chunked() {
            cpe_status::Entity::insert_many(batch)
                .on_conflict(OnConflict::new().do_nothing().to_owned())
                .do_nothing()
                .exec_without_returning(connection)
                .await?;
        }

        Ok(())
    }
}
