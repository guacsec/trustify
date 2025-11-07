use crate::graph::{
    advisory::{purl_status::PurlStatus, version::VersionInfo},
    error::Error,
};
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait, QueryFilter};
use sea_query::{Expr, OnConflict, PgFunc};
use std::collections::{BTreeMap, BTreeSet};
use tracing::instrument;
use trustify_common::{cpe::Cpe, db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity::{purl_status, status, version_range};
use uuid::Uuid;

/// Input data for creating a PURL status entry
#[derive(Clone, Debug)]
pub struct PurlStatusEntry {
    pub advisory_id: Uuid,
    pub vulnerability_id: String,
    pub purl: Purl,
    pub status: String,
    pub version_info: VersionInfo,
    pub context_cpe: Option<Cpe>,
}

/// Creator for batch insertion of PURL statuses
///
/// Follows the Creator pattern used by PurlCreator, CpeCreator, etc.
/// Collects PURL status entries and creates them in batches to avoid
/// N+1 query problems and race conditions.
#[derive(Default)]
pub struct PurlStatusCreator {
    entries: Vec<PurlStatusEntry>,
}

impl PurlStatusCreator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a PURL status entry to be created
    pub fn add(&mut self, entry: &PurlStatusEntry) {
        self.entries.push(entry.clone());
    }

    /// Create all collected PURL statuses in batches
    #[instrument(skip_all, fields(num = self.entries.len()), err(level=tracing::Level::INFO))]
    pub async fn create<C>(self, connection: &C) -> Result<(), Error>
    where
        C: ConnectionTrait,
    {
        if self.entries.is_empty() {
            return Ok(());
        }

        // 1. Batch lookup all unique status slugs
        let unique_statuses: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.status.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let status_models = status::Entity::find()
            .filter(Expr::col(status::Column::Slug).eq(PgFunc::any(unique_statuses)))
            .all(connection)
            .await?;

        let status_map: BTreeMap<String, Uuid> = status_models
            .into_iter()
            .map(|s| (s.slug.clone(), s.id))
            .collect();

        // 2. Deduplicate and build ActiveModels
        let mut version_ranges = BTreeMap::new();
        let mut purl_statuses = BTreeMap::new();

        for entry in self.entries {
            // Validate status exists
            let status_id = *status_map
                .get(&entry.status)
                .ok_or_else(|| Error::InvalidStatus(entry.status.clone()))?;

            // Create PurlStatus and use its uuid() method
            let purl_status = PurlStatus {
                cpe: entry.context_cpe.clone(),
                purl: entry.purl.clone(),
                status: status_id,
                info: entry.version_info.clone(),
            };

            let uuid = purl_status.uuid(entry.advisory_id, entry.vulnerability_id.clone());
            let base_purl_id = entry.purl.package_uuid();
            let version_range_id = entry.version_info.uuid();
            let context_cpe_id = entry.context_cpe.as_ref().map(|cpe| cpe.uuid());

            // Deduplicate version ranges
            version_ranges
                .entry(version_range_id)
                .or_insert_with(|| entry.version_info.clone().into_active_model());

            // Deduplicate purl_statuses by UUID
            purl_statuses
                .entry(uuid)
                .or_insert_with(|| purl_status::ActiveModel {
                    id: Set(uuid),
                    advisory_id: Set(entry.advisory_id),
                    vulnerability_id: Set(entry.vulnerability_id.clone()),
                    status_id: Set(status_id),
                    base_purl_id: Set(base_purl_id),
                    version_range_id: Set(version_range_id),
                    context_cpe_id: Set(context_cpe_id),
                });
        }

        // 3. Batch insert version ranges
        for batch in &version_ranges.into_values().chunked() {
            version_range::Entity::insert_many(batch)
                .on_conflict(OnConflict::new().do_nothing().to_owned())
                .do_nothing()
                .exec_without_returning(connection)
                .await?;
        }

        // 4. Batch insert purl_statuses
        for batch in &purl_statuses.into_values().chunked() {
            purl_status::Entity::insert_many(batch)
                .on_conflict(OnConflict::new().do_nothing().to_owned())
                .do_nothing()
                .exec_without_returning(connection)
                .await?;
        }

        Ok(())
    }
}
