use crate::graph::error::Error;
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use sea_query::OnConflict;
use std::collections::BTreeMap;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::organization;

/// Input data for creating an organization entry
#[derive(Clone, Debug, Default)]
pub struct OrganizationEntry {
    pub name: String,
    pub cpe_key: Option<String>,
    pub website: Option<String>,
}

/// Creator for batch insertion of organizations
///
/// Follows the Creator pattern used by PurlCreator, VulnerabilityCreator, etc.
/// Collects organization entries and creates them in batches to avoid
/// N+1 query problems and ensure consistent lock ordering.
#[derive(Default)]
pub struct OrganizationCreator {
    /// Organizations to insert, keyed by name for deduplication
    /// Uses BTreeMap to ensure consistent ordering by name
    entries: BTreeMap<String, OrganizationEntry>,
}

impl OrganizationCreator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an organization entry to be created
    pub fn add(
        &mut self,
        name: impl Into<String>,
        cpe_key: Option<String>,
        website: Option<String>,
    ) {
        let name = name.into();

        // Merge with existing entry if present
        self.entries
            .entry(name.clone())
            .and_modify(|existing| {
                // Update fields if new entry has data
                if cpe_key.is_some() {
                    existing.cpe_key = cpe_key.clone();
                }
                if website.is_some() {
                    existing.website = website.clone();
                }
            })
            .or_insert_with(|| OrganizationEntry {
                name,
                cpe_key,
                website,
            });
    }

    /// Create all collected organizations in batches
    ///
    /// Uses ON CONFLICT (name) DO NOTHING with database-generated random UUIDs.
    /// Requires unique constraint on name column (added via migration).
    #[instrument(skip_all, fields(num = self.entries.len()), err(level=tracing::Level::INFO))]
    pub async fn create<C>(self, connection: &C) -> Result<(), Error>
    where
        C: ConnectionTrait,
    {
        if self.entries.is_empty() {
            return Ok(());
        }

        // Convert entries to active models
        let mut models: Vec<_> = self
            .entries
            .into_values()
            .map(|entry| organization::ActiveModel {
                id: Default::default(), // Database generates random UUID
                name: Set(entry.name),
                cpe_key: Set(entry.cpe_key),
                website: Set(entry.website),
            })
            .collect();

        // Sort by name to ensure consistent lock acquisition order
        models.sort_by(|a, b| a.name.as_ref().cmp(b.name.as_ref()));

        // Batch insert with ON CONFLICT (name) DO NOTHING
        // The unique constraint on name prevents duplicates
        for batch in &models.chunked() {
            organization::Entity::insert_many(batch)
                .on_conflict(OnConflict::new().do_nothing().to_owned())
                .do_nothing()
                .exec_without_returning(connection)
                .await?;
        }

        Ok(())
    }
}
