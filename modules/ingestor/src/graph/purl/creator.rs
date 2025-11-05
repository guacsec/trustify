use crate::graph::error::Error;
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use sea_query::OnConflict;
use std::collections::{BTreeMap, HashSet};
use tracing::instrument;
use trustify_common::{db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity::{
    base_purl,
    qualified_purl::{self, Qualifiers},
    versioned_purl,
};
use uuid::Uuid;

/// Creator of PURLs.
#[derive(Default)]
pub struct PurlCreator {
    purls: HashSet<Purl>,
}

impl PurlCreator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, purl: Purl) {
        self.purls.insert(purl);
    }

    #[instrument(skip_all, fields(num = self.purls.len()), err(level=tracing::Level::INFO))]
    pub async fn create<C>(self, db: &C) -> Result<(), Error>
    where
        C: ConnectionTrait,
    {
        if self.purls.is_empty() {
            return Ok(());
        }

        // insert all packages

        let mut packages = BTreeMap::new();
        let mut versions = BTreeMap::new();
        let mut qualifieds = BTreeMap::new();

        for purl in self.purls {
            let cp = purl.clone().into();
            let (package, version, qualified) = purl.uuids();
            packages
                .entry(package)
                .or_insert_with(|| base_purl::ActiveModel {
                    id: Set(package),
                    r#type: Set(purl.ty),
                    namespace: Set(purl.namespace),
                    name: Set(purl.name),
                });

            versions
                .entry(version)
                .or_insert_with(|| versioned_purl::ActiveModel {
                    id: Set(version),
                    base_purl_id: Set(package),
                    version: Set(purl.version.unwrap_or_default()),
                });

            qualifieds
                .entry(qualified)
                .or_insert_with(|| qualified_purl::ActiveModel {
                    id: Set(qualified),
                    versioned_purl_id: Set(version),
                    qualifiers: Set(Qualifiers(purl.qualifiers)),
                    purl: Set(cp),
                });
        }

        // insert packages

        for batch in &packages.into_values().chunked() {
            base_purl::Entity::insert_many(batch)
                .on_conflict(OnConflict::new().do_nothing().to_owned())
                .do_nothing()
                .exec_without_returning(db)
                .await?;
        }

        // insert all package versions

        for batch in &versions.into_values().chunked() {
            versioned_purl::Entity::insert_many(batch)
                .on_conflict(OnConflict::new().do_nothing().to_owned())
                .do_nothing()
                .exec_without_returning(db)
                .await?;
        }

        // insert all qualified packages

        for batch in &qualifieds.into_values().chunked() {
            qualified_purl::Entity::insert_many(batch)
                .on_conflict(OnConflict::new().do_nothing().to_owned())
                .do_nothing()
                .exec_without_returning(db)
                .await?;
        }

        // return

        Ok(())
    }

    /// find PURLs matching that qualified PURL id
    pub fn find(&self, qualified_purl_id: Uuid) -> Option<String> {
        self.purls
            .iter()
            .find(|purl| purl.qualifier_uuid() == qualified_purl_id)
            .map(|purl| purl.to_string())
    }
}
