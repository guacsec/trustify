pub mod creator;

use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use std::fmt::Debug;
use tracing::instrument;
use trustify_entity::organization;

use crate::graph::{Graph, error::Error};

#[derive(Clone, Debug)]
pub struct OrganizationInformation {
    pub cpe_key: Option<String>,
    pub website: Option<String>,
}

impl OrganizationInformation {
    pub fn has_data(&self) -> bool {
        self.cpe_key.is_some() || self.website.is_some()
    }
}

impl From<()> for OrganizationInformation {
    fn from(_: ()) -> Self {
        Self {
            cpe_key: None,
            website: None,
        }
    }
}

pub struct OrganizationContext<'g> {
    graph: &'g Graph,
    pub organization: organization::Model,
}

impl<'g> OrganizationContext<'g> {
    pub fn new(graph: &'g Graph, organization: organization::Model) -> Self {
        Self {
            graph,
            organization,
        }
    }
}

impl Graph {
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn get_organizations<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<Vec<OrganizationContext<'_>>, Error> {
        Ok(organization::Entity::find()
            .all(connection)
            .await?
            .into_iter()
            .map(|organization| OrganizationContext::new(self, organization))
            .collect())
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn get_organization_by_name<C: ConnectionTrait>(
        &self,
        name: impl Into<String> + Debug,
        connection: &C,
    ) -> Result<Option<OrganizationContext<'_>>, Error> {
        Ok(organization::Entity::find()
            .filter(organization::Column::Name.eq(name.into()))
            .one(connection)
            .await?
            .map(|organization| OrganizationContext::new(self, organization)))
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn ingest_organization<C: ConnectionTrait>(
        &self,
        name: impl Into<String> + Debug,
        information: impl Into<OrganizationInformation> + Debug,
        connection: &C,
    ) -> Result<OrganizationContext<'_>, Error> {
        let name = name.into();
        let information = information.into();

        if let Some(found) = self.get_organization_by_name(&name, connection).await? {
            if information.has_data() {
                let mut entity = organization::ActiveModel::from(found.organization);
                entity.website = Set(information.website);
                entity.cpe_key = Set(information.cpe_key);
                let model = entity.update(connection).await?;
                Ok(OrganizationContext::new(found.graph, model))
            } else {
                Ok(found)
            }
        } else {
            let entity = organization::ActiveModel {
                id: Default::default(),
                name: Set(name),
                cpe_key: Set(information.cpe_key),
                website: Set(information.website),
            };

            Ok(OrganizationContext::new(
                self,
                entity.insert(connection).await?,
            ))
        }
    }
}
