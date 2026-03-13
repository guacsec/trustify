use std::str::FromStr;

use crate::graph::sbom::{Checksum, ReferenceSource, common::node::NodeCreator};
use sea_orm::{ConnectionTrait, DbErr, EntityTrait, Set};
use sea_query::OnConflict;
use serde_cyclonedx::cyclonedx::v_1_6::Component;
use serde_json::{Map, Value};
use trustify_common::{db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity::sbom_ai;
use uuid::Uuid;

pub struct ModelCard {
    pub properties: Value,
}

impl From<&Component> for ModelCard {
    fn from(c: &Component) -> Self {
        let properties = Value::from(c.model_card.as_ref().and_then(|card| {
            card.properties.as_ref().map(|v| {
                v.iter()
                    .map(|p| (p.name.clone(), p.value.clone().into()))
                    .collect::<Map<_, _>>()
            })
        }));
        ModelCard { properties }
    }
}

pub struct MachineLearningModelCreator {
    sbom_id: Uuid,
    nodes: NodeCreator,
    models: Vec<sbom_ai::ActiveModel>,
}

impl MachineLearningModelCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::new(sbom_id),
            models: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity: usize) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::with_capacity(sbom_id, capacity),
            models: Vec::with_capacity(capacity),
        }
    }

    pub fn add<I, C>(
        &mut self,
        node_id: String,
        name: String,
        purl: Option<String>,
        checksums: I,
        model_card: ModelCard,
    ) where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.nodes.add(node_id.clone(), name, checksums);
        let uuid = purl
            .and_then(|s| Purl::from_str(&s).ok())
            .map(|p| p.qualifier_uuid());
        self.models.push(sbom_ai::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id),
            properties: Set(model_card.properties),
            qualified_purl_id: Set(uuid),
        });
    }

    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        self.nodes.create(db).await?;

        for batch in &self.models.into_iter().chunked() {
            sbom_ai::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([sbom_ai::Column::SbomId, sbom_ai::Column::NodeId])
                        .do_nothing()
                        .to_owned(),
                )
                .exec(db)
                .await?;
        }

        Ok(())
    }
}

impl<'a> ReferenceSource<'a> for MachineLearningModelCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes.references()
    }
}
