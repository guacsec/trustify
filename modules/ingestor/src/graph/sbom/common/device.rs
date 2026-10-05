use crate::graph::sbom::{Checksum, ReferenceSource, common::node::NodeCreator};
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{
    advisory_vulnerability_product_identifier::ProductIdentifierType, sbom_node_product_identifier,
};
use uuid::Uuid;

pub struct DeviceIdentifierCreator {
    sbom_id: Uuid,
    nodes: NodeCreator,
    identifiers: Vec<sbom_node_product_identifier::ActiveModel>,
}

impl DeviceIdentifierCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::new(sbom_id),
            identifiers: Vec::new(),
        }
    }

    pub fn add<I, C>(
        &mut self,
        node_id: String,
        name: String,
        checksums: I,
        identifiers: Vec<(ProductIdentifierType, String)>,
    ) where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.nodes.add(node_id.clone(), name, checksums);

        for (id_type, value) in identifiers {
            self.identifiers
                .push(sbom_node_product_identifier::ActiveModel {
                    sbom_id: Set(self.sbom_id),
                    node_id: Set(node_id.clone()),
                    identifier_type: Set(id_type),
                    value: Set(value),
                });
        }
    }

    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        self.nodes.create(db).await?;

        for batch in &self.identifiers.into_iter().chunked() {
            sbom_node_product_identifier::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_node_product_identifier::Column::SbomId,
                        sbom_node_product_identifier::Column::NodeId,
                        sbom_node_product_identifier::Column::IdentifierType,
                        sbom_node_product_identifier::Column::Value,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        Ok(())
    }
}

impl<'a> ReferenceSource<'a> for DeviceIdentifierCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes.references()
    }
}
