use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{
    advisory_vulnerability_product_identifier::ProductIdentifierType, sbom_node_product_identifier,
};
use uuid::Uuid;

/// Creates the product identifiers (SKUs, model and serial numbers) of SBOM nodes. The nodes
/// themselves are created as packages.
pub struct DeviceIdentifierCreator {
    sbom_id: Uuid,
    identifiers: Vec<sbom_node_product_identifier::ActiveModel>,
}

impl DeviceIdentifierCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            identifiers: Vec::new(),
        }
    }

    pub fn add(&mut self, node_id: String, identifiers: Vec<(ProductIdentifierType, String)>) {
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
        for batch in self.identifiers.into_iter().chunked() {
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
                .try_insert()
                .exec(db)
                .await?;
        }

        Ok(())
    }
}
