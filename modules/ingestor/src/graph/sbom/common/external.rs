use crate::graph::sbom::{ExternalReference, ReferenceSource};
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{
    sbom_external_node::{self, DiscriminatorType},
    sbom_node,
};
use uuid::Uuid;

/// A discriminator for external documents.
pub struct Discriminator {
    pub r#type: DiscriminatorType,
    pub value: String,
}

impl Discriminator {
    pub fn new(r#type: DiscriminatorType, value: String) -> Self {
        Self { r#type, value }
    }

    pub fn split(value: Option<Self>) -> (Option<DiscriminatorType>, Option<String>) {
        match value {
            Some(value) => (Some(value.r#type), Some(value.value)),
            None => (None, None),
        }
    }
}

// Creator of packages and relationships.
pub struct ExternalNodeCreator {
    sbom_id: Uuid,
    nodes: Vec<sbom_node::ActiveModel>,
    externals: Vec<sbom_external_node::ActiveModel>,
}

impl ExternalNodeCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,

            nodes: Default::default(),
            externals: Default::default(),
        }
    }

    pub fn add(&mut self, node_id: &str, external: ExternalReference) {
        let ExternalReference {
            external_type,
            external_document_id,
            external_node_id,
            discriminator,
        } = external;

        self.nodes.push(sbom_node::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id.into()),
            name: Set(external_node_id.clone()),
        });

        let (r#type, value) = Discriminator::split(discriminator);

        self.externals.push(sbom_external_node::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id.into()),
            external_doc_ref: Set(external_document_id),
            external_node_ref: Set(external_node_id),
            external_type: Set(external_type),
            discriminator_type: Set(r#type),
            discriminator_value: Set(value),
            target_sbom_id: Default::default(),
        })
    }

    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        for batch in &self.nodes.into_iter().chunked() {
            sbom_node::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([sbom_node::Column::SbomId, sbom_node::Column::NodeId])
                        .do_nothing()
                        .to_owned(),
                )
                .try_insert()
                .exec(db)
                .await?;
        }

        for batch in &self.externals.into_iter().chunked() {
            sbom_external_node::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_external_node::Column::SbomId,
                        sbom_external_node::Column::NodeId,
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

impl<'a> ReferenceSource<'a> for ExternalNodeCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes
            .iter()
            .filter_map(move |node| match &node.node_id {
                Set(node_id) => Some(node_id.as_str()),
                _ => None,
            })
    }
}
