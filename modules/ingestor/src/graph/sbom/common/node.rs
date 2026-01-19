use crate::graph::sbom::{Checksum, ReferenceSource};
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{sbom_node, sbom_node_checksum};
use uuid::Uuid;

use super::{
    CryptographicAssetCreator, FileCreator, MachineLearningModelCreator, NodeInfoParam,
    PackageCreator, PackageReference,
};

// Base node creator
pub struct NodeCreator {
    sbom_id: Uuid,
    nodes: Vec<sbom_node::ActiveModel>,
    checksums: Vec<sbom_node_checksum::ActiveModel>,

    packages: PackageCreator,
    files: FileCreator,
    models: MachineLearningModelCreator,
    crypto: CryptographicAssetCreator,
}

impl NodeCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: Vec::new(),
            checksums: Vec::new(),
            packages: PackageCreator::new(sbom_id),
            files: FileCreator::new(sbom_id),
            models: MachineLearningModelCreator::default(),
            crypto: CryptographicAssetCreator::default(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity: usize) -> Self {
        Self {
            sbom_id,
            nodes: Vec::with_capacity(capacity),
            checksums: Vec::with_capacity(capacity),
            packages: PackageCreator::with_capacity(sbom_id, capacity),
            files: FileCreator::with_capacity(sbom_id, capacity),
            models: MachineLearningModelCreator::default(),
            crypto: CryptographicAssetCreator::default(),
        }
    }

    pub fn add<I, C>(&mut self, node_id: String, name: String, checksums: I)
    where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        for checksum in checksums.into_iter() {
            let checksum = checksum.into();
            self.checksums.push(sbom_node_checksum::ActiveModel {
                sbom_id: Set(self.sbom_id),
                node_id: Set(node_id.clone()),
                r#type: Set(checksum.r#type.into()),
                value: Set(checksum.value),
            })
        }

        self.nodes.push(sbom_node::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id),
            name: Set(name),
        });
    }

    pub fn add_package<'a, I, C>(
        &mut self,
        info: NodeInfoParam,
        name: String,
        checksums: I,
        refs: impl Iterator<Item = &'a PackageReference>,
    ) where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.add(info.node_id.clone(), name, checksums);
        self.packages.add(info, refs);
    }

    pub fn add_file<I, C>(&mut self, node_id: String, name: String, checksums: I)
    where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.add(node_id.clone(), name, checksums);
        self.files.add(node_id);
    }

    pub fn add_model<I, C>(&mut self, node_id: String, name: String, checksums: I)
    where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.add(node_id.clone(), name, checksums);
        self.models.add(node_id);
    }

    pub fn add_crypto<I, C>(&mut self, node_id: String, name: String, checksums: I)
    where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.add(node_id.clone(), name, checksums);
        self.crypto.add(node_id);
    }

    #[instrument(skip_all, fields(num=self.nodes.len()), err(level=tracing::Level::INFO))]
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        for batch in &self.nodes.into_iter().chunked() {
            sbom_node::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([sbom_node::Column::SbomId, sbom_node::Column::NodeId])
                        .do_nothing()
                        .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        for batch in &self.checksums.into_iter().chunked() {
            sbom_node_checksum::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_node_checksum::Column::SbomId,
                        sbom_node_checksum::Column::NodeId,
                        sbom_node_checksum::Column::Type,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        self.packages.create(db).await?;
        self.files.create(db).await?;

        Ok(())
    }

    pub fn get_packages_mut(&mut self) -> &mut PackageCreator {
        &mut self.packages
    }
}

impl<'a> ReferenceSource<'a> for NodeCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes
            .iter()
            .filter_map(move |node| match &node.node_id {
                Set(node_id) => Some(node_id.as_str()),
                _ => None,
            })
    }
}
