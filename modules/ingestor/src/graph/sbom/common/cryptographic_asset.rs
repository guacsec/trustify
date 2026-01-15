use crate::graph::sbom::{Checksum, ReferenceSource, common::node::NodeCreator};
use sea_orm::{ConnectionTrait, DbErr};
use uuid::Uuid;

// Creator of files and relationships.
pub struct CryptographicAssetCreator {
    nodes: NodeCreator,
}

impl CryptographicAssetCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            nodes: NodeCreator::new(sbom_id),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity_files: usize) -> Self {
        Self {
            nodes: NodeCreator::with_capacity(sbom_id, capacity_files),
        }
    }

    pub fn add<I, C>(&mut self, node_id: String, name: String, checksums: I)
    where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.nodes.add(node_id.clone(), name, checksums);
    }

    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        self.nodes.create(db).await?;

        Ok(())
    }
}

impl<'a> ReferenceSource<'a> for CryptographicAssetCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes.references()
    }
}
