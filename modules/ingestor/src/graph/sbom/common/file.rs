use crate::graph::sbom::{Checksum, ReferenceSource, common::node::NodeCreator};
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::sbom_file;
use uuid::Uuid;

// Creator of files and relationships.
pub struct FileCreator {
    sbom_id: Uuid,
    nodes: NodeCreator,
    files: Vec<sbom_file::ActiveModel>,
}

impl FileCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::new(sbom_id),
            files: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity_files: usize) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::with_capacity(sbom_id, capacity_files),
            files: Vec::with_capacity(capacity_files),
        }
    }

    pub fn add<I, C>(&mut self, node_id: String, name: String, checksums: I)
    where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.nodes.add(node_id.clone(), name, checksums);

        self.files.push(sbom_file::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id),
        });
    }

    #[instrument(skip_all, fields(num=self.files.len()), err(level=tracing::Level::INFO))]
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        self.nodes.create(db).await?;

        for batch in &self.files.into_iter().chunked() {
            sbom_file::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([sbom_file::Column::SbomId, sbom_file::Column::NodeId])
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

impl<'a> ReferenceSource<'a> for FileCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes.references()
    }
}
