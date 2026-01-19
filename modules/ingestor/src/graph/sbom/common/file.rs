use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::sbom_file;
use uuid::Uuid;

// Creator of files and relationships.
pub struct FileCreator {
    sbom_id: Uuid,
    files: Vec<sbom_file::ActiveModel>,
}

impl FileCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            files: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity: usize) -> Self {
        Self {
            sbom_id,
            files: Vec::with_capacity(capacity),
        }
    }

    pub fn add(&mut self, node_id: String) {
        self.files.push(sbom_file::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id),
        });
    }

    #[instrument(skip_all, fields(num=self.files.len()), err(level=tracing::Level::INFO))]
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
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
