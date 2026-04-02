use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use tracing::instrument;
use trustify_common::{db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity::{sbom_node_cpe_ref, sbom_node_purl_ref};
use uuid::Uuid;

pub enum PackageReference {
    Purl(Purl),
    Cpe(Uuid),
}

pub struct ReferenceCreator {
    sbom_id: Uuid,
    pub(crate) purl_refs: Vec<sbom_node_purl_ref::ActiveModel>,
    pub(crate) cpe_refs: Vec<sbom_node_cpe_ref::ActiveModel>,
}

impl ReferenceCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            purl_refs: Vec::new(),
            cpe_refs: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity: usize) -> Self {
        Self {
            sbom_id,
            purl_refs: Vec::with_capacity(capacity),
            cpe_refs: Vec::new(), // most packages won't have a CPE, so we start with a low number
        }
    }

    pub fn add<'a>(&mut self, node_id: &str, refs: impl Iterator<Item = &'a PackageReference>) {
        let node_id_value = Set(node_id.to_string());
        for reference in refs {
            match reference {
                PackageReference::Cpe(cpe) => {
                    self.cpe_refs.push(sbom_node_cpe_ref::ActiveModel {
                        sbom_id: Set(self.sbom_id),
                        node_id: node_id_value.clone(),
                        cpe_id: Set(*cpe),
                    });
                }
                PackageReference::Purl(purl) => {
                    self.purl_refs.push(sbom_node_purl_ref::ActiveModel {
                        sbom_id: Set(self.sbom_id),
                        node_id: node_id_value.clone(),
                        qualified_purl_id: Set(purl.qualifier_uuid()),
                    });
                }
            }
        }
    }

    #[instrument(
        skip_all,
        fields(
            num_purl_refs=self.purl_refs.len(),
            num_cpe_refs=self.cpe_refs.len(),
        ),
        err(level=tracing::Level::INFO)
    )]
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        for batch in &self.purl_refs.into_iter().chunked() {
            sbom_node_purl_ref::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_node_purl_ref::Column::SbomId,
                        sbom_node_purl_ref::Column::NodeId,
                        sbom_node_purl_ref::Column::QualifiedPurlId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        for batch in &self.cpe_refs.into_iter().chunked() {
            sbom_node_cpe_ref::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_node_cpe_ref::Column::SbomId,
                        sbom_node_cpe_ref::Column::NodeId,
                        sbom_node_cpe_ref::Column::CpeId,
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
