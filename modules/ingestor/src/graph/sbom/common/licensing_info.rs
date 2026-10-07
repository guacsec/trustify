use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::licensing_infos;
use uuid::Uuid;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LicensingInfo {
    pub sbom_id: Uuid,
    pub license_id: String,
    pub name: String,
    pub extracted_text: String,
    pub comment: Option<String>,
}

impl LicensingInfo {
    pub fn with_sbom_id(
        sbom_id: Uuid,
        name: String,
        license_id: String,
        extracted_text: String,
        comment: Option<String>,
    ) -> Self {
        Self {
            sbom_id,
            license_id,
            name,
            extracted_text,
            comment,
        }
    }
}

pub struct LicensingInfoCreator {
    license_refs: Vec<licensing_infos::ActiveModel>,
}

impl Default for LicensingInfoCreator {
    fn default() -> Self {
        Self::new()
    }
}

impl LicensingInfoCreator {
    pub fn new() -> Self {
        Self {
            license_refs: Default::default(),
        }
    }

    pub fn add(&mut self, info: &LicensingInfo) {
        self.license_refs.push(licensing_infos::ActiveModel {
            sbom_id: Set(info.sbom_id),
            name: Set(info.name.clone()),
            license_id: Set(info.license_id.clone()),
            extracted_text: Set(info.extracted_text.clone()),
            comment: if let Some(comment) = info.comment.clone() {
                Set(comment)
            } else {
                Set(String::default())
            },
        });
    }

    #[instrument(skip_all, fields(num = self.license_refs.len()), err)]
    pub async fn create<C>(self, db: &C) -> Result<(), DbErr>
    where
        C: ConnectionTrait,
    {
        for batch in &self.license_refs.into_iter().chunked() {
            licensing_infos::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        licensing_infos::Column::SbomId,
                        licensing_infos::Column::LicenseId,
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
