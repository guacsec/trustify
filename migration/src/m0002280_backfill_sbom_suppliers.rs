/// Data migration that re-processes SPDX SBOMs to backfill the `suppliers`
/// column using the corrected `describing_packages()` logic.
use crate::data::{
    Document, MigrationTraitWithData, SchemaDataManager,
    sbom::{Id, Sbom},
};
use bytes::Bytes;
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    QueryFilter, QuerySelect, Set,
};
use sea_orm_migration::prelude::*;
use sea_query::{Expr, extension::postgres::PgExpr};
use trustify_entity::labels::Labels;
use trustify_module_ingestor::graph::sbom::spdx::suppliers;
use trustify_module_storage::service::StorageBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

mod legacy {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "sbom")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub sbom_id: Uuid,
        pub suppliers: Vec<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// SPDX-only Document wrapper that filters `all()` to SPDX-labeled SBOMs.
struct SpdxSbom(Sbom);

impl From<Bytes> for SpdxSbom {
    fn from(value: Bytes) -> Self {
        SpdxSbom(Sbom::from(value))
    }
}

impl Document for SpdxSbom {
    type Id = Id;

    async fn all<C: ConnectionTrait>(tx: &C) -> Result<Vec<Id>, DbErr> {
        use trustify_entity::sbom;

        sbom::Entity::find()
            .filter(Expr::col(sbom::Column::Labels).contains(Labels::new().add("type", "spdx")))
            .select_only()
            .column_as(sbom::Column::SourceDocumentId, "source")
            .column_as(sbom::Column::SbomId, "sbom")
            .into_model()
            .all(tx)
            .await
    }

    async fn source<S, C>(id: &Id, storage: &S, tx: &C) -> Result<Self, anyhow::Error>
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait,
    {
        Sbom::source(id, storage, tx).await.map(SpdxSbom)
    }
}

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .process(
                self,
                async |sbom: SpdxSbom, id: Id, tx: &DatabaseTransaction| {
                    let Sbom::Spdx(spdx) = sbom.0 else {
                        return Ok(());
                    };

                    let new_suppliers = suppliers(&spdx);

                    let mut model = legacy::ActiveModel::new();
                    model.sbom_id = Set(id.sbom);
                    model.suppliers = Set(new_suppliers);
                    model.save(tx).await?;

                    Ok(())
                },
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaDataManager) -> Result<(), DbErr> {
        Ok(())
    }
}
