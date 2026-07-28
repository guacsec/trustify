/// Data migration that re-processes SPDX SBOMs to backfill the `suppliers`
/// column using the corrected `describing_packages()` logic.
use crate::data::{
    MigrationTraitWithData, SchemaDataManager,
    sbom::{Id, Sbom, SpdxSbom},
};
use sea_orm::{ActiveModelBehavior, ActiveModelTrait, DatabaseTransaction, Set};
use sea_orm_migration::prelude::*;
use trustify_module_ingestor::graph::sbom::spdx::suppliers;

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
