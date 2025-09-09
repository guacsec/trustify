use crate::{
    data::{MigrationTraitWithData, Sbom, SchemaDataManager},
    sbom,
    sea_orm::{ActiveModelTrait, IntoActiveModel, Set},
};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .process(sbom!(async |sbom, model, tx| {
                let mut model = model.into_active_model();
                match sbom {
                    Sbom::CycloneDx(_sbom) => {
                        // TODO: just an example
                        model.authors = Set(vec![]);
                    }
                    Sbom::Spdx(_sbom) => {
                        // TODO: just an example
                        model.authors = Set(vec![]);
                    }
                }

                model.save(tx).await?;

                Ok(())
            }))
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaDataManager) -> Result<(), DbErr> {
        Ok(())
    }
}
