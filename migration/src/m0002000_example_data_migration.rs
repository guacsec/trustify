use crate::{
    data::{DocumentProcessor, Sbom},
    sbom,
    sea_orm::{ActiveModelTrait, IntoActiveModel, Set},
};
use sea_orm_migration::prelude::*;
use trustify_module_storage::service::{dispatch::DispatchBackend, fs::FileSystemBackend};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // TODO: make this configurable
        let (storage, _tmp) = FileSystemBackend::for_test()
            .await
            .map_err(|err| DbErr::Migration(format!("failed to create storage backend: {err}")))?;
        let storage = DispatchBackend::Filesystem(storage);

        // process data

        manager
            .process(
                &storage,
                sbom!(async |sbom, model, tx| {
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
                }),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
