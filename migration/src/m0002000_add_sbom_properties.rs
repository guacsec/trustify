use crate::data::{MigrationTraitWithData, SchemaDataManager, sbom::Sbom as SbomDoc};
use sea_orm::{ActiveModelBehavior, ActiveModelTrait, DatabaseTransaction, Set};
use sea_orm_migration::prelude::*;
use trustify_common::advisory::cyclonedx::extract_properties_json;

#[derive(DeriveMigrationName)]
pub struct Migration;

mod legacy {
    use sea_orm::entity::prelude::*;
    use sea_orm::sqlx::types::time::OffsetDateTime;
    use trustify_entity::labels::Labels;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "sbom")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub sbom_id: Uuid,
        pub node_id: String,

        pub document_id: Option<String>,

        pub published: Option<OffsetDateTime>,
        pub authors: Vec<String>,
        pub suppliers: Vec<String>,
        pub data_licenses: Vec<String>,

        pub source_document_id: Uuid,

        pub labels: Labels,

        /// properties from the SBOM document
        pub properties: serde_json::Value,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Sbom::Properties)
                            .json()
                            .default(serde_json::Value::Null)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(ColumnDef::new(Sbom::Properties).not_null().to_owned())
                    .to_owned(),
            )
            .await?;

        manager
            .process(
                self,
                async |sbom: SbomDoc, id: crate::data::sbom::Id, tx: &DatabaseTransaction| {
                    let mut model = legacy::ActiveModel::new();
                    model.sbom_id = Set(id.sbom);
                    match sbom {
                        SbomDoc::CycloneDx(sbom) => {
                            model.properties = Set(extract_properties_json(&sbom));
                        }
                        SbomDoc::Spdx(_sbom) => {
                            model.properties = Set(serde_json::Value::Object(Default::default()));
                        }
                        SbomDoc::Other(_) => {
                            // we ignore others
                        }
                    }

                    model.save(tx).await?;

                    Ok(())
                },
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .drop_column(Sbom::Properties)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    Properties,
}
