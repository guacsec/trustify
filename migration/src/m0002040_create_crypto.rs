use sea_orm_migration::prelude::*;
use sea_query::extension::postgres::Type;
use strum::VariantNames;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create the CryptoAssetType enum
        let builder = manager.get_connection().get_database_backend();
        let values = CryptoAssetType::VARIANTS.iter().skip(1).copied();
        let stmt = builder
            .build(
                Type::create()
                    .as_enum(CryptoAssetType::Table)
                    .values(values),
            )
            .to_string();
        manager.get_connection().execute_unprepared(&stmt).await?;

        // Create the SbomCrypto table
        manager
            .create_table(
                Table::create()
                    .table(SbomCrypto::Table)
                    .col(ColumnDef::new(SbomCrypto::SbomId).uuid().not_null())
                    .col(ColumnDef::new(SbomCrypto::NodeId).string().not_null())
                    .col(
                        ColumnDef::new(SbomCrypto::AssetType)
                            .custom(CryptoAssetType::Table)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomCrypto::Properties)
                            .json_binary()
                            .default(serde_json::Value::Null),
                    )
                    .col(ColumnDef::new(SbomCrypto::Oid).string().null())
                    .primary_key(
                        Index::create()
                            .col(SbomCrypto::SbomId)
                            .col(SbomCrypto::NodeId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(SbomCrypto::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop table
        manager
            .drop_table(Table::drop().table(SbomCrypto::Table).to_owned())
            .await?;
        // Drop enum
        manager
            .drop_type(
                Type::drop()
                    .if_exists()
                    .name(CryptoAssetType::Table)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum SbomCrypto {
    Table,
    SbomId,
    NodeId,
    AssetType,
    Properties,
    Oid,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    SbomId,
}

#[derive(DeriveIden, strum::VariantNames, strum::Display, Clone)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
#[allow(unused)]
pub enum CryptoAssetType {
    Table,
    Algorithm,
    Certificate,
    Protocol,
    #[sea_orm(iden = "related-crypto-material")]
    RelatedCryptoMaterial,
}
