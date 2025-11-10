use crate::{
    advisory,
    data::{Advisory as AdvisoryDoc, MigrationTraitWithData, SchemaDataManager},
};
use sea_orm::sea_query::extension::postgres::*;
use sea_orm_migration::prelude::*;
use strum::VariantNames;
use trustify_common::db::create_enum_if_not_exists;
use trustify_module_ingestor::{
    graph::cvss::ScoreCreator,
    service::advisory::{csaf, cve, osv},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        create_enum_if_not_exists(
            manager,
            Severity::Table,
            Severity::VARIANTS.iter().skip(1).copied(),
        )
        .await?;

        create_enum_if_not_exists(
            manager,
            ScoreType::Table,
            ScoreType::VARIANTS.iter().skip(1).copied(),
        )
        .await?;

        manager
            .create_table(
                Table::create()
                    .table(AdvisoryVulnerabilityScore::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AdvisoryVulnerabilityScore::Id)
                            .uuid()
                            .not_null()
                            .primary_key()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(AdvisoryVulnerabilityScore::AdvisoryId)
                            .uuid()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(AdvisoryVulnerabilityScore::VulnerabilityId)
                            .string()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(AdvisoryVulnerabilityScore::Type)
                            .custom(ScoreType::Table)
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(AdvisoryVulnerabilityScore::Vector)
                            .string()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(AdvisoryVulnerabilityScore::Score)
                            .float()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(AdvisoryVulnerabilityScore::Severity)
                            .custom(Severity::Table)
                            .not_null()
                            .to_owned(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(AdvisoryVulnerabilityScore::AdvisoryId)
                            .from_col(AdvisoryVulnerabilityScore::VulnerabilityId)
                            .to(
                                AdvisoryVulnerability::Table,
                                (
                                    AdvisoryVulnerability::AdvisoryId,
                                    AdvisoryVulnerability::VulnerabilityId,
                                ),
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .process(
                self,
                advisory!(async |advisory, model, tx| {
                    let mut creator = ScoreCreator::new(model.id);
                    match advisory {
                        AdvisoryDoc::Cve(advisory) => {
                            cve::extract_scores(&advisory, &mut creator);
                        }
                        AdvisoryDoc::Csaf(advisory) => {
                            csaf::extract_scores(&advisory, &mut creator);
                        }
                        AdvisoryDoc::Osv(advisory) => {
                            osv::extract_scores(&advisory, &mut creator);
                        }
                        _ => {
                            // we ignore others
                        }
                    }

                    creator.create(tx).await?;

                    Ok(())
                }),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(AdvisoryVulnerabilityScore::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .drop_type(Type::drop().if_exists().name(Severity::Table).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().if_exists().name(ScoreType::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum AdvisoryVulnerability {
    Table,
    AdvisoryId,
    VulnerabilityId,
}

#[derive(DeriveIden)]
enum AdvisoryVulnerabilityScore {
    Table,
    Id,
    AdvisoryId,
    VulnerabilityId,
    Type,
    Vector,
    Score,
    Severity,
}

#[derive(DeriveIden, strum::VariantNames, strum::Display, Clone)]
#[allow(unused)]
enum ScoreType {
    Table,
    #[strum(to_string = "2.0")]
    V2_0,
    #[strum(to_string = "3.0")]
    V3_0,
    #[strum(to_string = "3.1")]
    V3_1,
    #[strum(to_string = "4.0")]
    V4_0,
}

#[derive(DeriveIden, strum::VariantNames, strum::Display, Clone)]
#[strum(serialize_all = "lowercase")]
#[allow(unused)]
enum Severity {
    Table,
    None,
    Low,
    Medium,
    High,
    Critical,
}
