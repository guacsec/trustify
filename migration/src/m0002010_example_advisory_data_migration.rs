use crate::{
    advisory,
    data::{Advisory as AdvisoryDoc, MigrationTraitWithData, SchemaDataManager},
};
use sea_orm::sea_query::extension::postgres::Type;
use sea_orm_migration::prelude::*;
use strum::VariantNames;
use trustify_module_ingestor::{
    graph::cvss::ScoreCreator,
    service::advisory::{cve, osv},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .create_type(
                Type::create()
                    .as_enum(Severity::Table)
                    .values(Severity::VARIANTS.iter().skip(1).copied())
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(ScoreType::Table)
                    .values(ScoreType::VARIANTS.iter().skip(1).copied())
                    .to_owned(),
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
                            .uuid()
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
                    match advisory {
                        AdvisoryDoc::Cve(advisory) => {
                            let mut creator = ScoreCreator::new(model.id);
                            cve::extract_scores(&advisory, &mut creator);
                            creator.create(tx).await?;
                        }
                        AdvisoryDoc::Csaf(advisory) => {}
                        AdvisoryDoc::Osv(advisory) => {
                            let mut creator = ScoreCreator::new(model.id);
                            osv::extract_scores(&advisory, &mut creator);
                            creator.create(tx).await?;
                        }
                        _ => {
                            // we ignore others
                        }
                    }

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
            .drop_type(Type::drop().if_exists().name("severity").to_owned())
            .await?;

        manager
            .drop_type(Type::drop().if_exists().name("score_type").to_owned())
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

#[derive(DeriveIden, strum::VariantNames, strum::Display)]
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

#[derive(DeriveIden, strum::VariantNames, strum::Display)]
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
