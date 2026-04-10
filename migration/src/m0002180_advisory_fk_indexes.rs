use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Index on advisory_vulnerability_score(advisory_id)
        //
        // Required for CASCADE deletes and ScoreCreator's wipe-and-replace DELETE
        // that runs on every advisory ingestion. Also used by UI CVSS score loading.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(AdvisoryVulnerabilityScore::Table)
                    .name(Indexes::IdxAdvVulnScoreAdvisoryId.to_string())
                    .col(AdvisoryVulnerabilityScore::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        // Index on purl_status(advisory_id)
        //
        // Required for CASCADE deletes on advisory deletion.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(PurlStatus::Table)
                    .name(Indexes::IdxPurlStatusAdvisoryId.to_string())
                    .col(PurlStatus::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        // Index on product_status(advisory_id)
        //
        // Required for CASCADE deletes on advisory deletion.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(ProductStatus::Table)
                    .name(Indexes::IdxProductStatusAdvisoryId.to_string())
                    .col(ProductStatus::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(ProductStatus::Table)
                    .name(Indexes::IdxProductStatusAdvisoryId.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PurlStatus::Table)
                    .name(Indexes::IdxPurlStatusAdvisoryId.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(AdvisoryVulnerabilityScore::Table)
                    .name(Indexes::IdxAdvVulnScoreAdvisoryId.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    IdxAdvVulnScoreAdvisoryId,
    IdxPurlStatusAdvisoryId,
    IdxProductStatusAdvisoryId,
}

#[derive(DeriveIden)]
enum AdvisoryVulnerabilityScore {
    Table,
    AdvisoryId,
}

#[derive(DeriveIden)]
enum PurlStatus {
    Table,
    AdvisoryId,
}

#[derive(DeriveIden)]
enum ProductStatus {
    Table,
    AdvisoryId,
}
