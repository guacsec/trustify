use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // HASH index on license(text) for exact-match lookups
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(License::Table)
                    .name(Indexes::IdxLicenseTextHash.to_string())
                    .col(License::Text)
                    .index_type(IndexType::Hash)
                    .to_owned(),
            )
            .await?;

        // B-tree composite index on sbom_package_license(license_id, sbom_id)
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(SbomPackageLicense::Table)
                    .name(Indexes::IdxSbomPkgLicLicenseSbom.to_string())
                    .col(SbomPackageLicense::LicenseId)
                    .col(SbomPackageLicense::SbomId)
                    .to_owned(),
            )
            .await?;

        // B-tree composite index on licensing_infos(sbom_id, license_id, name)
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(LicensingInfos::Table)
                    .name(Indexes::IdxLicensingInfosComposite.to_string())
                    .col(LicensingInfos::SbomId)
                    .col(LicensingInfos::LicenseId)
                    .col(LicensingInfos::Name)
                    .to_owned(),
            )
            .await?;

        // Replace function with optimized version (early exit for non-LicenseRef texts)
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002110_license_query_performance/up.sql"))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Restore original function from m0001180
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002110_license_query_performance/down.sql"))
            .await
            .map(|_| ())?;

        // Drop indexes in reverse order
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(LicensingInfos::Table)
                    .name(Indexes::IdxLicensingInfosComposite.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomPackageLicense::Table)
                    .name(Indexes::IdxSbomPkgLicLicenseSbom.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(License::Table)
                    .name(Indexes::IdxLicenseTextHash.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    IdxLicenseTextHash,
    IdxSbomPkgLicLicenseSbom,
    IdxLicensingInfosComposite,
}

#[derive(DeriveIden)]
enum SbomPackageLicense {
    Table,
    LicenseId,
    SbomId,
}

#[derive(DeriveIden)]
enum License {
    Table,
    Text,
}

#[derive(DeriveIden)]
enum LicensingInfos {
    Table,
    SbomId,
    LicenseId,
    Name,
}
