use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // product_version.sbom_id — used in analysis graph loading:
        //   LEFT JOIN product_version ON sbom.sbom_id = product_version.sbom_id
        // Without this index, every SBOM graph load triggers a sequential scan
        // of the entire product_version table.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(ProductVersion::Table)
                    .name(Indexes::ProductVersionSbomIdIdx.to_string())
                    .col(ProductVersion::SbomId)
                    .to_owned(),
            )
            .await?;

        // product_version.product_id — used in analysis graph loading:
        //   LEFT JOIN product ON product_version.product_id = product.id
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(ProductVersion::Table)
                    .name(Indexes::ProductVersionProductIdIdx.to_string())
                    .col(ProductVersion::ProductId)
                    .to_owned(),
            )
            .await?;

        // package_relates_to_package (sbom_id, relationship) — used in CPE
        // context filter SQL and SBOM advisory queries:
        //   WHERE sbom_id = $1 AND relationship = 13
        // The existing PK (sbom_id, left_node_id, relationship, right_node_id)
        // has left_node_id between sbom_id and relationship, forcing a scan of
        // all left_node_id values per SBOM.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(PackageRelatesToPackage::Table)
                    .name(Indexes::PackageRelatesToPackageSbomRelIdx.to_string())
                    .col(PackageRelatesToPackage::SbomId)
                    .col(PackageRelatesToPackage::Relationship)
                    .to_owned(),
            )
            .await?;

        // purl_status.version_range_id — used in vulnerability analysis:
        //   INNER JOIN version_range ON purl_status.version_range_id = version_range.id
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(PurlStatus::Table)
                    .name(Indexes::PurlStatusVersionRangeIdIdx.to_string())
                    .col(PurlStatus::VersionRangeId)
                    .to_owned(),
            )
            .await?;

        // cpe (vendor, product, version) — used in the generalized CPE lookup
        // within product_advisory_info_sql():
        //   WHERE (vendor, product, version) IN (SELECT ...)
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(Cpe::Table)
                    .name(Indexes::CpeVendorProductVersionIdx.to_string())
                    .col(Cpe::Vendor)
                    .col(Cpe::Product)
                    .col(Cpe::Version)
                    .to_owned(),
            )
            .await?;

        // advisory.issuer_id — used in advisory listing/detail queries:
        //   LEFT JOIN organization ON advisory.issuer_id = organization.id
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisoryIssuerIdIdx.to_string())
                    .col(Advisory::IssuerId)
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
                    .table(Advisory::Table)
                    .name(Indexes::AdvisoryIssuerIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Cpe::Table)
                    .name(Indexes::CpeVendorProductVersionIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PurlStatus::Table)
                    .name(Indexes::PurlStatusVersionRangeIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PackageRelatesToPackage::Table)
                    .name(Indexes::PackageRelatesToPackageSbomRelIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(ProductVersion::Table)
                    .name(Indexes::ProductVersionProductIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(ProductVersion::Table)
                    .name(Indexes::ProductVersionSbomIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    ProductVersionSbomIdIdx,
    ProductVersionProductIdIdx,
    PackageRelatesToPackageSbomRelIdx,
    PurlStatusVersionRangeIdIdx,
    CpeVendorProductVersionIdx,
    AdvisoryIssuerIdIdx,
}

#[derive(DeriveIden)]
pub enum ProductVersion {
    Table,
    SbomId,
    ProductId,
}

#[derive(DeriveIden)]
pub enum PackageRelatesToPackage {
    Table,
    SbomId,
    Relationship,
}

#[derive(DeriveIden)]
pub enum PurlStatus {
    Table,
    VersionRangeId,
}

#[derive(DeriveIden)]
pub enum Cpe {
    Table,
    Vendor,
    Product,
    Version,
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    IssuerId,
}
