use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomPackagePurlRef::Table)
                    .drop_foreign_key(Keys::SbomPackagePurlRefSbomIdNodeIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::SbomPackagePurlRefSbomIdNodeIdFkey.to_string())
                    .from(
                        SbomPackagePurlRef::Table,
                        (SbomPackagePurlRef::SbomId, SbomPackagePurlRef::NodeId),
                    )
                    .to(SbomNode::Table, (SbomNode::SbomId, SbomNode::NodeId))
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SbomPackageCpeRef::Table)
                    .drop_foreign_key(Keys::SbomPackageCpeRefSbomIdNodeIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::SbomPackageCpeRefSbomIdNodeIdFkey.to_string())
                    .from(
                        SbomPackageCpeRef::Table,
                        (SbomPackageCpeRef::SbomId, SbomPackageCpeRef::NodeId),
                    )
                    .to(SbomNode::Table, (SbomNode::SbomId, SbomNode::NodeId))
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomPackagePurlRef::Table)
                    .drop_foreign_key(Keys::SbomPackagePurlRefSbomIdNodeIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::SbomPackagePurlRefSbomIdNodeIdFkey.to_string())
                    .from(
                        SbomPackagePurlRef::Table,
                        (SbomPackagePurlRef::SbomId, SbomPackagePurlRef::NodeId),
                    )
                    .to(
                        SbomPackage::Table,
                        (SbomPackage::SbomId, SbomPackage::NodeId),
                    )
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SbomPackageCpeRef::Table)
                    .drop_foreign_key(Keys::SbomPackageCpeRefSbomIdNodeIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::SbomPackageCpeRefSbomIdNodeIdFkey.to_string())
                    .from(
                        SbomPackageCpeRef::Table,
                        (SbomPackageCpeRef::SbomId, SbomPackageCpeRef::NodeId),
                    )
                    .to(
                        SbomPackage::Table,
                        (SbomPackage::SbomId, SbomPackage::NodeId),
                    )
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SbomPackagePurlRef {
    Table,
    SbomId,
    NodeId,
}

#[derive(DeriveIden)]
enum SbomPackageCpeRef {
    Table,
    SbomId,
    NodeId,
}

#[derive(DeriveIden)]
enum SbomNode {
    Table,
    SbomId,
    NodeId,
}

#[derive(DeriveIden)]
enum SbomPackage {
    Table,
    SbomId,
    NodeId,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Keys {
    SbomPackagePurlRefSbomIdNodeIdFkey,
    SbomPackageCpeRefSbomIdNodeIdFkey,
}
