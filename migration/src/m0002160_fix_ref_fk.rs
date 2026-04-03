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
            .rename_table(
                Table::rename()
                    .table(SbomPackagePurlRef::Table, SbomNodePurlRef::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::SbomNodePurlRefSbomIdNodeIdFkey.to_string())
                    .from(
                        SbomNodePurlRef::Table,
                        (SbomNodePurlRef::SbomId, SbomNodePurlRef::NodeId),
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
            .rename_table(
                Table::rename()
                    .table(SbomPackageCpeRef::Table, SbomNodeCpeRef::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name(Keys::SbomNodeCpeRefSbomIdNodeIdFkey.to_string())
                    .from(
                        SbomNodeCpeRef::Table,
                        (SbomNodeCpeRef::SbomId, SbomNodeCpeRef::NodeId),
                    )
                    .to(SbomNode::Table, (SbomNode::SbomId, SbomNode::NodeId))
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002160_fix_ref_fk/up.sql"))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomNodePurlRef::Table)
                    .drop_foreign_key(Keys::SbomNodePurlRefSbomIdNodeIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(SbomNodePurlRef::Table, SbomPackagePurlRef::Table)
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
                    .table(SbomNodeCpeRef::Table)
                    .drop_foreign_key(Keys::SbomNodeCpeRefSbomIdNodeIdFkey)
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(SbomNodeCpeRef::Table, SbomPackageCpeRef::Table)
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

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002160_fix_ref_fk/down.sql"))
            .await
            .map(|_| ())?;

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
enum SbomNodePurlRef {
    Table,
    SbomId,
    NodeId,
}

#[derive(DeriveIden)]
enum SbomNodeCpeRef {
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
    SbomNodePurlRefSbomIdNodeIdFkey,
    SbomNodeCpeRefSbomIdNodeIdFkey,
}
