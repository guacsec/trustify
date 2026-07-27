/// Data migration that re-processes all SPDX SBOMs to backfill the `suppliers`
/// column using the corrected `describing_packages()` logic.
use crate::data::{MigrationTraitWithData, SchemaDataManager, sbom::Id, sbom::Sbom as SbomDoc};
use sea_orm::{ActiveModelBehavior, ActiveModelTrait, DatabaseTransaction, Set};
use sea_orm_migration::prelude::*;
use spdx_rs::models::{RelationshipType, SPDX};
use std::collections::HashSet;

#[derive(DeriveMigrationName)]
pub struct Migration;

mod legacy {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "sbom")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub sbom_id: Uuid,
        pub suppliers: Vec<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

fn describing_packages(sbom: &SPDX) -> HashSet<&str> {
    let mut packages = HashSet::new();

    for rel in &sbom.relationships {
        match rel.relationship_type {
            RelationshipType::Describes => {
                packages.insert(rel.related_spdx_element.as_str());
            }
            RelationshipType::DescribedBy => {
                packages.insert(rel.spdx_element_id.as_str());
            }
            _ => continue,
        }
    }

    packages.extend(
        sbom.document_creation_information
            .document_describes
            .iter()
            .map(|s| s.as_str()),
    );

    packages
}

fn suppliers(sbom: &SPDX) -> Vec<String> {
    let describing = describing_packages(sbom);

    let mut result = HashSet::new();
    for p in &sbom.package_information {
        if !describing.contains(p.package_spdx_identifier.as_str()) {
            continue;
        }
        if let Some(supplier) = &p.package_supplier {
            result.insert(supplier.clone());
        }
    }

    Vec::from_iter(result)
}

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .process(
                self,
                async |sbom: SbomDoc, id: Id, tx: &DatabaseTransaction| {
                    let SbomDoc::Spdx(spdx) = sbom else {
                        return Ok(());
                    };

                    let new_suppliers = suppliers(&spdx);

                    let mut model = legacy::ActiveModel::new();
                    model.sbom_id = Set(id.sbom);
                    model.suppliers = Set(new_suppliers);
                    model.save(tx).await?;

                    Ok(())
                },
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaDataManager) -> Result<(), DbErr> {
        Ok(())
    }
}
