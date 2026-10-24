use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

/// SeaORM entity for PQC algorithm-to-NIST-replacement mappings.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "crypto_remediation")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub algorithm_name: String,
    pub algorithm_primitive: Option<String>,
    pub replacement_name: String,
    pub replacement_standard: Option<String>,
    pub replacement_primitive: Option<String>,
    pub updated_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
