use sea_orm::entity::prelude::*;

/// An identifier of an assertion context, as stated by the advisory.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "assertion_context_identifier")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub context_id: Uuid,
    #[sea_orm(primary_key)]
    pub kind: ContextIdentifierKind,
    /// The canonical value, e.g. a CPE 2.3 string, a PURL, `sha256:…`, or a model number.
    #[sea_orm(primary_key)]
    pub value: String,
    /// The CPE, for kind [`ContextIdentifierKind::Cpe`].
    pub cpe_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::assertion_context::Entity",
        from = "Column::ContextId",
        to = "super::assertion_context::Column::Id",
        on_delete = "Cascade"
    )]
    Context,
    #[sea_orm(
        belongs_to = "super::cpe::Entity",
        from = "Column::CpeId",
        to = "super::cpe::Column::Id"
    )]
    Cpe,
}

impl Related<super::assertion_context::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Context.def()
    }
}

impl Related<super::cpe::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cpe.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// The kind of an identifier of an assertion context.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, EnumIter, DeriveActiveEnum)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "context_identifier_kind"
)]
pub enum ContextIdentifierKind {
    #[sea_orm(string_value = "cpe")]
    Cpe,
    #[sea_orm(string_value = "purl")]
    Purl,
    #[sea_orm(string_value = "model_number")]
    ModelNumber,
    #[sea_orm(string_value = "serial_number")]
    SerialNumber,
    #[sea_orm(string_value = "sku")]
    Sku,
    #[sea_orm(string_value = "digest")]
    Digest,
}
