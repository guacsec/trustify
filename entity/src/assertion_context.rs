use sea_orm::entity::prelude::*;

/// The product an advisory assertion is stated in, e.g. the platform of a CSAF relationship
/// ("golang as a default component of Red Hat Storage 3"). Shared across advisories.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "assertion_context")]
pub struct Model {
    /// Deterministic, from the category and the identifiers (or the name, without identifiers).
    #[sea_orm(primary_key)]
    pub id: Uuid,
    /// How the subject of the assertion relates to the context, if stated.
    pub category: Option<AssertionContextCategory>,
    /// The name of the product, e.g. "Red Hat Storage 3".
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::assertion_context_identifier::Entity")]
    Identifier,
}

impl Related<super::assertion_context_identifier::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Identifier.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// How the subject of an assertion relates to its context (CSAF relationship categories).
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, EnumIter, DeriveActiveEnum)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "assertion_context_category"
)]
pub enum AssertionContextCategory {
    #[sea_orm(string_value = "default_component_of")]
    DefaultComponentOf,
    #[sea_orm(string_value = "external_component_of")]
    ExternalComponentOf,
    #[sea_orm(string_value = "installed_on")]
    InstalledOn,
    #[sea_orm(string_value = "installed_with")]
    InstalledWith,
    #[sea_orm(string_value = "optional_component_of")]
    OptionalComponentOf,
}
