use sea_orm::entity::prelude::*;

/// An option of the correlation engine, for the advisories of one publisher.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_option")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub key: CorrelationOptionKey,
    /// The publisher namespace of the advisories the option applies to, without a trailing `/`.
    pub publisher_namespace: String,
    /// The value, its type depends on the key.
    #[sea_orm(column_type = "JsonBinary")]
    pub value: serde_json::Value,
    /// Why the option is set, shown with the evidence it enables.
    pub reason: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The options of the correlation engine.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "correlation_option_key"
)]
pub enum CorrelationOptionKey {
    /// A versionless PURL (`pkg:rpm/redhat/golang`) states the status of all versions. Its value
    /// is a boolean.
    #[sea_orm(string_value = "versionless_purl")]
    VersionlessPurl,
    /// A `fixed` version means `first_fixed`: earlier versions of the stream are affected, later
    /// ones are fixed. Its value is a boolean.
    #[sea_orm(string_value = "fixed_is_first_fixed")]
    FixedIsFirstFixed,
}
