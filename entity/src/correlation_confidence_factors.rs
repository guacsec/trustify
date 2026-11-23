//! The confidence factors of evidence, stored once per distinct set and referenced by
//! [`super::correlation_evidence::Model::confidence_factors_id`].
use sea_orm::{DbBackend, FromQueryResult, Statement, entity::prelude::*};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "correlation_confidence_factors")]
pub struct Model {
    /// Derived from the value by the database function `correlation_detail_id`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Serialized `trustify_api::correlation::ConfidenceFactor`s, empty for evidence extracted
    /// before they were recorded.
    #[sea_orm(column_type = "JsonBinary")]
    pub value: serde_json::Value,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Store a set of confidence factors, unless it's stored already, returning its ID.
pub async fn store<C: ConnectionTrait>(
    connection: &C,
    value: serde_json::Value,
) -> Result<Uuid, DbErr> {
    #[derive(FromQueryResult)]
    struct Stored {
        id: Uuid,
    }
    Stored::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "WITH stored AS (INSERT INTO correlation_confidence_factors (id, value) VALUES (correlation_detail_id($1), $1) ON CONFLICT (id) DO NOTHING) SELECT correlation_detail_id($1) AS id",
        [value.into()],
    ))
    .one(connection)
    .await?
    .map(|stored| stored.id)
    .ok_or_else(|| DbErr::RecordNotInserted)
}
