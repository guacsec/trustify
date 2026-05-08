use crate::{Error, sbom::service::SbomService};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, DatabaseBackend, EntityTrait,
    IntoActiveModel, QueryTrait,
};
use sea_query::Expr;
use trustify_common::id::{Id, TrySelectForId};
use trustify_entity::{labels::Labels, sbom};
use uuid::Uuid;

impl SbomService {
    /// Set the labels of an SBOM
    ///
    /// Returns `Ok(Some(()))` if a document was found and updated. If no document was found, it will
    /// return `Ok(None)`.
    pub async fn set_labels<C: ConnectionTrait>(
        &self,
        id: Id,
        labels: Labels,
        connection: &C,
    ) -> Result<Option<()>, Error> {
        let result = sbom::Entity::update_many()
            .try_filter(id)?
            .col_expr(sbom::Column::Labels, Expr::value(labels.validate()?))
            .exec(connection)
            .await?;

        Ok((result.rows_affected > 0).then_some(()))
    }

    /// Update the labels of an SBOM
    ///
    /// Finds the SBOM by id using `FOR UPDATE`, applies the mutator, and stores the result.
    /// The caller must provide a transaction for `FOR UPDATE` semantics.
    pub async fn update_labels<F>(
        &self,
        id: Id,
        mutator: F,
        connection: &impl ConnectionTrait,
    ) -> Result<Option<()>, Error>
    where
        F: FnOnce(Labels) -> Labels,
    {
        let mut query = sbom::Entity::find()
            .try_filter(id)?
            .build(DatabaseBackend::Postgres);

        query.sql.push_str(" FOR UPDATE");

        let Some(result) = sbom::Entity::find()
            .from_raw_sql(query)
            .one(connection)
            .await?
        else {
            return Ok(None);
        };

        let labels = result.labels.clone();
        let mut result = result.into_active_model();
        result.labels = Set(mutator(labels).validate()?);
        result.revision = Set(Uuid::now_v7());

        result.update(connection).await?;

        Ok(Some(()))
    }
}
