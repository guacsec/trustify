//! Support for *versioned* package.

use crate::graph::{
    error::Error,
    purl::{PackageContext, qualified_package::QualifiedPackageContext},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, FromQueryResult, QueryFilter,
    Statement,
};
use std::fmt::{Debug, Formatter};
use trustify_common::purl::Purl;
use trustify_entity::{
    self as entity,
    qualified_purl::{CanonicalPurl, Qualifiers},
    versioned_purl,
};

/// Live context for a package version.
#[derive(Clone)]
pub struct PackageVersionContext<'g> {
    pub package: PackageContext<'g>,
    pub package_version: entity::versioned_purl::Model,
}

impl Debug for PackageVersionContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version.fmt(f)
    }
}

impl<'g> PackageVersionContext<'g> {
    pub fn new(package: &PackageContext<'g>, package_version: versioned_purl::Model) -> Self {
        Self {
            package: package.clone(),
            package_version,
        }
    }

    pub async fn ingest_qualified_package<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<QualifiedPackageContext<'g>, Error> {
        let id = purl.qualifier_uuid();
        let cp: CanonicalPurl = purl.clone().into();
        let qualifiers_json = serde_json::to_value(Qualifiers(purl.qualifiers.clone()))
            .map_err(|e| Error::Any(anyhow::anyhow!("Failed to serialize qualifiers: {}", e)))?;
        let purl_json = serde_json::to_value(&cp)
            .map_err(|e| Error::Any(anyhow::anyhow!("Failed to serialize purl: {}", e)))?;

        // Raw SQL required: SeaORM's .exec() with ON CONFLICT DO NOTHING doesn't support RETURNING,
        // forcing a SELECT after every INSERT attempt (2 queries always). This approach uses
        // RETURNING to get the row in 1 query on success, only doing a SELECT on conflict.
        let sql_insert = r#"
            INSERT INTO qualified_purl (id, versioned_purl_id, qualifiers, purl)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING
            RETURNING *
        "#;

        let result =
            entity::qualified_purl::Model::find_by_statement(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                sql_insert,
                vec![
                    id.into(),
                    self.package_version.id.into(),
                    sea_query::Value::Json(Some(Box::new(qualifiers_json.clone()))),
                    sea_query::Value::Json(Some(Box::new(purl_json.clone()))),
                ],
            ))
            .one(connection)
            .await?;

        // If INSERT returned None (conflict occurred), fetch the existing row
        let result = if let Some(model) = result {
            model
        } else {
            // Use the deterministic id to fetch the exact row
            entity::qualified_purl::Entity::find_by_id(id)
                .one(connection)
                .await?
                .ok_or_else(|| {
                    Error::Any(anyhow::anyhow!(
                        "Failed to find qualified_purl after conflict"
                    ))
                })?
        };

        Ok(QualifiedPackageContext::new(self, result))
    }

    pub async fn get_qualified_package<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<Option<QualifiedPackageContext<'g>>, Error> {
        let found = entity::qualified_purl::Entity::find()
            .filter(entity::qualified_purl::Column::VersionedPurlId.eq(self.package_version.id))
            .filter(
                entity::qualified_purl::Column::Qualifiers.eq(Qualifiers(purl.qualifiers.clone())),
            )
            .one(connection)
            .await?;

        Ok(found.map(|model| QualifiedPackageContext::new(self, model)))
    }
}
