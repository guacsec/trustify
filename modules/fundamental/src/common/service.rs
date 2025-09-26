use crate::{Error, common::LicenseRefMapping, source_document::model::SourceDocument};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, FromQueryResult, PaginatorTrait,
    QueryFilter, QuerySelect, QueryTrait, RelationTrait, Select, Statement,
};
use sea_query::{
    ColumnType, Condition, Expr, Func, JoinType, SelectStatement, SimpleExpr, UnionType,
    extension::postgres::PgExpr,
};
use spdx_expression;
use std::{collections::BTreeMap, future::Future};
use trustify_common::db::{
    ExpandLicenseExpression,
    query::{Columns, Filtering, IntoColumns, Query, q},
};
use trustify_entity::{license, sbom_package, sbom_package_license, sbom_package_purl_ref};
use trustify_module_storage::service::{StorageBackend, StorageKey, dispatch::DispatchBackend};

pub const LICENSE: &str = "license";

/// Builds a CycloneDX license query using direct text matching on license fields
///
/// # Arguments
/// * `license_query` - The license query to filter by
/// * `base_query` - The base query to apply license filtering to
pub fn build_cyclonedx_license_query<E>(
    license_query: Query,
    base_query: Select<E>,
) -> Result<SelectStatement, Error>
where
    E: EntityTrait,
{
    Ok(base_query
        .filtering_with(
            license_query,
            license::Entity
                .columns()
                .translator(|field, operator, value| match field {
                    LICENSE => Some(format!("text{operator}{value}")),
                    _ => None,
                }),
        )?
        .into_query())
}

/// Builds an SPDX license query using expand_license_expression() for LicenseRef resolution
///
/// # Arguments
/// * `license_query` - The license query to filter by
/// * `base_query` - The base query to apply license filtering to
pub fn build_spdx_license_query<E>(
    license_query: Query,
    base_query: Select<E>,
) -> Result<SelectStatement, Error>
where
    E: EntityTrait,
{
    const EXPANDED_LICENSE: &str = "expanded_license";
    Ok(base_query
        .filtering_with(
            license_query,
            Columns::default()
                .add_expr(
                    EXPANDED_LICENSE,
                    SimpleExpr::FunctionCall(
                        Func::cust(ExpandLicenseExpression)
                            .arg(Expr::col(license::Column::Text))
                            .arg(Expr::col((
                                sbom_package_license::Entity,
                                sbom_package_license::Column::SbomId,
                            ))),
                    ),
                    ColumnType::Text,
                )
                .translator(|field, operator, value| match field {
                    LICENSE => Some(format!("{EXPANDED_LICENSE}{operator}{value}")),
                    _ => None,
                }),
        )?
        .filter(Expr::col(license::Column::Text).ilike("%LicenseRef-%"))
        .into_query())
}

/// Creates a base query for PURL license filtering (targeting qualified_purl_id)
pub fn create_purl_license_filtering_base_query() -> Select<sbom_package_purl_ref::Entity> {
    sbom_package_purl_ref::Entity::find()
        .select_only()
        .column(sbom_package_purl_ref::Column::QualifiedPurlId)
        .join(
            JoinType::Join,
            sbom_package_purl_ref::Relation::Package.def(),
        )
        .join(JoinType::Join, sbom_package::Relation::PackageLicense.def())
        .join(
            JoinType::Join,
            sbom_package_license::Relation::License.def(),
        )
}

/// Creates a base query for SBOM license filtering (targeting sbom_id)
pub fn create_sbom_license_filtering_base_query() -> Select<sbom_package_license::Entity> {
    sbom_package_license::Entity::find()
        .select_only()
        .column(sbom_package_license::Column::SbomId)
        .join(
            JoinType::Join,
            sbom_package_license::Relation::License.def(),
        )
}

/// Applies license filtering to a query using a two-phase SPDX/CycloneDX approach
///
/// This function encapsulates the complete license filtering pattern used by both
/// PURL and SBOM services, eliminating code duplication.
///
/// # Arguments
/// * `main_query` - The main query to apply license filtering to
/// * `search_query` - The full search query that may contain license constraints
/// * `base_query_fn` - Function that creates the base query for license filtering
/// * `target_column` - The column to use in the subquery (e.g., qualified_purl::Column::Id or sbom::Column::SbomId)
///
/// # Returns
/// The modified main query with license filtering applied (if license constraints exist)
pub fn apply_license_filtering<E, BE, F, C>(
    main_query: Select<E>,
    search_query: &Query,
    base_query_fn: F,
    target_column: C,
) -> Result<Select<E>, Error>
where
    E: EntityTrait,
    BE: EntityTrait,
    F: Fn() -> Select<BE>,
    C: ColumnTrait,
{
    // since different fields conditions in input query are AND'd when translating them
    // into DB query, if the `license` field is in the input query then qualified_purl
    // that will match the input query criteria must be among the one satisfying
    // the license values requested in the input query itself.
    if let Some(license_query) = search_query
        .get_constraint_for_field(LICENSE)
        .map(|constraint| q(&format!("{constraint}")))
    {
        let license_filtering_base_query = base_query_fn();
        let mut select_from_spdx =
            build_spdx_license_query(license_query.clone(), license_filtering_base_query.clone())?;
        let select_from_cyclonedx =
            build_cyclonedx_license_query(license_query, license_filtering_base_query)?;

        // Filters using a two-phase approach:
        // 1. SPDX documents: Uses expand_license_expression() for LicenseRef resolution
        // 2. CycloneDX documents: Direct text matching on license field
        // The results are UNIONed and used to filter the main query.
        let select_filtering_by_license =
            select_from_spdx.union(UnionType::Distinct, select_from_cyclonedx);

        Ok(main_query.filter(
            Condition::all().add(target_column.in_subquery(select_filtering_by_license.clone())),
        ))
    } else {
        // No license filtering needed, return the query unchanged
        Ok(main_query)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum DocumentType {
    Advisory,
    Sbom,
}

/// Fetch all unique key/value labels matching the `filter_text` for all the `r#type` entities, i.e. `DocumentType::Advisory` or `DocumentType::Sbom`
///
/// If limit=0 then all data will be fetched
pub async fn fetch_labels<C: ConnectionTrait>(
    r#type: DocumentType,
    filter_text: String,
    limit: u64,
    connection: &C,
) -> Result<Vec<serde_json::Value>, Error> {
    let sql = format!(
        r#"
SELECT DISTINCT ON (kv.key, kv.value)
    kv.key,
    CASE
        WHEN kv.value IS NULL OR kv.value = '' THEN NULL
        ELSE kv.value
    END AS value
FROM {table},
    LATERAL jsonb_each_text(labels) AS kv
WHERE
    CASE
        WHEN kv.value IS NULL THEN kv.key
        ELSE kv.key || '=' || kv.value
    END ILIKE $1 ESCAPE '\'
ORDER BY
    kv.key, kv.value
"#,
        table = match r#type {
            DocumentType::Advisory => "advisory",
            DocumentType::Sbom => "sbom",
        }
    );

    let statement = Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        [format!("%{}%", escape(filter_text)).into()],
    );

    let selector = serde_json::Value::find_by_statement(statement);
    let labels: Vec<serde_json::Value> = if limit == 0 {
        selector.all(connection).await?
    } else {
        selector.paginate(connection, limit).fetch().await?
    };

    Ok(labels)
}

fn escape(text: String) -> String {
    text.replace('%', "\\").replace('\\', "\\\\")
}

/// Delete the original raw json doc from storage. An appropriate
/// message is returned in the event of an error, but it's up to the
/// caller to either log the message or return failure to its caller.
pub async fn delete_doc(
    doc: Option<&SourceDocument>,
    storage: impl DocumentDelete,
) -> Result<(), Error> {
    match doc {
        Some(doc) => {
            let key = doc.try_into()?;
            storage.delete(key).await
        }
        None => Ok(()),
    }
}
pub trait DocumentDelete {
    fn delete(&self, key: StorageKey) -> impl Future<Output = Result<(), Error>>;
}
impl DocumentDelete for &DispatchBackend {
    async fn delete(&self, key: StorageKey) -> Result<(), Error> {
        (*self).delete(key).await.map_err(Error::Storage)
    }
}

/// Extract LicenseRef mappings from SPDX license expressions
///
/// This function parses SPDX license expressions and extracts LicenseRef mappings,
/// which are then added to the provided `licenses_ref_mapping` vector.
///
/// # Arguments
/// * `license_name` - The SPDX license expression to parse
/// * `licensing_infos` - A BTreeMap containing license ID to license name mappings
/// * `licenses_ref_mapping` - A mutable vector where LicenseRef mappings will be added
pub fn extract_license_ref_mappings(
    license_name: &str,
    licensing_infos: &BTreeMap<String, String>,
    licenses_ref_mapping: &mut Vec<LicenseRefMapping>,
) {
    if let Ok(parsed) = spdx_expression::SpdxExpression::parse(license_name) {
        parsed
            .licenses()
            .into_iter()
            .filter(|license| license.license_ref)
            .for_each(|license| {
                let license_id = license.to_string();
                let license_name = licensing_infos
                    .get(&license_id)
                    .cloned()
                    .unwrap_or_default();
                licenses_ref_mapping.push(LicenseRefMapping {
                    license_id,
                    license_name,
                });
            });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::anyhow;
    use test_log::test;
    use trustify_module_storage::service::StorageKey;

    #[test(tokio::test)]
    async fn delete_failure() -> Result<(), anyhow::Error> {
        // Setup mock that simulates a delete error
        struct FailingDelete {}
        impl DocumentDelete for FailingDelete {
            async fn delete(&self, _key: StorageKey) -> Result<(), Error> {
                Err(Error::Storage(anyhow!("Delete failed")))
            }
        }

        // Deleting no doc is fine, error or not
        let msg = delete_doc(None, FailingDelete {}).await;
        assert!(msg.is_ok());

        // Failing to delete an invalid doc from storage should log an error
        let doc = SourceDocument::default();
        match delete_doc(Some(&doc), FailingDelete {}).await {
            Ok(_) => panic!("expected error"),
            Err(e) => assert!(e.to_string().contains("Missing prefix")),
        };

        // Failing to delete a valid doc from storage should log a different error
        let doc = SourceDocument {
            sha256: String::from(
                "sha256:488c5d97daed3613746f0c246f4a3d1b26ea52ce43d6bdd33f4219f881a00c07",
            ),
            ..Default::default()
        };
        match delete_doc(Some(&doc), FailingDelete {}).await {
            Ok(_) => panic!("expected error"),
            Err(e) => assert!(e.to_string().contains("Delete failed")),
        };

        Ok(())
    }
}
