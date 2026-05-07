use crate::{
    Error,
    common::{
        LicenseRefMapping,
        license_filtering::{LICENSE, license_text_coalesce},
    },
    license::model::{
        SpdxLicenseDetails, SpdxLicenseSummary,
        sbom_license::{
            ExtractedLicensingInfos, Purl, SbomNameId, SbomPackageLicense, SbomPackageLicenseBase,
        },
    },
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, FromQueryResult, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait, RelationTrait, Statement,
};
use sea_query::{
    Asterisk, Condition, Expr, Func, JoinType, PostgresQueryBuilder, SimpleExpr, UnionType,
};
use serde::{Deserialize, Serialize};
use spdx::License;
use tracing::instrument;
use trustify_common::{
    db::query::{Columns, Filtering, IntoColumns, Query, q},
    id::{Id, TrySelectForId},
    model::{PaginatedResults, Pagination},
};
use trustify_entity::{
    expanded_license, license, licensing_infos, qualified_purl, sbom, sbom_license_expanded,
    sbom_node, sbom_node_cpe_ref, sbom_node_purl_ref, sbom_package, sbom_package_license,
};
use utoipa::ToSchema;

pub mod license_export;

#[cfg(test)]
mod test;

pub struct LicenseService {}

pub struct LicenseExportResult {
    pub sbom_package_license: Vec<SbomPackageLicense>,
    pub extracted_licensing_infos: Vec<ExtractedLicensingInfos>,
    pub sbom_name_group_version: Option<SbomNameId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, FromQueryResult)]
pub struct LicenseText {
    #[sea_orm(from_alias = "text")]
    pub license: String,
}

impl Default for LicenseService {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseService {
    pub fn new() -> Self {
        Self {}
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn license_export<C: ConnectionTrait>(
        &self,
        id: Id,
        connection: &C,
    ) -> Result<LicenseExportResult, Error> {
        let name_version_group: Option<SbomNameId> = sbom::Entity::find()
            .try_filter(id.clone())?
            .join(JoinType::Join, sbom::Relation::SbomNode.def())
            .select_only()
            .column_as(sbom::Column::DocumentId, "sbom_id")
            .column_as(sbom_node::Column::Name, "sbom_name")
            .into_model::<SbomNameId>()
            .one(connection)
            .await?;

        let package_license: Vec<SbomPackageLicenseBase> = sbom::Entity::find()
            .try_filter(id.clone())?
            .join(JoinType::LeftJoin, sbom::Relation::Packages.def())
            .join(JoinType::InnerJoin, sbom_package::Relation::Node.def())
            .join(
                JoinType::LeftJoin,
                sbom_node::Relation::PackageLicense.def(),
            )
            .join(
                JoinType::InnerJoin,
                sbom_package_license::Relation::License.def(),
            )
            .select_only()
            .column_as(sbom::Column::SbomId, "sbom_id")
            .column_as(sbom_package::Column::NodeId, "node_id")
            .column_as(sbom_node::Column::Name, "name")
            .column_as(sbom_package::Column::Group, "group")
            .column_as(sbom_package::Column::Version, "version")
            .column_as(license::Column::Text, "license_text")
            .column_as(sbom_package_license::Column::LicenseType, "license_type")
            .into_model::<SbomPackageLicenseBase>()
            .all(connection)
            .await?;

        let mut sbom_package_list = Vec::new();
        for spl in package_license {
            let result_purl: Vec<Purl> = sbom_node_purl_ref::Entity::find()
                .join(JoinType::Join, sbom_node_purl_ref::Relation::Purl.def())
                .filter(
                    Condition::all()
                        .add(sbom_node_purl_ref::Column::NodeId.eq(spl.node_id.clone()))
                        .add(sbom_node_purl_ref::Column::SbomId.eq(spl.sbom_id)),
                )
                .select_only()
                .column_as(qualified_purl::Column::Purl, "purl")
                .into_model::<Purl>()
                .all(connection)
                .await?;
            let result_cpe: Vec<trustify_entity::cpe::Model> = sbom_node_cpe_ref::Entity::find()
                .join(JoinType::Join, sbom_node_cpe_ref::Relation::Cpe.def())
                .filter(
                    Condition::all()
                        .add(sbom_node_cpe_ref::Column::NodeId.eq(spl.node_id.clone()))
                        .add(sbom_node_cpe_ref::Column::SbomId.eq(spl.sbom_id)),
                )
                .select_only()
                .column_as(trustify_entity::cpe::Column::Id, "id")
                .column_as(trustify_entity::cpe::Column::Part, "part")
                .column_as(trustify_entity::cpe::Column::Vendor, "vendor")
                .column_as(trustify_entity::cpe::Column::Product, "product")
                .column_as(trustify_entity::cpe::Column::Version, "version")
                .column_as(trustify_entity::cpe::Column::Update, "update")
                .column_as(trustify_entity::cpe::Column::Edition, "edition")
                .column_as(trustify_entity::cpe::Column::Language, "language")
                .into_model::<trustify_entity::cpe::Model>()
                .all(connection)
                .await?;

            sbom_package_list.push(SbomPackageLicense {
                name: spl.name,
                group: spl.group,
                version: spl.version,
                purl: result_purl,
                cpe: result_cpe,
                license_text: spl.license_text,
                license_type: spl.license_type,
            });
        }
        let license_info_list: Vec<ExtractedLicensingInfos> = licensing_infos::Entity::find()
            .filter(
                Condition::all()
                    .add(licensing_infos::Column::SbomId.eq(id.try_as_uid().unwrap_or_default())),
            )
            .select_only()
            .column_as(licensing_infos::Column::LicenseId, "license_id")
            .column_as(licensing_infos::Column::Name, "name")
            .column_as(licensing_infos::Column::ExtractedText, "extracted_text")
            .column_as(licensing_infos::Column::Comment, "comment")
            .into_model::<ExtractedLicensingInfos>()
            .all(connection)
            .await?;

        Ok(LicenseExportResult {
            sbom_package_license: sbom_package_list,
            extracted_licensing_infos: license_info_list,
            sbom_name_group_version: name_version_group,
        })
    }

    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn list_spdx_licenses(
        &self,
        search: Query,
        paginated: impl Pagination,
    ) -> Result<PaginatedResults<SpdxLicenseSummary>, Error> {
        let all_matching = spdx::identifiers::LICENSES
            .iter()
            .filter(
                |License {
                     name: identifier,
                     full_name: name,
                     ..
                 }| {
                    search.q.is_empty()
                        || identifier.to_lowercase().contains(&search.q.to_lowercase())
                        || name.to_lowercase().contains(&search.q.to_lowercase())
                },
            )
            .collect::<Vec<_>>();

        let total = if paginated.total() {
            Some(all_matching.len() as u64)
        } else {
            None
        };

        if all_matching.len() < paginated.offset() as usize {
            return Ok(PaginatedResults {
                items: vec![],
                total,
            });
        }

        let matching = &all_matching[paginated.offset() as usize..];

        if paginated.limit() > 0 && matching.len() > paginated.limit() as usize {
            Ok(PaginatedResults {
                items: SpdxLicenseSummary::from_details(&matching[..paginated.limit() as usize]),
                total,
            })
        } else {
            Ok(PaginatedResults {
                items: SpdxLicenseSummary::from_details(matching),
                total,
            })
        }
    }

    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn get_spdx_license(&self, id: &str) -> Result<Option<SpdxLicenseDetails>, Error> {
        if let Some(License {
            name: spdx_identifier,
            full_name: spdx_name,
            ..
        }) = spdx::identifiers::LICENSES.iter().find(
            |License {
                 name: identifier, ..
             }| identifier.eq_ignore_ascii_case(id),
        ) && let Some(text) = spdx::text::LICENSE_TEXTS
            .iter()
            .find_map(|(identifier, text)| {
                if identifier.eq_ignore_ascii_case(spdx_identifier) {
                    Some(text.to_string())
                } else {
                    None
                }
            })
        {
            return Ok(Some(SpdxLicenseDetails {
                summary: SpdxLicenseSummary {
                    id: spdx_identifier.to_string(),
                    name: spdx_name.to_string(),
                },
                text,
            }));
        }
        Ok(None)
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn get_all_license_info<C: ConnectionTrait>(
        &self,
        id: Id,
        connection: &C,
    ) -> Result<Option<Vec<LicenseRefMapping>>, Error> {
        // check the SBOM exists searching by the provided Id
        let sbom = sbom::Entity::find()
            .join(JoinType::LeftJoin, sbom::Relation::SourceDocument.def())
            .try_filter(id)?
            .one(connection)
            .await?;

        match sbom {
            Some(sbom) => {
                // Build the COALESCE expression once: prefer pre-expanded text, fall back to raw
                // license text. Reused for both SELECT columns and ORDER BY to avoid repetition.
                let coalesce_expr = license_text_coalesce();

                let licenses = sbom_package_license::Entity::find()
                    .select_only()
                    .distinct()
                    .column_as(coalesce_expr.clone(), "license_name")
                    .column_as(coalesce_expr.clone(), "license_id")
                    .filter(sbom_package_license::Column::SbomId.eq(sbom.sbom_id))
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_license::Relation::SbomLicenseExpanded.def(),
                    )
                    .join(
                        JoinType::LeftJoin,
                        sbom_license_expanded::Relation::ExpandedLicense.def(),
                    )
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_license::Relation::License.def(),
                    )
                    .order_by_asc(coalesce_expr)
                    .into_model::<LicenseRefMapping>()
                    .all(connection)
                    .await?;
                Ok(Some(licenses))
            }
            None => Ok(None),
        }
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn licenses<C: ConnectionTrait>(
        &self,
        search: Query,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<LicenseText>, Error> {
        const LICENSE_TEXT: &str = "text";

        // Build query for SPDX licenses (from expanded_license dictionary)
        let mut spdx_query = expanded_license::Entity::find()
            .select_only()
            .distinct()
            .column_as(expanded_license::Column::ExpandedText, LICENSE_TEXT);

        // Build query for licenses not yet linked to any SBOM: includes both
        //   (a) pre-loaded SPDX dictionary entries with no SBOM connection yet, AND
        //   (b) licenses from older SBOMs ingested before license expansion was implemented.
        // Use NOT EXISTS instead of LEFT JOIN + IS NULL to find licenses without SBOMs.
        // On large tables, LEFT JOIN scans all rows while NOT EXISTS
        // uses a Nested Loop Anti Join with index-only scan.
        let exists_subquery = sea_query::Query::select()
            .expr(Expr::val(1))
            .from(sbom_license_expanded::Entity)
            .and_where(
                Expr::col((
                    sbom_license_expanded::Entity,
                    sbom_license_expanded::Column::LicenseId,
                ))
                .equals((license::Entity, license::Column::Id)),
            )
            .to_owned();

        let mut non_sbom_query = license::Entity::find()
            .select_only()
            .distinct()
            .column_as(license::Column::Text, LICENSE_TEXT)
            .filter(Expr::exists(exists_subquery).not());

        // Apply filtering to both queries (without sorting - that's applied to the UNION result)
        let filter_only = Query {
            q: search.q.clone(),
            sort: String::new(), // Don't sort individual queries before UNION
        };

        let spdx_columns =
            expanded_license::Entity
                .columns()
                .translator(|field, operator, value| match field {
                    LICENSE => Some(format!("expanded_text{operator}{value}")),
                    _ => None,
                });

        let non_sbom_columns = license::Entity
            .columns()
            .translator(|field, operator, value| match field {
                LICENSE => Some(format!("text{operator}{value}")),
                _ => None,
            });

        spdx_query = spdx_query.filtering_with(filter_only.clone(), spdx_columns)?;
        non_sbom_query = non_sbom_query.filtering_with(filter_only, non_sbom_columns)?;

        // Union the two queries
        QueryTrait::query(&mut spdx_query).union(UnionType::Distinct, non_sbom_query.into_query());
        // Add an expression for the license field and use it as the default sort
        let expr = SimpleExpr::Custom(LICENSE_TEXT.into());
        spdx_query = spdx_query
            .filtering_with(
                q("").sort(&search.sort),
                Columns::default().add_expr("license", expr.clone(), sea_orm::ColumnType::Text),
            )?
            .order_by_asc(expr);

        let mut union_query = spdx_query.into_query();

        // Count total results
        let count_query = sea_query::Query::select()
            .expr_as(Func::count(Expr::col(Asterisk)), "num_items")
            .from_subquery(union_query.clone(), "subquery")
            .to_owned();

        #[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema, FromQueryResult)]
        struct Count {
            num_items: i64,
        }

        let total = if paginated.total() {
            let (sql_count, values) = count_query.build(PostgresQueryBuilder);
            Some(
                Count::find_by_statement(Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    sql_count,
                    values,
                ))
                .one(connection)
                .await?
                .unwrap_or(Count { num_items: 0 })
                .num_items as u64,
            )
        } else {
            None
        };

        // Apply pagination
        union_query = union_query
            .offset(paginated.offset())
            .limit(paginated.limit())
            .to_owned();

        let (sql, values) = union_query.build(PostgresQueryBuilder);
        let items = LicenseText::find_by_statement(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            sql,
            values,
        ))
        .all(connection)
        .await?;

        Ok(PaginatedResults { total, items })
    }
}
