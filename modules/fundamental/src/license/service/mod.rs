use crate::{
    Error,
    common::{
        LicenseRefMapping, license_filtering,
        license_filtering::{LICENSE, build_license_filtering_with_clause},
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
    QuerySelect, QueryTrait, RelationTrait, Statement,
};
use sea_query::{
    Alias, ColumnType, Condition, Expr, JoinType, Order::Asc, PostgresQueryBuilder, UnionType,
    query,
};
use serde::{Deserialize, Serialize};
use trustify_common::{
    db::query::{Columns, Filtering, Query},
    id::{Id, TrySelectForId},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{
    license, licensing_infos, qualified_purl, sbom, sbom_node, sbom_package, sbom_package_cpe_ref,
    sbom_package_license, sbom_package_purl_ref,
};
use utoipa::ToSchema;

pub mod license_export;

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
                sbom_package::Relation::PackageLicense.def(),
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
            let result_purl: Vec<Purl> = sbom_package_purl_ref::Entity::find()
                .join(JoinType::Join, sbom_package_purl_ref::Relation::Purl.def())
                .filter(
                    Condition::all()
                        .add(sbom_package_purl_ref::Column::NodeId.eq(spl.node_id.clone()))
                        .add(sbom_package_purl_ref::Column::SbomId.eq(spl.sbom_id)),
                )
                .select_only()
                .column_as(qualified_purl::Column::Purl, "purl")
                .into_model::<Purl>()
                .all(connection)
                .await?;
            let result_cpe: Vec<trustify_entity::cpe::Model> = sbom_package_cpe_ref::Entity::find()
                .join(JoinType::Join, sbom_package_cpe_ref::Relation::Cpe.def())
                .filter(
                    Condition::all()
                        .add(sbom_package_cpe_ref::Column::NodeId.eq(spl.node_id.clone()))
                        .add(sbom_package_cpe_ref::Column::SbomId.eq(spl.sbom_id)),
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

    pub async fn list_spdx_licenses(
        &self,
        search: Query,
        paginated: Paginated,
    ) -> Result<PaginatedResults<SpdxLicenseSummary>, Error> {
        let all_matching = spdx::identifiers::LICENSES
            .iter()
            .filter(|(identifier, name, _)| {
                search.q.is_empty()
                    || identifier.to_lowercase().contains(&search.q.to_lowercase())
                    || name.to_lowercase().contains(&search.q.to_lowercase())
            })
            .collect::<Vec<_>>();

        if all_matching.len() < paginated.offset as usize {
            return Ok(PaginatedResults {
                items: vec![],
                total: all_matching.len() as u64,
            });
        }

        let matching = &all_matching[paginated.offset as usize..];

        if paginated.limit > 0 && matching.len() > paginated.limit as usize {
            Ok(PaginatedResults {
                items: SpdxLicenseSummary::from_details(&matching[..paginated.limit as usize]),
                total: all_matching.len() as u64,
            })
        } else {
            Ok(PaginatedResults {
                items: SpdxLicenseSummary::from_details(matching),
                total: all_matching.len() as u64,
            })
        }
    }

    pub async fn get_spdx_license(&self, id: &str) -> Result<Option<SpdxLicenseDetails>, Error> {
        if let Some((spdx_identifier, spdx_name, _)) = spdx::identifiers::LICENSES
            .iter()
            .find(|(identifier, _name, _flags)| identifier.eq_ignore_ascii_case(id))
            && let Some(text) = spdx::text::LICENSE_TEXTS
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

        const EXPANDED_LICENSE: &str = "expanded_license";
        const LICENSE_NAME: &str = "license_name";
        match sbom {
            Some(sbom) => {
                let expand_license_expression = sbom_package_license::Entity::find()
                    .select_only()
                    .distinct()
                    .column_as(
                        license_filtering::get_case_license_text_sbom_id(),
                        EXPANDED_LICENSE,
                    )
                    .join(
                        JoinType::Join,
                        sbom_package_license::Relation::License.def(),
                    )
                    .filter(sbom_package_license::Column::SbomId.eq(sbom.sbom_id));
                let (sql, values) = query::Query::select()
                    // reported twice to keep compatibility with LicenseRefMapping currently
                    // exposed in the involved endpoint.
                    .expr_as(Expr::col(Alias::new(EXPANDED_LICENSE)), LICENSE_NAME)
                    .expr_as(Expr::col(Alias::new(EXPANDED_LICENSE)), "license_id")
                    .from_subquery(expand_license_expression.into_query(), "expanded_licenses")
                    .order_by(LICENSE_NAME, Asc)
                    .build(PostgresQueryBuilder);
                let result: Vec<LicenseRefMapping> = LicenseRefMapping::find_by_statement(
                    Statement::from_sql_and_values(connection.get_database_backend(), sql, values),
                )
                .all(connection)
                .await?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    pub async fn licenses<C: ConnectionTrait>(
        &self,
        search: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<LicenseText>, Error> {
        // Build the CTEs for license filtering
        let with_clause = build_license_filtering_with_clause();

        const LICENSE_TEXT: &str = "text";
        const EXPANDED_LICENSE: &str = "expanded_text";
        // Let's build a Select<Entity> in order to, further down, use filtering_with function
        let mut base_query = sbom::Entity::find()
            .distinct()
            .select_only()
            .expr_as(Expr::col(EXPANDED_LICENSE), LICENSE_TEXT);
        // Basically the sorting and the querying can not be applied at the same time because
        // they work against different target columns that causes issue
        // when a full-text search query is executed because it would be applied also to
        // "sort" column in a phase when it won't be available yet in the query.
        let Query { ref q, ref sort } = search;
        // add query condition
        if !q.is_empty() {
            base_query = base_query.filtering_with(
                trustify_common::db::query::q(&q.to_string()),
                Columns::default()
                    .add_column(EXPANDED_LICENSE, ColumnType::Text)
                    .translator(|field, operator, value| match (field, operator) {
                        (LICENSE, _) => Some(format!("{EXPANDED_LICENSE}{operator}{value}")),
                        _ => None,
                    }),
            )?;
        }
        // add sorting condition
        if !sort.is_empty() {
            base_query = base_query.filtering_with(
                trustify_common::db::query::q("").sort(sort),
                Columns::default()
                    .add_column(LICENSE_TEXT, ColumnType::Text)
                    .translator(|field, operator, _value| match (field, operator) {
                        (LICENSE, "asc" | "desc") => Some(format!("{}:{operator}", LICENSE_TEXT)),
                        _ => None,
                    }),
            )?;
        }
        let mut statement = base_query.into_query().to_owned();
        let mut license_texts = statement.join(
            JoinType::Join,
            Alias::new("expanded"),
            Condition::all().add(
                Expr::col((sbom::Entity, sbom::Column::SbomId))
                    .equals((Alias::new("expanded"), Alias::new("sbom_id"))),
            ),
        );

        let default_licenses_with_no_sboms = license::Entity::find()
            .distinct()
            .select_only()
            .column(license::Column::Text)
            .join(JoinType::LeftJoin, license::Relation::PackageLicense.def())
            .filter(sbom_package_license::Column::SbomId.is_null())
            .filtering_with(
                search.clone(),
                Columns::default()
                    .add_column(license::Column::Text, ColumnType::Text)
                    .translator(|field, operator, value| match (field, operator) {
                        (LICENSE, "asc" | "desc") => Some(format!("{}:{operator}", LICENSE_TEXT)),
                        (LICENSE, _) => Some(format!("{}{operator}{value}", LICENSE_TEXT)),
                        _ => None,
                    }),
            )?
            .into_query()
            .to_owned();

        license_texts =
            license_texts.union(UnionType::Distinct, default_licenses_with_no_sboms.clone());

        let license_texts_count = sea_query::Query::select()
            .expr_as(Expr::cust("count(*)"), "num_items")
            .from_subquery(license_texts.clone(), "subquery")
            .to_owned();
        let (sql_count, values) = license_texts_count
            .clone()
            .with(with_clause.clone())
            .build(PostgresQueryBuilder);
        // the standard approach for counting can not be used because it doesn't work with CTE
        // since the generated query starts with:
        // SELECT COUNT(*) AS num_items FROM (SELECT licensing_infos_mappings"
        // which is not SQL syntactically correct
        // let selector_raw = LicenseText::find_by_statement(Statement::from_sql_and_values(
        //     DatabaseBackend::Postgres,
        //     sql_count.clone(),
        //     values.clone(),
        // ));
        // let total = selector_raw.count(connection).await?;
        let selector_raw = Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            sql_count.clone(),
            values.clone(),
        );

        #[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema, FromQueryResult)]
        struct Count {
            // It should be u64 but PostgreSQL doesn't support it
            // https://www.sea-ql.org/SeaORM/docs/1.1.x/generate-entity/column-types/#type-mappings
            num_items: i64,
        }
        let total = Count::find_by_statement(selector_raw)
            .one(connection)
            .await?
            .unwrap_or(Count { num_items: 0 })
            .num_items as u64;

        let select_paginated = license_texts
            .offset(paginated.offset)
            .limit(paginated.limit)
            .to_owned();
        let (sql, values) = select_paginated
            .with(with_clause)
            .build(PostgresQueryBuilder);
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
