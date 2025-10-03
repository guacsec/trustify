use crate::{
    Error,
    common::{LicenseRefMapping, license_filtering, license_filtering::LICENSE},
    license::model::{
        SpdxLicenseDetails, SpdxLicenseSummary,
        sbom_license::{
            ExtractedLicensingInfos, Purl, SbomNameId, SbomPackageLicense, SbomPackageLicenseBase,
        },
    },
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, QueryFilter, QuerySelect,
    QueryTrait, RelationTrait, Statement,
};
use sea_query::{
    Alias, ColumnType, Condition, Expr, JoinType, Order::Asc, PostgresQueryBuilder, query,
};
use serde::{Deserialize, Serialize};
use trustify_common::{
    db::{
        limiter::LimiterAsModelTrait,
        query::{Columns, Filtering, Query},
    },
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
        let case_license_text_sbom_id = license_filtering::get_case_license_text_sbom_id();
        let limiter = license::Entity::find()
            .distinct()
            .select_only()
            .column_as(case_license_text_sbom_id.clone(), LICENSE)
            .left_join(sbom_package_license::Entity)
            .filtering_with(
                search,
                Columns::default().add_expr(LICENSE, case_license_text_sbom_id, ColumnType::Text),
            )?
            .limiting_as::<LicenseText>(connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let items = limiter.fetch().await?;
        Ok(PaginatedResults { total, items })
    }
}
