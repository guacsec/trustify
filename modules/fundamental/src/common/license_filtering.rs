use crate::Error;
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait, RelationTrait, Select,
};
use sea_query::{
    Alias, ColumnType, CommonTableExpression, Condition, Expr, Func, JoinType, PgFunc,
    SelectStatement, SimpleExpr, UnionType, WithClause, extension::postgres::PgExpr,
};
use trustify_common::db::{
    CaseLicenseTextSbomId, CustomFunc, ExpandLicenseExpression,
    query::{Columns, Filtering, IntoColumns, Query, q},
};
use trustify_entity::{
    license, licensing_infos, sbom_package, sbom_package_license, sbom_package_purl_ref,
};

pub const LICENSE: &str = "license";

/// Builds a CycloneDX license query using direct text matching on license fields
///
/// # Arguments
/// * `license_query` - The license query to filter by
/// * `base_query` - The base query to apply license filtering to
fn build_cyclonedx_license_query<E>(
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
fn build_spdx_license_query<E>(
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

/// Creates a base query for SBOM package license filtering (targeting packages within a specific SBOM)
pub fn create_sbom_package_license_filtering_base_query(
    sbom_id: sea_orm::prelude::Uuid,
) -> Select<sbom_package::Entity> {
    sbom_package::Entity::find()
        .filter(sbom_package::Column::SbomId.eq(sbom_id))
        .select_only()
        .column(sbom_package::Column::NodeId)
        .join(JoinType::Join, sbom_package::Relation::PackageLicense.def())
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

/// Returns the case_license_text_sbom_id() PLSQL function that conditionally applies expand_license_expression() for SPDX LicenseRefs
///
/// This function generates a SQL CASE expression that:
/// - Returns the expanded license expression when the license text contains 'LicenseRef-' (SPDX format)
/// - Returns the original license text for all other cases (including CycloneDX)
///
/// This allows unified handling of both SPDX and CycloneDX licenses in a single query.
pub fn get_case_license_text_sbom_id() -> SimpleExpr {
    SimpleExpr::FunctionCall(
        Func::cust(CaseLicenseTextSbomId)
            .arg(Expr::col((license::Entity, license::Column::Text)))
            .arg(Expr::col((
                sbom_package_license::Entity,
                sbom_package_license::Column::SbomId,
            ))),
    )
}

/// Builds a WithClause containing the three CTEs required for SPDX license filtering
///
/// This function creates the Common Table Expressions (CTEs) needed to handle SPDX license
/// expression expansion with LicenseRef mappings:
///
/// 1. `licensing_infos_mappings` - Aggregates license ID/name mappings per SBOM
/// 2. `unique_license_sbom` - Deduplicates license text by (license_text, sbom_id)
/// 3. `expanded` - Applies expand_license_expression_with_mappings() to resolve LicenseRefs
///
/// # Returns
/// A WithClause containing all three CTEs, ready to be attached to a query via `.with()`
///
/// # Example Usage
/// ```rust
/// use sea_orm::{EntityTrait, QueryTrait};
/// use trustify_entity::sbom;
/// use trustify_module_fundamental::common::license_filtering::build_license_filtering_with_clause;
///
/// let with_clause = build_license_filtering_with_clause();
/// let my_select_query = sbom::Entity::find();
/// let query = my_select_query.into_query().with(with_clause);
/// ```
pub fn build_license_filtering_with_clause() -> WithClause {
    // licensing_infos_mappings CTE
    let licensing_infos_mappings_query = licensing_infos::Entity::find()
        .select_only()
        .expr_as(
            PgFunc::array_agg(
                Expr::cust_with_exprs(
                    "ROW($1, $2)",
                    [
                        Expr::col(licensing_infos::Column::LicenseId).into(),
                        Expr::col(licensing_infos::Column::Name).into(),
                    ],
                )
                .cast_as("license_mapping"),
            ),
            "license_mapping",
        )
        .column(licensing_infos::Column::SbomId)
        .group_by(licensing_infos::Column::SbomId);

    let licensing_infos_mappings_cte = CommonTableExpression::new()
        .query(licensing_infos_mappings_query.into_query())
        .table_name(Alias::new("licensing_infos_mappings"))
        .to_owned();

    // unique_license_sbom CTE
    let unique_license_sbom_query = sbom_package_license::Entity::find()
        .distinct()
        .select_only()
        .column(license::Column::Text)
        .expr(Expr::col((
            sbom_package_license::Entity,
            sbom_package_license::Column::SbomId,
        )))
        .column_as(license::Column::Id, "license_id")
        .join(
            JoinType::Join,
            sbom_package_license::Relation::License.def(),
        );

    let unique_license_sbom_cte = CommonTableExpression::new()
        .query(unique_license_sbom_query.into_query())
        .table_name(Alias::new("unique_license_sbom"))
        .to_owned();

    // expanded CTE
    let expanded_query = sea_query::Query::select()
        .column((Alias::new("unique_license_sbom"), Alias::new("sbom_id")))
        .column((Alias::new("unique_license_sbom"), Alias::new("license_id")))
        .expr_as(
            Func::cust(CustomFunc::ExpandLicenseExpressionWithMappings).args([
                Expr::col((Alias::new("unique_license_sbom"), Alias::new("text"))).into(),
                Expr::col((
                    Alias::new("licensing_infos_mappings"),
                    Alias::new("license_mapping"),
                ))
                .into(),
            ]),
            Alias::new("expanded_text"),
        )
        .from(Alias::new("unique_license_sbom"))
        .join(
            JoinType::LeftJoin,
            Alias::new("licensing_infos_mappings"),
            Expr::col((Alias::new("unique_license_sbom"), Alias::new("sbom_id"))).equals((
                Alias::new("licensing_infos_mappings"),
                Alias::new("sbom_id"),
            )),
        )
        .to_owned();

    let expanded_cte = CommonTableExpression::new()
        .query::<SelectStatement>(expanded_query)
        .table_name(Alias::new("expanded"))
        .to_owned();

    // Combine all CTEs into a WithClause
    WithClause::new()
        .cte(licensing_infos_mappings_cte)
        .cte(unique_license_sbom_cte)
        .cte(expanded_cte)
        .to_owned()
}
