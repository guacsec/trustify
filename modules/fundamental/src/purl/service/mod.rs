use crate::{
    Error,
    purl::model::{
        details::{
            base_purl::BasePurlDetails, purl::PurlDetails, versioned_purl::VersionedPurlDetails,
        },
        summary::{base_purl::BasePurlSummary, purl::PurlSummary, r#type::TypeSummary},
    },
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, RelationTrait, Select, prelude::Uuid,
};
use sea_query::{
    ColumnType, Condition, Expr, Func, JoinType, Order, SelectStatement, SimpleExpr, UnionType,
    extension::postgres::PgExpr,
};
use tracing::instrument;
use trustify_common::{
    db::{
        ExpandLicenseExpression,
        limiter::LimiterTrait,
        query::{Columns, Filtering, IntoColumns, Query, q},
    },
    model::{Paginated, PaginatedResults},
    purl::{Purl, PurlErr},
};
use trustify_entity::{
    base_purl, license,
    qualified_purl::{self, CanonicalPurl},
    sbom_package, sbom_package_license, sbom_package_purl_ref, versioned_purl,
};
use trustify_module_ingestor::common::Deprecation;

#[derive(Default)]
pub struct PurlService {}

const LICENSE: &str = "license";

impl PurlService {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn purl_types<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<Vec<TypeSummary>, Error> {
        #[derive(FromQueryResult)]
        struct Ecosystem {
            r#type: String,
        }

        let ecosystems: Vec<_> = base_purl::Entity::find()
            .select_only()
            .column(base_purl::Column::Type)
            .group_by(base_purl::Column::Type)
            .distinct()
            .order_by(base_purl::Column::Type, Order::Asc)
            .into_model::<Ecosystem>()
            .all(connection)
            .await?
            .into_iter()
            .map(|e| e.r#type)
            .collect();

        TypeSummary::from_names(&ecosystems, connection).await
    }

    pub async fn base_purls_by_type<C: ConnectionTrait>(
        &self,
        r#type: &str,
        query: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let limiter = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(r#type))
            .filtering(query)?
            .limiting(connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&limiter.fetch().await?).await?,
            total,
        })
    }

    pub async fn base_purl<C: ConnectionTrait>(
        &self,
        r#type: &str,
        namespace: Option<String>,
        name: &str,
        connection: &C,
    ) -> Result<Option<BasePurlDetails>, Error> {
        let mut query = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(r#type))
            .filter(base_purl::Column::Name.eq(name));

        if let Some(ns) = namespace {
            query = query.filter(base_purl::Column::Namespace.eq(ns));
        } else {
            query = query.filter(base_purl::Column::Namespace.is_null());
        }

        if let Some(package) = query.one(connection).await? {
            Ok(Some(
                BasePurlDetails::from_entity(&package, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn versioned_purl<C: ConnectionTrait>(
        &self,
        r#type: &str,
        namespace: Option<String>,
        name: &str,
        version: &str,
        connection: &C,
    ) -> Result<Option<VersionedPurlDetails>, Error> {
        let mut query = versioned_purl::Entity::find()
            .left_join(base_purl::Entity)
            .filter(base_purl::Column::Type.eq(r#type))
            .filter(base_purl::Column::Name.eq(name))
            .filter(versioned_purl::Column::Version.eq(version));

        if let Some(ns) = namespace {
            query = query.filter(base_purl::Column::Namespace.eq(ns));
        } else {
            query = query.filter(base_purl::Column::Namespace.is_null());
        }

        let package_version = query.one(connection).await?;

        if let Some(package_version) = package_version {
            Ok(Some(
                VersionedPurlDetails::from_entity(None, &package_version, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn base_purl_by_uuid<C: ConnectionTrait>(
        &self,
        base_purl_uuid: &Uuid,
        connection: &C,
    ) -> Result<Option<BasePurlDetails>, Error> {
        if let Some(package) = base_purl::Entity::find_by_id(*base_purl_uuid)
            .one(connection)
            .await?
        {
            Ok(Some(
                BasePurlDetails::from_entity(&package, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn base_purl_by_purl<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<Option<BasePurlDetails>, Error> {
        let mut query = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(&purl.ty))
            .filter(base_purl::Column::Name.eq(&purl.name));

        if let Some(ns) = &purl.namespace {
            query = query.filter(base_purl::Column::Namespace.eq(ns));
        } else {
            query = query.filter(base_purl::Column::Namespace.is_null());
        }

        if let Some(base_purl) = query.one(connection).await? {
            Ok(Some(
                BasePurlDetails::from_entity(&base_purl, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn versioned_purl_by_uuid<C: ConnectionTrait>(
        &self,
        purl_version_uuid: &Uuid,
        connection: &C,
    ) -> Result<Option<VersionedPurlDetails>, Error> {
        if let Some(package_version) = versioned_purl::Entity::find_by_id(*purl_version_uuid)
            .one(connection)
            .await?
        {
            Ok(Some(
                VersionedPurlDetails::from_entity(None, &package_version, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn versioned_purl_by_purl<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<Option<VersionedPurlDetails>, Error> {
        if let Some(version) = &purl.version {
            let mut query = versioned_purl::Entity::find()
                .left_join(base_purl::Entity)
                .filter(base_purl::Column::Type.eq(&purl.ty))
                .filter(base_purl::Column::Name.eq(&purl.name))
                .filter(versioned_purl::Column::Version.eq(version));

            if let Some(ns) = &purl.namespace {
                query = query.filter(base_purl::Column::Namespace.eq(ns));
            } else {
                query = query.filter(base_purl::Column::Namespace.is_null());
            }

            let package_version = query.one(connection).await?;

            if let Some(package_version) = package_version {
                Ok(Some(
                    VersionedPurlDetails::from_entity(None, &package_version, connection).await?,
                ))
            } else {
                Ok(None)
            }
        } else {
            Err(Error::Purl(PurlErr::MissingVersion(
                "A versioned pURL requires a version".to_string(),
            )))
        }
    }

    pub async fn purl_by_purl<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        deprecation: Deprecation,
        connection: &C,
    ) -> Result<Option<PurlDetails>, Error> {
        let canonical = CanonicalPurl::from(purl.clone());
        match qualified_purl::Entity::find()
            .filter(qualified_purl::Column::Purl.eq(canonical))
            .one(connection)
            .await?
        {
            Some(purl) => Ok(Some(
                PurlDetails::from_entity(None, None, &purl, deprecation, connection).await?,
            )),
            None => Ok(None),
        }
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn purl_by_uuid<C: ConnectionTrait>(
        &self,
        purl_uuid: &Uuid,
        deprecation: Deprecation,
        connection: &C,
    ) -> Result<Option<PurlDetails>, Error> {
        match qualified_purl::Entity::find_by_id(*purl_uuid)
            .one(connection)
            .await?
        {
            Some(pkg) => Ok(Some(
                PurlDetails::from_entity(None, None, &pkg, deprecation, connection).await?,
            )),
            None => Ok(None),
        }
    }

    pub async fn base_purls<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let limiter = base_purl::Entity::find().filtering(query)?.limiting(
            connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&limiter.fetch().await?).await?,
            total,
        })
    }

    #[instrument(skip(self, connection), err)]
    pub async fn purls<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<PurlSummary>, Error> {
        let mut select = qualified_purl::Entity::find().filtering_with(
            query.clone(),
            qualified_purl::Entity
                .columns()
                .json_keys("purl", &["ty", "namespace", "name", "version"])
                .json_keys("qualifiers", &["arch", "distro", "repository_url"])
                .translator(|f, op, v| match f {
                    "type" | "purl:type" => Some(format!("purl:ty{op}{v}")),
                    "purl" => Purl::translate(op, v),
                    // Add an empty condition (effectively TRUE) to the main SQL query
                    // since the real filtering by license happens in the license subqueries below
                    LICENSE => Some("".to_string()),
                    _ => None,
                }),
        )?;

        // since different fields conditions in input query are AND'd when translating them
        // into DB query, if the `license` field is in the input query then qualified_purl
        // that will match the input query criteria must be among the one satisfying
        // the license values requested in the input query itself.
        if let Some(license_query) = query
            .get_constraint_for_field(LICENSE)
            .map(|constraint| q(&format!("{constraint}")))
        {
            let mut select_packages_from_spdx =
                Self::build_spdx_license_query(license_query.clone())?;

            let select_packages_from_cyclonedx =
                Self::build_cyclonedx_license_query(license_query)?;

            // Filters PURLs by license using a two-phase approach:
            // 1. SPDX documents: Uses expand_license_expression() for LicenseRef resolution
            // 2. CycloneDX documents: Direct text matching on license field
            // The results are UNIONed and used to filter the main query.
            let select_packages_filtering_by_license = select_packages_from_spdx
                .union(UnionType::Distinct, select_packages_from_cyclonedx);

            select = select.filter(
                Condition::all().add(
                    qualified_purl::Column::Id
                        .in_subquery(select_packages_filtering_by_license.clone()),
                ),
            );
        }

        let limiter = select.limiting(connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: PurlSummary::from_entities(&limiter.fetch().await?),
            total,
        })
    }

    fn build_cyclonedx_license_query(license_query: Query) -> Result<SelectStatement, Error> {
        Ok(Self::create_license_filtering_base_query()
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

    fn build_spdx_license_query(license_query: Query) -> Result<SelectStatement, Error> {
        const EXPANDED_LICENSE: &str = "expanded_license";
        Ok(Self::create_license_filtering_base_query()
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

    fn create_license_filtering_base_query() -> Select<sbom_package_purl_ref::Entity> {
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

    #[instrument(skip(self, connection), err)]
    pub async fn gc_purls<C: ConnectionTrait>(&self, connection: &C) -> Result<u64, Error> {
        let res = connection
            .execute_unprepared(include_str!("gc_purls.sql"))
            .await?;

        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod test;
