use super::SbomService;
use crate::{
    Error,
    common::license_filtering::{LICENSE, license_text_coalesce},
    purl::model::summary::purl::PurlSummary,
    sbom::model::{
        ModelCatcher, SbomExternalPackageReference, SbomModel, SbomNodeReference, SbomPackage,
        SbomPackageRelation, SbomPackageSummary, SbomSummary, Which, details::SbomDetails,
    },
};
use futures_util::{StreamExt, TryStreamExt, stream};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, FromJsonQueryResult, FromQueryResult,
    IntoSimpleExpr, QueryFilter, QueryOrder, QueryResult, QuerySelect, QueryTrait, RelationTrait,
    Select, SelectColumns, Statement, StreamTrait, prelude::Uuid,
};
use sea_query::{ColumnType, Expr, JoinType, UnionType, extension::postgres::PgExpr};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, fmt::Debug, sync::Arc};
use tracing::{Instrument, info_span, instrument};
use trustify_common::{
    cpe::Cpe,
    db::{
        limiter::{LimitedResult, LimiterTrait, limit_selector},
        multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel},
        query::{Columns, Filtering, IntoColumns, Query, q},
    },
    id::{Id, TrySelectForId},
    model::{Paginated, PaginatedResults},
    purl::Purl,
    service::{Mappable, Resulting},
};
use trustify_entity::{
    advisory, advisory_vulnerability, base_purl,
    cpe::{self, CpeDto},
    labels::Labels,
    license, organization, package_relates_to_package, qualified_purl,
    relationship::Relationship,
    sbom, sbom_ai, sbom_group_assignment, sbom_license_expanded, sbom_node, sbom_node_cpe_ref,
    sbom_node_purl_ref, sbom_package, sbom_package_license, source_document, status,
    versioned_purl, vulnerability,
};

#[derive(Clone, Debug, Default)]
pub struct FetchOptions {
    labels: Labels,
    groups: Option<Vec<Uuid>>,
}

impl FetchOptions {
    pub fn labels(mut self, labels: impl Into<Labels>) -> Self {
        self.labels = labels.into();
        self
    }

    pub fn groups(mut self, groups: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.groups = Some(
            groups
                .into_iter()
                .filter_map(|s| Uuid::parse_str(s.as_ref()).ok())
                .collect(),
        );
        self
    }
}

impl SbomService {
    /// Fetch an SBOM, its node, and source document
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn fetch_sbom<C: ConnectionTrait>(
        &self,
        id: Id,
        connection: &C,
    ) -> Result<Option<(sbom::Model, sbom_node::Model, source_document::Model)>, Error> {
        let select = sbom::Entity::find()
            .find_also_linked(sbom::SbomNodeLink)
            .find_also_related(source_document::Entity)
            .try_filter(id)?;

        let map = |(sbom, node, source_document)| Some((sbom, node?, source_document?));

        Ok(select.one(connection).await?.and_then(map))
    }

    /// fetch one sbom
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn fetch_sbom_details<C>(
        &self,
        id: Id,
        statuses: Vec<String>,
        connection: &C,
    ) -> Result<Option<SbomDetails>, Error>
    where
        C: ConnectionTrait + StreamTrait,
    {
        Ok(match self.fetch_sbom(id, connection).await? {
            Some(row) => SbomDetails::from_entity(row, self, connection, statuses).await?,
            None => None,
        })
    }

    /// fetch the summary of one sbom
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn fetch_sbom_summary<C: ConnectionTrait>(
        &self,
        id: Id,
        connection: &C,
    ) -> Result<Option<SbomSummary>, Error> {
        Ok(match self.fetch_sbom(id, connection).await? {
            Some(row) => Some(SbomSummary::from_entity(row, self, connection).await?),
            None => None,
        })
    }

    /// delete one sbom
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn delete_sbom<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<bool, Error> {
        // IMPORTANT: Capture qualified_purl IDs before CASCADE deletion.
        // After SBOM deletion, CASCADE removes sbom_node_purl_ref entries,
        // then GC uses the captured IDs to clean up orphaned PURLs.
        let qualified_purl_ids: Vec<Uuid> = sbom_node_purl_ref::Entity::find()
            .select_only()
            .column(sbom_node_purl_ref::Column::QualifiedPurlId)
            .filter(sbom_node_purl_ref::Column::SbomId.eq(id))
            .into_tuple()
            .all(connection)
            .await?;

        log::debug!(
            "Captured {} qualified_purl IDs from SBOM {} for cleanup",
            qualified_purl_ids.len(),
            id
        );

        // Delete the SBOM - CASCADE will properly delete sbom_package and sbom_node_purl_ref
        let stmt = Statement::from_sql_and_values(
            connection.get_database_backend(),
            r#"DELETE FROM sbom WHERE sbom_id=$1 RETURNING source_document_id"#,
            [id.into()],
        );

        let result = connection.query_all(stmt).await?;
        if result.len() > 1 {
            return Err(Error::Data(format!("Too many rows deleted for {id}")));
        }

        for row in &result {
            let source_document = row.try_get_by_index::<Option<Uuid>>(0)?;
            if let Some(doc) = source_document {
                source_document::Entity::delete_by_id(doc)
                    .exec(connection)
                    .await?;
            }
        }

        // Cleanup orphaned PURLs if deletion succeeded and we had PURLs to check
        if !qualified_purl_ids.is_empty() && result.len() == 1 {
            // Build array parameter for the GC query
            let array_param = sea_query::Value::Array(
                sea_query::ArrayType::Uuid,
                Some(Box::new(
                    qualified_purl_ids
                        .iter()
                        .map(|&id| sea_query::Value::Uuid(Some(Box::new(id))))
                        .collect(),
                )),
            );

            let gc_stmt = Statement::from_sql_and_values(
                connection.get_database_backend(),
                // it looks much more readable in an SQL file
                include_str!("gc_purls_after_sbom_deletion.sql"),
                vec![array_param],
            );

            let gc_result = connection.execute(gc_stmt).await?;
            log::debug!(
                "Cleaned up {} orphaned purl records after SBOM {} deletion",
                gc_result.rows_affected(),
                id
            );
        }

        Ok(result.len() == 1)
    }

    /// fetch all SBOMs
    pub async fn fetch_sboms<C, P>(
        &self,
        search: Query,
        paginated: Paginated,
        options: FetchOptions,
        connection: &C,
    ) -> Result<PaginatedResults<SbomSummary<P>>, Error>
    where
        C: ConnectionTrait,
        P: IntoPackage,
    {
        let mut query = if options.labels.is_empty() {
            sbom::Entity::find()
        } else {
            sbom::Entity::find().filter(Expr::col(sbom::Column::Labels).contains(options.labels))
        };

        if let Some(group_ids) = options.groups {
            query = query.filter(
                sbom::Column::SbomId.in_subquery(
                    sbom_group_assignment::Entity::find()
                        .select_only()
                        .column(sbom_group_assignment::Column::SbomId)
                        .filter(sbom_group_assignment::Column::GroupId.is_in(group_ids))
                        .into_query(),
                ),
            );
        }

        // Add license filtering if license query is present
        if let Some(license_query) = search
            .get_constraint_for_field(LICENSE)
            .map(|constraint| q(&format!("{constraint}")))
        {
            // SPDX path: join through junction → dictionary
            let mut spdx_select = sbom_license_expanded::Entity::find()
                .select_only()
                .distinct()
                .column(sbom_license_expanded::Column::SbomId)
                .join(
                    JoinType::InnerJoin,
                    sbom_license_expanded::Relation::ExpandedLicense.def(),
                )
                .filtering_with(
                    license_query.clone(),
                    Columns::default()
                        .add_column("expanded_text", ColumnType::Text)
                        .translator(|field, operator, value| match field {
                            LICENSE => Some(format!("expanded_text{operator}{value}")),
                            _ => None,
                        }),
                )?;

            // CycloneDX path: direct text match
            let cyclonedx_select = sbom_package_license::Entity::find()
                .select_only()
                .distinct()
                .column(sbom_package_license::Column::SbomId)
                .join(
                    JoinType::InnerJoin,
                    sbom_package_license::Relation::License.def(),
                )
                .filtering_with(
                    license_query,
                    license::Entity
                        .columns()
                        .translator(|field, operator, value| match field {
                            LICENSE => Some(format!("text{operator}{value}")),
                            _ => None,
                        }),
                )?;

            QueryTrait::query(&mut spdx_select)
                .union(UnionType::Distinct, cyclonedx_select.into_query());
            query = query.filter(sbom::Column::SbomId.in_subquery(spdx_select.into_query()));
        }

        let limiter = query
            .find_also_linked(sbom::SbomNodeLink)
            .find_also_related(source_document::Entity)
            .filtering_with(
                search,
                Columns::from_entity::<sbom::Entity>()
                    .add_columns(sbom_node::Entity)
                    .add_columns(source_document::Entity)
                    .alias("sbom_node", "r0")
                    .translator(|f, op, v| match f.split_once(':') {
                        Some(("label", key)) => Some(format!("labels:{key}{op}{v}")),
                        _ => match f {
                            // Add an empty condition (effectively TRUE) to the main SQL query
                            // since the real filtering by license happens in the license subqueries above
                            LICENSE => Some("".to_string()),
                            _ => None,
                        },
                    }),
            )?
            .limiting(connection, paginated.offset, paginated.limit, &self.cache);

        let LimitedResult {
            items: sboms,
            total,
        } = limiter.fetch().await?;
        let total = total.requested(paginated.total).await?;

        let items = stream::iter(
            sboms
                .into_iter()
                .filter_map(|(sbom, node, source_document)| Some((sbom, node?, source_document?))),
        )
        .then(|row| async { SbomSummary::from_entity(row, self, connection).await })
        .try_collect()
        .instrument(info_span!("from_entity"))
        .await?;

        Ok(PaginatedResults { total, items })
    }

    /// Fetch all packages from an SBOM.
    ///
    /// If you need to find packages based on their relationship, even in the relationship to
    /// SBOM itself, use [`Self::fetch_related_packages`].
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn fetch_sbom_packages<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        search: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<SbomPackage>, Error> {
        let mut query = sbom_package::Entity::find()
            .filter(sbom_package::Column::SbomId.eq(sbom_id))
            .join(JoinType::Join, sbom_package::Relation::Node.def())
            .select_only()
            .column_as(sbom_package::Column::NodeId, "id")
            .group_by(sbom_package::Column::NodeId)
            .column_as(sbom_package::Column::Version, "version")
            .group_by(sbom_package::Column::Version)
            .column_as(sbom_node::Column::Name, "name")
            .group_by(sbom_node::Column::Name)
            .join(JoinType::LeftJoin, sbom_node::Relation::Purl.def())
            .join(JoinType::LeftJoin, sbom_node::Relation::Cpe.def());

        query = join_licenses(query);

        // Apply license filter via subqueries, matching the same pattern as `fetch_sboms`.
        // The `filtering_with` translator cannot express OR across two different table columns,
        // so we pre-filter node_ids: any package whose SPDX-expanded text OR raw license text
        // matches the query is included.
        if let Some(license_constraint) = search
            .get_constraint_for_field(LICENSE)
            .map(|constraint| q(&format!("{constraint}")))
        {
            // SPDX path: match via expanded_license dictionary
            let mut spdx_pkg_select = sbom_package_license::Entity::find()
                .select_only()
                .distinct()
                .column(sbom_package_license::Column::NodeId)
                .join(
                    JoinType::InnerJoin,
                    sbom_package_license::Relation::SbomLicenseExpanded.def(),
                )
                .join(
                    JoinType::InnerJoin,
                    sbom_license_expanded::Relation::ExpandedLicense.def(),
                )
                .filter(sbom_package_license::Column::SbomId.eq(sbom_id))
                .filtering_with(
                    license_constraint.clone(),
                    Columns::default()
                        .add_column("expanded_text", ColumnType::Text)
                        .translator(|field, operator, value| match field {
                            LICENSE => Some(format!("expanded_text{operator}{value}")),
                            _ => None,
                        }),
                )?;

            // CycloneDX path: match raw license text directly
            let cdx_pkg_select = sbom_package_license::Entity::find()
                .select_only()
                .distinct()
                .column(sbom_package_license::Column::NodeId)
                .join(
                    JoinType::InnerJoin,
                    sbom_package_license::Relation::License.def(),
                )
                .filter(sbom_package_license::Column::SbomId.eq(sbom_id))
                .filtering_with(
                    license_constraint,
                    license::Entity
                        .columns()
                        .translator(|field, operator, value| match field {
                            LICENSE => Some(format!("text{operator}{value}")),
                            _ => None,
                        }),
                )?;

            QueryTrait::query(&mut spdx_pkg_select)
                .union(UnionType::Distinct, cdx_pkg_select.into_query());
            query = query
                .filter(sbom_package::Column::NodeId.in_subquery(spdx_pkg_select.into_query()));
        }

        query = join_purls_and_cpes(query)
            .filtering_with(
                search,
                sbom_package::Entity
                    .columns()
                    .add_columns(sbom_node::Entity)
                    .add_columns(base_purl::Entity)
                    .add_columns(sbom_node_cpe_ref::Entity)
                    .add_columns(sbom_package_license::Entity)
                    .add_columns(license::Entity)
                    .add_columns(sbom_node_purl_ref::Entity)
                    .translator(|field, _operator, _value| {
                        match field {
                            // License filtering is handled via subqueries above; return an empty
                            // condition here so the main query is not further restricted.
                            LICENSE => Some("".to_string()),
                            _ => None,
                        }
                    }),
            )?
            // default order
            .order_by_asc(sbom_node::Column::Name)
            .order_by_asc(sbom_package::Column::Version);

        // limit and execute

        let limiter = limit_selector::<_, _, _, PackageCatcher>(
            connection,
            query,
            paginated.offset,
            paginated.limit,
            &self.cache,
        );

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total).await?;
        let items = items.into_iter().map(SbomPackage::from_row).collect();

        Ok(PaginatedResults { items, total })
    }

    /// Fetch AI models associated with an SBOM.
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn fetch_sbom_models<C: ConnectionTrait>(
        &self,
        sbom_id: Option<Uuid>,
        search: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<SbomModel>, Error> {
        let mut query = join_purls_and_cpes(
            sbom_ai::Entity::find()
                .select_only()
                .column_as(sbom_ai::Column::NodeId, "id")
                .group_by(sbom_ai::Column::NodeId)
                .column(sbom_node::Column::Name)
                .group_by(sbom_node::Column::Name)
                .column(sbom_ai::Column::Properties)
                .group_by(sbom_ai::Column::Properties)
                .join(JoinType::LeftJoin, sbom_ai::Relation::Node.def())
                .join(JoinType::LeftJoin, sbom_ai::Relation::Purl.def())
                .join(JoinType::LeftJoin, sbom_ai::Relation::Cpe.def())
                .filtering_with(
                    search,
                    Columns::from_entity::<sbom_ai::Entity>()
                        .add_columns(sbom_node::Entity)
                        .add_columns(qualified_purl::Entity)
                        .translator(|f, op, v| match f {
                            "purl:type" => Some(format!("purl:ty{op}{v}")),
                            "purl" => Purl::translate(op, v),
                            _ => None,
                        }),
                )?,
        );
        if let Some(id) = sbom_id {
            query = query.filter(sbom_ai::Column::SbomId.eq(id));
        }

        let limiter = limit_selector::<_, _, _, ModelCatcher>(
            connection,
            query,
            paginated.offset,
            paginated.limit,
            &self.cache,
        );

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total).await?;
        let items = items.into_iter().map(SbomModel::from_row).collect();

        Ok(PaginatedResults { items, total })
    }

    /// Get all packages describing the SBOM.
    #[instrument(skip(self, db), err(level=tracing::Level::INFO))]
    pub async fn describes_packages<C, R, P>(
        &self,
        sbom_id: Uuid,
        paginated: R,
        db: &C,
    ) -> Result<R::Output<P>, Error>
    where
        C: ConnectionTrait,
        R: Resulting,
        P: IntoPackage,
    {
        self.fetch_related_packages(
            sbom_id,
            Default::default(),
            paginated,
            Which::Left,
            SbomNodeReference::All,
            Some(Relationship::Describes),
            db,
        )
        .await
        .map(|r| r.map_all(|rel| rel.package))
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn count_related_sboms<C: ConnectionTrait>(
        &self,
        references: Vec<SbomExternalPackageReference<'_>>,
        connection: &C,
    ) -> Result<Vec<i64>, Error> {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        enum Id {
            Cpe(Uuid),
            Purl(Uuid),
        }

        let ids = references
            .iter()
            .map(|r| match r {
                SbomExternalPackageReference::Cpe(c) => Id::Cpe(c.uuid()),
                SbomExternalPackageReference::Purl(p) => Id::Purl(p.qualifier_uuid()),
            })
            .collect::<Vec<_>>();

        let mut counts_map = HashMap::new();

        let cpes = ids
            .iter()
            .filter_map(|id| match id {
                Id::Cpe(id) => Some(*id),
                _ => None,
            })
            .collect::<Vec<_>>();

        counts_map.extend(
            sbom::Entity::find()
                .join(JoinType::Join, sbom::Relation::Node.def())
                .join(JoinType::Join, sbom_node::Relation::Cpe.def())
                .filter(sbom_node_cpe_ref::Column::CpeId.is_in(cpes))
                .group_by(sbom_node_cpe_ref::Column::CpeId)
                .select_only()
                .column(sbom_node_cpe_ref::Column::CpeId)
                .column_as(sbom_node::Column::SbomId.count(), "count")
                .into_tuple::<(Uuid, i64)>()
                .all(connection)
                .await?
                .into_iter()
                .map(|(id, count)| (Id::Cpe(id), count)),
        );

        let purls = ids
            .iter()
            .filter_map(|id| match id {
                Id::Purl(id) => Some(*id),
                _ => None,
            })
            .collect::<Vec<_>>();

        counts_map.extend(
            sbom::Entity::find()
                .join(JoinType::Join, sbom::Relation::Node.def())
                .join(JoinType::Join, sbom_node::Relation::Purl.def())
                .filter(sbom_node_purl_ref::Column::QualifiedPurlId.is_in(purls))
                .group_by(sbom_node_purl_ref::Column::QualifiedPurlId)
                .select_only()
                .column(sbom_node_purl_ref::Column::QualifiedPurlId)
                .column_as(sbom_node::Column::SbomId.count(), "count")
                .into_tuple::<(Uuid, i64)>()
                .all(connection)
                .await?
                .into_iter()
                .map(|(id, count)| (Id::Purl(id), count)),
        );

        // now use the inbound order and retrieve results in that order

        let result: Vec<i64> = ids
            .into_iter()
            .map(|id| counts_map.get(&id).copied().unwrap_or_default())
            .collect();

        // return result

        Ok(result)
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn find_related_sboms<C: ConnectionTrait>(
        &self,
        package_ref: SbomExternalPackageReference<'_>,
        paginated: Paginated,
        query: Query,
        connection: &C,
    ) -> Result<PaginatedResults<SbomSummary>, Error> {
        let select = sbom::Entity::find().join(JoinType::Join, sbom::Relation::Node.def());

        let select = match package_ref {
            SbomExternalPackageReference::Purl(purl) => select
                .join(JoinType::Join, sbom_node::Relation::Purl.def())
                .filter(sbom_node_purl_ref::Column::QualifiedPurlId.eq(purl.qualifier_uuid())),
            SbomExternalPackageReference::Cpe(cpe) => select
                .join(JoinType::Join, sbom_node::Relation::Cpe.def())
                .filter(sbom_node_cpe_ref::Column::CpeId.eq(cpe.uuid())),
        };

        let query = select
            .find_also_linked(sbom::SbomNodeLink)
            .find_also_related(source_document::Entity)
            .filtering_with(
                query,
                Columns::from_entity::<sbom::Entity>()
                    .add_columns(sbom_node::Entity)
                    .alias("sbom_node", "r0"),
            )?;

        // limit and execute

        let limiter = query.limiting(connection, paginated.offset, paginated.limit, &self.cache);

        let LimitedResult {
            items: sboms,
            total,
        } = limiter.fetch().await?;
        let total = total.requested(paginated.total).await?;

        // collect results

        let items = stream::iter(
            sboms
                .into_iter()
                .filter_map(|(sbom, node, source_document)| Some((sbom, node?, source_document?))),
        )
        .then(|row| async { SbomSummary::from_entity(row, self, connection).await })
        .try_collect()
        .await?;

        Ok(PaginatedResults { items, total })
    }

    /// Fetch all related packages in the context of an SBOM.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self, db), err(level=tracing::Level::INFO))]
    pub async fn fetch_related_packages<C, R, P>(
        &self,
        sbom_id: Uuid,
        search: Query,
        options: R,
        which: Which,
        reference: impl Into<SbomNodeReference<'_>> + Debug,
        relationship: Option<Relationship>,
        db: &C,
    ) -> Result<R::Output<SbomPackageRelation<P>>, Error>
    where
        C: ConnectionTrait,
        R: Resulting,
        P: IntoPackage,
    {
        // which way

        log::debug!("Which: {which:?}");

        // select all qualified packages for which we have relationships

        let (filter, join) = match which {
            Which::Left => (
                package_relates_to_package::Column::LeftNodeId,
                package_relates_to_package::Relation::Right,
            ),
            Which::Right => (
                package_relates_to_package::Column::RightNodeId,
                package_relates_to_package::Relation::Left,
            ),
        };

        let mut query = package_relates_to_package::Entity::find()
            .filter(package_relates_to_package::Column::SbomId.eq(sbom_id))
            .select_only()
            .select_column_as(sbom_node::Column::NodeId, "id")
            .select_column_as(sbom_node::Column::Name, "name")
            .select_column_as(
                package_relates_to_package::Column::Relationship,
                "relationship",
            )
            .select_column_as(sbom_package::Column::Group, "group")
            .select_column_as(sbom_package::Column::Version, "version")
            // join the other side
            .join(JoinType::Join, join.def())
            .join(JoinType::Join, sbom_node::Relation::Package.def());

        query = P::build_query(query);

        // filter for reference

        query = match reference.into() {
            SbomNodeReference::All => {
                // sbom - add join to sbom table
                query.join(JoinType::Join, sbom_node::Relation::Sbom.def())
            }
            SbomNodeReference::Package(node_id) => {
                // package - set node id filter
                query.filter(filter.eq(node_id))
            }
        };

        // apply filter conditions

        query = query.filtering(search)?;

        // add relationship type filter

        if let Some(relationship) = relationship {
            query = query.filter(package_relates_to_package::Column::Relationship.eq(relationship));
        }

        // execute

        #[derive(FromQueryResult)]
        struct Row<P: FromQueryResult> {
            relationship: Relationship,
            #[sea_orm(nested)]
            package: P,
        }

        let r: R::Output<Row<P::Row>> = R::get(options, db, query, &self.cache).await?;

        Ok(r.flat_map_all(|row| {
            Some(SbomPackageRelation {
                relationship: row.relationship,
                package: P::from_row(row.package),
            })
        }))
    }

    /// A simplified version of [`Self::fetch_related_packages`].
    ///
    /// It uses [`Which::Right`] and the provided reference, [`Default::default`] for the rest.
    pub async fn related_packages<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        relationship: impl Into<Option<Relationship>>,
        pkg: impl Into<SbomNodeReference<'_>> + Debug,
        tx: &C,
    ) -> Result<Vec<SbomPackage>, Error> {
        let result = self
            .fetch_related_packages(
                sbom_id,
                Default::default(),
                (),
                Which::Left,
                pkg,
                relationship.into(),
                tx,
            )
            .await?;

        // turn into a map, removing duplicates

        let result: HashMap<_, _> = result
            .into_iter()
            .map(|r: SbomPackageRelation<SbomPackage>| (r.package.id.clone(), r.package))
            .collect();

        // take the de-duplicated values and return them

        Ok(result.into_values().collect())
    }
}

pub trait IntoPackage: Sized {
    type Row: FromQueryResult + Send + Sync + 'static;

    fn build_query(
        query: Select<package_relates_to_package::Entity>,
    ) -> Select<package_relates_to_package::Entity>;

    fn from_row(row: Self::Row) -> Self;
}

impl IntoPackage for SbomPackageSummary {
    type Row = PackageCatcherBase;

    fn build_query(
        query: Select<package_relates_to_package::Entity>,
    ) -> Select<package_relates_to_package::Entity> {
        query
    }

    fn from_row(row: Self::Row) -> Self {
        Self {
            id: row.id,
            name: row.name,
            group: row.group,
            version: row.version,
        }
    }
}

impl IntoPackage for SbomPackage {
    type Row = PackageCatcher;

    fn build_query(
        mut query: Select<package_relates_to_package::Entity>,
    ) -> Select<package_relates_to_package::Entity> {
        // we're joining more, so we need to group now

        query = query
            .group_by(sbom_node::Column::NodeId)
            .group_by(sbom_node::Column::Name)
            .group_by(package_relates_to_package::Column::Relationship)
            .group_by(sbom_package::Column::Group)
            .group_by(sbom_package::Column::Version);

        // join ref tables

        query = query
            .join(JoinType::LeftJoin, sbom_node::Relation::Purl.def())
            .join(JoinType::LeftJoin, sbom_node::Relation::Cpe.def());

        // collect licenses

        query = join_licenses(query);

        // collect PURLs and CPEs

        query = join_purls_and_cpes(query);

        query
    }

    fn from_row(row: Self::Row) -> Self {
        let purl = PurlSummary::from_values(row.purls);

        let cpe = row
            .cpes
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|cpe| {
                serde_json::from_value::<CpeDto>(cpe.clone())
                    .inspect_err(|err| {
                        log::warn!("Failed to deserialize CPE: {err}");
                    })
                    .ok()
            })
            .flat_map(|cpe| {
                log::debug!("CPE: {cpe:?}");
                Cpe::try_from(cpe)
                    .inspect_err(|err| {
                        log::warn!("Failed to build CPE: {err}");
                    })
                    .ok()
            })
            .map(|cpe| cpe.to_string())
            .collect();

        // License names are now pre-expanded via JOIN with expanded_license table
        // No need to build licenses_ref_mapping manually
        let licenses = row
            .licenses
            .into_iter()
            .map(|license| license.into())
            .collect();

        SbomPackage {
            id: row.base.id,
            name: row.base.name,
            group: row.base.group,
            version: row.base.version,
            purl,
            cpe,
            licenses,
            #[allow(deprecated)]
            licenses_ref_mapping: vec![], // No longer needed - licenses are pre-expanded
        }
    }
}

/// Join CPE and PURL information.
///
/// Given a select over something which already joins sbom_node_purl_ref and
/// sbom_node_cpe_ref, this adds joins to fetch the data for PURLs and CPEs so that it can be
/// built using [`package_from_row`].
///
/// This will add the columns `purls` and `cpes` to the selected output.
fn join_purls_and_cpes<E>(query: Select<E>) -> Select<E>
where
    E: EntityTrait,
{
    query
        .join(JoinType::LeftJoin, sbom_node_purl_ref::Relation::Purl.def())
        .join(
            JoinType::LeftJoin,
            qualified_purl::Relation::VersionedPurl.def(),
        )
        .join(JoinType::LeftJoin, versioned_purl::Relation::BasePurl.def())
        // aggregate the purls
        .select_column_as(
            Expr::cust_with_exprs(
                "coalesce(array_agg(distinct $1) filter (where $2), '{}')",
                [
                    qualified_purl::Column::Purl.into_simple_expr(),
                    sbom_node_purl_ref::Column::QualifiedPurlId
                        .is_not_null()
                        .into_simple_expr(),
                ],
            ),
            "purls",
        )
        .join(JoinType::LeftJoin, sbom_node_cpe_ref::Relation::Cpe.def())
        // aggregate the cpes
        .select_column_as(
            Expr::cust_with_exprs(
                "to_json(coalesce(array_agg(distinct $1) filter (where $2), '{}'))",
                [
                    Expr::col(cpe::Entity).into_simple_expr(),
                    sbom_node_cpe_ref::Column::CpeId.is_not_null(),
                ],
            ),
            "cpes",
        )
}

/// Join License information.
///
/// Given a select over sbom_package, this adds joins to fetch the data for Licenses so that it can be
/// built using [`package_from_row`].
///
/// This will add the column `licenses` to the selected output.
fn join_licenses<E>(query: Select<E>) -> Select<E>
where
    E: EntityTrait,
{
    query
        .select_column_as(
            Expr::cust_with_exprs(
                "coalesce(json_agg(distinct jsonb_build_object('license_name', $1, 'license_type', $2)) filter (where $3), '[]'::json)",
                [
                    license_text_coalesce(),
                    sbom_package_license::Column::LicenseType.into_simple_expr(),
                    Expr::col((license::Entity, license::Column::Text)).is_not_null(),
                ],
            ),
            "licenses",
        )
        .join(
            JoinType::LeftJoin,
            sbom_node::Relation::PackageLicense.def(),
        )
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
}

#[derive(FromQueryResult)]
pub struct PackageCatcher {
    #[sea_orm(nested)]
    base: PackageCatcherBase,

    purls: Vec<Value>,
    cpes: Value,

    licenses: Vec<LicenseBasicInfo>,
}

#[derive(FromQueryResult)]
pub struct PackageCatcherBase {
    id: String,
    name: String,
    group: Option<String>,
    version: Option<String>,
}

#[derive(Serialize, Deserialize, FromJsonQueryResult)]
pub struct LicenseBasicInfo {
    pub license_name: String,
    pub license_type: i32,
}

#[derive(Debug)]
pub struct QueryCatcher {
    pub advisory: Arc<advisory::Model>,
    pub qualified_purl: Arc<qualified_purl::Model>,
    pub sbom_package: Arc<sbom_package::Model>,
    pub sbom_node: Arc<sbom_node::Model>,
    pub advisory_vulnerability: Arc<advisory_vulnerability::Model>,
    pub vulnerability: Arc<vulnerability::Model>,
    pub context_cpe: Option<Arc<cpe::Model>>,
    pub status: Arc<status::Model>,
    pub organization: Option<Arc<organization::Model>>,
}

impl FromQueryResult for QueryCatcher {
    fn from_query_result(res: &QueryResult, _pre: &str) -> Result<Self, DbErr> {
        Ok(Self {
            advisory: Arc::new(Self::from_query_result_multi_model(
                res,
                "",
                advisory::Entity,
            )?),
            advisory_vulnerability: Arc::new(Self::from_query_result_multi_model(
                res,
                "",
                advisory_vulnerability::Entity,
            )?),
            vulnerability: Arc::new(Self::from_query_result_multi_model(
                res,
                "",
                vulnerability::Entity,
            )?),
            qualified_purl: Arc::new(Self::from_query_result_multi_model(
                res,
                "",
                qualified_purl::Entity,
            )?),
            sbom_package: Arc::new(Self::from_query_result_multi_model(
                res,
                "",
                sbom_package::Entity,
            )?),
            sbom_node: Arc::new(Self::from_query_result_multi_model(
                res,
                "",
                sbom_node::Entity,
            )?),
            context_cpe: Self::from_query_result_multi_model_optional(res, "", cpe::Entity)?
                .map(Arc::new),
            status: Arc::new(Self::from_query_result_multi_model(
                res,
                "",
                status::Entity,
            )?),
            organization: Self::from_query_result_multi_model_optional(
                res,
                "",
                organization::Entity,
            )?
            .map(Arc::new),
        })
    }
}

impl FromQueryResultMultiModel for QueryCatcher {
    fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr> {
        select
            .try_model_columns(advisory::Entity)?
            .try_model_columns(advisory_vulnerability::Entity)?
            .try_model_columns(vulnerability::Entity)?
            .try_model_columns(base_purl::Entity)?
            .try_model_columns(versioned_purl::Entity)?
            .try_model_columns(qualified_purl::Entity)?
            .try_model_columns(sbom_package::Entity)?
            .try_model_columns(sbom_node::Entity)?
            .try_model_columns(status::Entity)?
            .try_model_columns(cpe::Entity)?
            .try_model_columns(organization::Entity)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::pagination_cache::PaginationCache;
    use trustify_common::db::query::q;
    use trustify_common::hashing::Digests;
    use trustify_entity::labels::Labels;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn all_sboms(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let sbom_v1 = ctx
            .graph
            .ingest_sbom(
                Labels::default(),
                &Digests::digest("RHSA-1"),
                Some("http://redhat.com/test.json".to_string()),
                (),
                &ctx.db,
            )
            .await?;
        let sbom_v1_again = ctx
            .graph
            .ingest_sbom(
                Labels::default(),
                &Digests::digest("RHSA-1"),
                Some("http://redhat.com/test.json".to_string()),
                (),
                &ctx.db,
            )
            .await?;
        let sbom_v2 = ctx
            .graph
            .ingest_sbom(
                Labels::default(),
                &Digests::digest("RHSA-2"),
                Some("http://myspace.com/test.json".to_string()),
                (),
                &ctx.db,
            )
            .await?;

        let _other_sbom = ctx
            .graph
            .ingest_sbom(
                Labels::default(),
                &Digests::digest("RHSA-3"),
                Some("http://geocities.com/other.json".to_string()),
                (),
                &ctx.db,
            )
            .await?;

        assert_eq!(sbom_v1.sbom.sbom_id, sbom_v1_again.sbom.sbom_id);
        assert_ne!(sbom_v1.sbom.sbom_id, sbom_v2.sbom.sbom_id);

        let fetch = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

        let fetched = fetch
            .fetch_sboms::<_, SbomPackage>(
                q("MySpAcE").sort("name,authors,published"),
                Paginated {
                    total: true,
                    ..Default::default()
                },
                Default::default(),
                &ctx.db,
            )
            .await?;

        log::debug!("{:#?}", fetched.items);
        assert_eq!(Some(1), fetched.total);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let _sbom1 = ctx
            .graph
            .ingest_sbom(
                Labels::new()
                    .add("source", "test")
                    .add("ci", "job1")
                    .add("team", "a"),
                &Digests::digest("RHSA-1"),
                Some("http://redhat.com/test1.json".to_string()),
                (),
                &ctx.db,
            )
            .await?;

        let _sbom2 = ctx
            .graph
            .ingest_sbom(
                Labels::new()
                    .add("source", "test")
                    .add("ci", "job2")
                    .add("team", "b"),
                &Digests::digest("RHSA-2"),
                Some("http://redhat.com/test2.json".to_string()),
                (),
                &ctx.db,
            )
            .await?;

        let _sbom3 = ctx
            .graph
            .ingest_sbom(
                Labels::new()
                    .add("source", "test")
                    .add("ci", "job2")
                    .add("team", "a"),
                &Digests::digest("RHSA-3"),
                Some("http://redhat.com/test3.json".to_string()),
                (),
                &ctx.db,
            )
            .await?;

        let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

        let paginated_with_total = Paginated {
            total: true,
            ..Default::default()
        };

        let fetched = service
            .fetch_sboms::<_, SbomPackage>(
                Query::default(),
                paginated_with_total,
                FetchOptions::default().labels(("ci", "job1")),
                &ctx.db,
            )
            .await?;
        assert_eq!(Some(1), fetched.total);

        let fetched = service
            .fetch_sboms::<_, SbomPackage>(
                Query::default(),
                paginated_with_total,
                FetchOptions::default().labels(("ci", "job2")),
                &ctx.db,
            )
            .await?;
        assert_eq!(Some(2), fetched.total);

        let fetched = service
            .fetch_sboms::<_, SbomPackage>(
                Query::default(),
                paginated_with_total,
                FetchOptions::default().labels(("ci", "job3")),
                &ctx.db,
            )
            .await?;
        assert_eq!(Some(0), fetched.total);

        let fetched = service
            .fetch_sboms::<_, SbomPackage>(
                Query::default(),
                paginated_with_total,
                FetchOptions::default().labels(("foo", "bar")),
                &ctx.db,
            )
            .await?;
        assert_eq!(Some(0), fetched.total);

        let fetched = service
            .fetch_sboms::<_, SbomPackage>(
                Query::default(),
                paginated_with_total,
                Default::default(),
                &ctx.db,
            )
            .await?;
        assert_eq!(Some(3), fetched.total);

        let fetched = service
            .fetch_sboms::<_, SbomPackage>(
                Query::default(),
                paginated_with_total,
                FetchOptions::default().labels([("ci", "job2"), ("team", "a")]),
                &ctx.db,
            )
            .await?;
        assert_eq!(Some(1), fetched.total);

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn delete_sbom(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let sbom_v1 = ctx
            .graph
            .ingest_sbom(
                Labels::default(),
                &Digests::digest("RHSA-1"),
                Some("http://redhat.com/test.json".to_string()),
                (),
                &ctx.db,
            )
            .await?;

        let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

        assert!(service.delete_sbom(sbom_v1.sbom.sbom_id, &ctx.db).await?);
        assert!(!service.delete_sbom(sbom_v1.sbom.sbom_id, &ctx.db).await?);

        Ok(())
    }
}
