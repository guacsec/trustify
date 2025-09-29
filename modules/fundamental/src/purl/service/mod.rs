use std::collections::HashMap;

use crate::{
    Error,
    common::license_filtering::{
        LICENSE, apply_license_filtering, create_purl_license_filtering_base_query,
    },
    purl::model::{
        RecommendEntry, VulnerabilityStatus,
        details::{
            base_purl::BasePurlDetails, purl::PurlDetails, versioned_purl::VersionedPurlDetails,
        },
        summary::{base_purl::BasePurlSummary, purl::PurlSummary, r#type::TypeSummary},
    },
};
use regex::Regex;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, prelude::Uuid,
};
use sea_query::Order;
use tracing::instrument;
use trustify_common::{
    db::{
        limiter::LimiterTrait,
        query::{Filtering, IntoColumns, Query, q},
    },
    model::{Paginated, PaginatedResults},
    purl::{Purl, PurlErr},
};
use trustify_entity::{
    base_purl,
    qualified_purl::{self, CanonicalPurl},
    versioned_purl,
};
use trustify_module_ingestor::common::Deprecation;

#[derive(Default)]
pub struct PurlService {}

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

        // Add license filtering if license query is present
        select = apply_license_filtering(
            select,
            &query,
            create_purl_license_filtering_base_query,
            qualified_purl::Column::Id,
        )?;

        let limiter = select.limiting(connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: PurlSummary::from_entities(&limiter.fetch().await?),
            total,
        })
    }

    #[instrument(skip(self, connection), err)]
    pub async fn gc_purls<C: ConnectionTrait>(&self, connection: &C) -> Result<u64, Error> {
        let res = connection
            .execute_unprepared(include_str!("gc_purls.sql"))
            .await?;

        Ok(res.rows_affected())
    }

    #[instrument(skip(self, connection), err)]
    pub async fn recommend_purls<C: ConnectionTrait>(
        &self,
        purls: &[Purl],
        connection: &C,
    ) -> Result<HashMap<String, Vec<RecommendEntry>>, Error> {
        let mut recommendations = HashMap::new();

        #[allow(clippy::unwrap_used)]
        let pattern = Regex::new("redhat-[0-9]+$").unwrap();

        for purl in purls {
            let query = match purl.to_string().split_once('@') {
                Some((p, _)) => format!("purl~{p}"),
                None => format!("purl~{purl}"),
            };
            let summaries = self
                .purls(q(&query), Default::default(), connection)
                .await?;

            let Some(ref input_version_str) = purl.version else {
                continue;
            };
            let Ok(input_version) = lenient_semver::parse(input_version_str) else {
                log::debug!(
                    "input purl {} version {:?} failed to parse",
                    purl,
                    input_version_str
                );
                continue;
            };

            let highest_patch = summaries
                .items
                .into_iter()
                .fold(
                    None,
                    |acc: Option<(PurlSummary, semver::Version)>, summary: PurlSummary| {
                        summary
                            .head
                            .purl
                            .version
                            .as_ref()
                            .filter(|version| pattern.is_match(version))
                            .and_then(|version| {
                                lenient_semver::parse(version)
                                    .inspect_err(|_| {
                                        log::debug!(
                                            "purl {} version {:?} failed to parse",
                                            summary.head.purl,
                                            summary.head.purl.version
                                        )
                                    })
                                    .ok()
                            })
                            .filter(|version| {
                                version.major == input_version.major
                                    && version.minor == input_version.minor
                                    && version.patch == input_version.patch
                            })
                            .and_then(|version| match &acc {
                                Some((_, v)) if version.pre > v.pre => Some((summary, version)),
                                None => Some((summary, version)),
                                _ => None,
                            })
                            .or(acc)
                    },
                )
                .map(|(summary, _)| summary);

            let mut recommended_purls = Vec::new();
            if let Some(highest) = highest_patch
                && let Some(purl_details) = self
                    .versioned_purl_by_uuid(&highest.head.purl.version_uuid(), connection)
                    .await?
            {
                recommended_purls.push(RecommendEntry {
                    package: highest.head.purl.to_string(),
                    vulnerabilities: purl_details
                        .advisories
                        .iter()
                        .flat_map(|advisory| {
                            advisory.status.iter().map(|status| VulnerabilityStatus {
                                id: status.vulnerability.identifier.clone(),
                                status: Some(status.into()),
                                justification: None,
                            })
                        })
                        .collect(),
                });
            }

            recommendations.insert(purl.to_string(), recommended_purls);
        }

        Ok(recommendations)
    }
}

#[cfg(test)]
mod test;
