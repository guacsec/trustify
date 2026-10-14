//! The statuses an advisory states, as stored when it was ingested.
//!
//! These are the facts the correlation engine matches SBOMs against.

use crate::{
    error::Error,
    extractor::cpe::format_cpe23,
    model::{AdvisoryStatement, MatchedRange, StatementKind, StatementSubject},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, LoaderTrait, QueryFilter, QueryOrder, QueryTrait,
};
use tracing::{Instrument, info_span, instrument};
use trustify_common::{
    db::{
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
    },
    model::{PaginatedResults, Pagination},
    purl::Purl,
};
use trustify_entity::{
    base_purl, cpe, cpe_status, product, product_status, product_version_range, purl_status,
    qualified_purl, status, version_range,
};
use uuid::Uuid;

/// Lists the statements of advisories.
pub struct StatementService {
    cache: PaginationCache,
}

/// A related row which must exist, by its foreign key.
fn required<T>(value: Option<T>, what: &str) -> Result<T, Error> {
    value.ok_or_else(|| Error::NotFound(format!("{what} of an advisory statement")))
}

impl StatementService {
    /// Create a new service.
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    /// List the statements of an advisory about one kind of subject, optionally only those for
    /// one vulnerability, ordered by vulnerability.
    ///
    /// An unknown advisory has no statements.
    #[instrument(skip(self, paginated, connection), err(level = tracing::Level::INFO))]
    pub async fn list<C: ConnectionTrait>(
        &self,
        advisory_id: Uuid,
        kind: StatementKind,
        vulnerability: Option<&str>,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<AdvisoryStatement>, Error> {
        match kind {
            StatementKind::Purl => {
                self.purls(advisory_id, vulnerability, paginated, connection)
                    .await
            }
            StatementKind::Cpe => {
                self.cpes(advisory_id, vulnerability, paginated, connection)
                    .await
            }
            StatementKind::Product => {
                self.products(advisory_id, vulnerability, paginated, connection)
                    .await
            }
        }
    }

    async fn purls<C: ConnectionTrait>(
        &self,
        advisory_id: Uuid,
        vulnerability: Option<&str>,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<AdvisoryStatement>, Error> {
        let limiter = purl_status::Entity::find()
            .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
            .apply_if(vulnerability, |query, id| {
                query.filter(purl_status::Column::VulnerabilityId.eq(id))
            })
            .order_by_asc(purl_status::Column::VulnerabilityId)
            .order_by_asc(purl_status::Column::Id)
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        let statuses = items
            .load_one(status::Entity, connection)
            .instrument(info_span!("loading statuses"))
            .await?;
        let ranges = items
            .load_one(version_range::Entity, connection)
            .instrument(info_span!("loading version ranges"))
            .await?;
        let purls = items
            .load_one(base_purl::Entity, connection)
            .instrument(info_span!("loading base purls"))
            .await?;
        let qualified = items.load_one(qualified_purl::Entity, connection).await?;

        let items = items
            .into_iter()
            .zip(statuses)
            .zip(ranges)
            .zip(purls)
            .zip(qualified)
            .map(|((((row, status), range), purl), qualified)| {
                let purl = required(purl, "base PURL")?;
                let subject = match row.qualified_purl_id {
                    Some(_) => Purl::from(required(qualified, "qualified PURL")?.purl),
                    None => Purl {
                        ty: purl.r#type,
                        namespace: purl.namespace,
                        name: purl.name,
                        version: None,
                        qualifiers: Default::default(),
                    },
                };
                Ok(AdvisoryStatement {
                    vulnerability_id: row.vulnerability_id,
                    status: required(status, "status")?.slug,
                    subject: StatementSubject::Purl {
                        purl: subject.to_string(),
                    },
                    range: MatchedRange::from(required(range, "version range")?),
                    default: row.is_default,
                })
            })
            .collect::<Result<_, Error>>()?;

        Ok(PaginatedResults { items, total })
    }

    async fn cpes<C: ConnectionTrait>(
        &self,
        advisory_id: Uuid,
        vulnerability: Option<&str>,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<AdvisoryStatement>, Error> {
        let limiter = cpe_status::Entity::find()
            .filter(cpe_status::Column::AdvisoryId.eq(advisory_id))
            .apply_if(vulnerability, |query, id| {
                query.filter(cpe_status::Column::VulnerabilityId.eq(id))
            })
            .order_by_asc(cpe_status::Column::VulnerabilityId)
            .order_by_asc(cpe_status::Column::Id)
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        let statuses = items
            .load_one(status::Entity, connection)
            .instrument(info_span!("loading statuses"))
            .await?;
        let ranges = items
            .load_one(version_range::Entity, connection)
            .instrument(info_span!("loading version ranges"))
            .await?;
        let cpes = items
            .load_one(cpe::Entity, connection)
            .instrument(info_span!("loading cpes"))
            .await?;

        let items = items
            .into_iter()
            .zip(statuses)
            .zip(ranges)
            .zip(cpes)
            .map(|(((row, status), range), cpe)| {
                Ok(AdvisoryStatement {
                    vulnerability_id: row.vulnerability_id,
                    status: required(status, "status")?.slug,
                    subject: StatementSubject::Cpe {
                        cpe: format_cpe23(&required(cpe, "CPE")?),
                    },
                    range: MatchedRange::from(required(range, "version range")?),
                    default: false,
                })
            })
            .collect::<Result<_, Error>>()?;

        Ok(PaginatedResults { items, total })
    }

    async fn products<C: ConnectionTrait>(
        &self,
        advisory_id: Uuid,
        vulnerability: Option<&str>,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<AdvisoryStatement>, Error> {
        let limiter = product_status::Entity::find()
            .filter(product_status::Column::AdvisoryId.eq(advisory_id))
            .apply_if(vulnerability, |query, id| {
                query.filter(product_status::Column::VulnerabilityId.eq(id))
            })
            .order_by_asc(product_status::Column::VulnerabilityId)
            .order_by_asc(product_status::Column::Id)
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        let statuses = items
            .load_one(status::Entity, connection)
            .instrument(info_span!("loading statuses"))
            .await?;
        let product_ranges = items
            .load_one(product_version_range::Entity, connection)
            .instrument(info_span!("loading product version ranges"))
            .await?
            .into_iter()
            .map(|range| required(range, "product version range"))
            .collect::<Result<Vec<_>, Error>>()?;
        let ranges = product_ranges
            .load_one(version_range::Entity, connection)
            .instrument(info_span!("loading version ranges"))
            .await?;
        let products = product_ranges
            .load_one(product::Entity, connection)
            .instrument(info_span!("loading products"))
            .await?;

        let items = items
            .into_iter()
            .zip(statuses)
            .zip(product_ranges)
            .zip(ranges)
            .zip(products)
            .map(|((((row, status), product_range), range), product)| {
                Ok(AdvisoryStatement {
                    vulnerability_id: row.vulnerability_id,
                    status: required(status, "status")?.slug,
                    subject: StatementSubject::Product {
                        name: required(product, "product")?.name,
                        cpe_key: product_range.cpe_key,
                        package: row.package,
                        csaf_product_ids: row.csaf_product_ids.unwrap_or_default(),
                    },
                    range: MatchedRange::from(required(range, "version range")?),
                    default: false,
                })
            })
            .collect::<Result<_, Error>>()?;

        Ok(PaginatedResults { items, total })
    }
}
