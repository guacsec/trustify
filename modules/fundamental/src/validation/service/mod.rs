use crate::{Error, validation::model::ValidationReportSummary};
use sea_orm::{ConnectionTrait, EntityTrait, QueryOrder};
use trustify_common::{
    db::{
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Filtering, Query},
    },
    id::Id,
    model::{PaginatedResults, Pagination},
};
use trustify_entity::validation_report;
use trustify_module_ingestor::service::validation::store;

/// Read access to stored validation reports.
pub struct ValidationService {
    cache: PaginationCache,
}

impl ValidationService {
    /// Creates a new validation report service.
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    /// Lists reports matching the given query, newest first.
    ///
    /// Includes reports for documents that were rejected, which exist nowhere
    /// else: they have no document resource to be listed under.
    pub async fn list<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<ValidationReportSummary>, Error> {
        let limiter = validation_report::Entity::find()
            .filtering(query)?
            .order_by_desc(validation_report::Column::CreatedAt)
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        Ok(PaginatedResults {
            items: items.into_iter().map(Into::into).collect(),
            total,
        })
    }

    /// Every report for one document, newest first.
    ///
    /// Accepts an internal UUID or any supported digest. Only a SHA-256
    /// matches a rejected document: everything else resolves through the
    /// ingested document it belongs to.
    pub async fn get<C: ConnectionTrait>(
        &self,
        id: Id,
        connection: &C,
    ) -> Result<Vec<ValidationReportSummary>, Error> {
        let reports = store::by_document_id(id)
            .map_err(|err| Error::bad_request(err.to_string(), None::<String>))?
            .order_by_desc(validation_report::Column::CreatedAt)
            .all(connection)
            .await?;

        Ok(reports.into_iter().map(Into::into).collect())
    }

    /// Every report for documents with the given name, newest first.
    ///
    /// Matches the name of an SBOM's describing node and the advisory
    /// identifier, neither of which is unique.
    pub async fn get_by_name<C: ConnectionTrait>(
        &self,
        name: &str,
        query: Query,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<ValidationReportSummary>, Error> {
        let limiter = store::by_document_name(name)
            .filtering(query)?
            .order_by_desc(validation_report::Column::CreatedAt)
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        Ok(PaginatedResults {
            items: items.into_iter().map(Into::into).collect(),
            total,
        })
    }
}
