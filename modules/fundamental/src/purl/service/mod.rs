use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use crate::{
    Error,
    common::license_filtering::LICENSE,
    purl::model::{
        RecommendEntry, RecommendReportImpactSummary, RecommendReportPackage,
        RecommendReportResponse, RecommendReportSbom, VexStatus, VulnerabilityStatus,
        details::{
            base_purl::BasePurlDetails, purl::PurlDetails, versioned_purl::VersionedPurlDetails,
        },
        summary::{
            base_purl::BasePurlSummary, purl::PurlSummary, remediation::RemediationSummary,
            r#type::TypeSummary,
        },
    },
};
use regex::Regex;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, FromQueryResult, LoaderTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, RelationTrait, prelude::Uuid,
};
use sea_query::{
    Alias, Asterisk, ColumnType, Expr, ExprTrait, Func, IntoIden, IntoValueTuple,
    JoinType::{self, InnerJoin},
    Order, SimpleExpr, TableRef, UnionType, ValueTuple,
};
use tracing::{Instrument, info_span, instrument};
use trustify_common::{
    db::{
        VersionMatches,
        chunk::chunked_with,
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Columns, Filtering, IntoColumns, Query, q},
    },
    model::{PaginatedResults, Pagination},
    purl::{Purl, PurlErr},
};
use trustify_entity::{
    advisory, base_purl, license, organization, purl_status,
    qualified_purl::{self, CanonicalPurl},
    remediation, remediation_purl_status, sbom, sbom_license_expanded, sbom_node,
    sbom_node_purl_ref, sbom_package, sbom_package_license, source_document, status, version_range,
    versioned_purl, vulnerability,
};
use trustify_module_ingestor::common::Deprecation;
use trustify_module_storage::service::dispatch::DispatchBackend;

pub(crate) mod report;

/// Composite key identifying a base PURL by type, namespace, and name (without version).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct PurlKey<'a> {
    ty: &'a str,
    namespace: Option<&'a str>,
    name: &'a str,
}

/// Vulnerability status record linking a vulnerability ID to its VEX status and remediations.
struct StatusInfo {
    vuln_id: String,
    status_slug: String,
    remediations: Vec<remediation::Model>,
    source_id: Uuid,
    status_id: Uuid,
    advisory_pk: Uuid,
    context_cpe_id: Option<Uuid>,
    range: Arc<version_range::Model>,
    provider: report::ProviderIdentity,
    csaf: bool,
    /// The advisory identifier that reported this status, used for report provenance.
    advisory_id: Option<String>,
}

/// Red Hat CSAF ingestion used to store an `affected` range below every stated `fixed`
/// version, because the range was inferred at read time. Main marks those rows `derived`
/// through `purl_status_effective`; this branch has no such view, so a generated row is
/// identified by shape, as `m0002480_drop_redhat_derived_purl_status` does: no lower bound
/// and an exclusive upper bound. Red Hat documents never state that range themselves, so
/// the shape plus the publisher namespace is what makes the row inference rather than a
/// statement. A stated range of the same shape from another publisher is left alone.
fn is_generated_affected(status: &StatusInfo) -> bool {
    if status.status_slug != "affected"
        || !status.csaf
        || status.range.low_version.is_some()
        || status.range.high_version.is_none()
        || status.range.high_inclusive != Some(false)
    {
        return false;
    }
    status
        .advisory_id
        .as_deref()
        .and_then(|identifier| identifier.rsplit_once('#'))
        .is_some_and(|(namespace, _)| namespace.trim_end_matches('/') == "https://www.redhat.com")
}

/// A status row paired with the exact winner version it matched.
#[derive(FromQueryResult)]
struct WinnerPurlStatus {
    #[sea_orm(nested)]
    status: purl_status::Model,
    winner_versioned_purl_id: Uuid,
}

/// A PURL-to-SBOM association row fetched for the recommendation report endpoint.
struct SbomPurlRow {
    sbom_id: Uuid,
    node_id: Arc<str>,
    node_name: Arc<str>,
    package_group: Option<Arc<str>>,
    package_version: Option<Arc<str>>,
    node_purls: Arc<Vec<Purl>>,
    base_purl_id: Uuid,
    version: String,
    purl_type: String,
    purl_namespace: Option<String>,
    purl_name: String,
}

/// One aggregate per node prevents large attributes being repeated for each PURL association.
#[derive(FromQueryResult)]
struct SbomPurlNodeRow {
    sbom_id: Uuid,
    node_id: String,
    node_name: String,
    package_group: Option<String>,
    package_version: Option<String>,
    purls: serde_json::Value,
}

/// Source sizes are checked before materializing names or identifier arrays from the database.
#[derive(FromQueryResult)]
struct ReportInputSource {
    sbom_id: Uuid,
    size: i64,
}

/// SBOM root-node name row used to populate the report's sboms list.
#[derive(FromQueryResult)]
struct SbomNameRow {
    sbom_id: Uuid,
    name: String,
}

/// Metadata collected per `(base_purl_id, version)` group during report generation.
struct VersionGroup {
    purl_type: String,
    namespace: Option<String>,
    name: String,
}

/// A winning vendor recommendation for an upstream package, assembled during report generation.
struct ReportWinner {
    upstream_purl: String,
    target_purl: Purl,
    recommended_purl: String,
    base_purl_id: Uuid,
    winner_vp_id: Uuid,
    winner_version: String,
    upstream_version: String,
}

/// Report rows retain the selected verdict, its advisory and equivalent-context membership.
#[derive(PartialEq, Eq, Hash)]
struct ReportPackageKey {
    purl: String,
    recommended_purl: String,
    status: String,
    advisory_id: Option<String>,
    found_in: Vec<Uuid>,
}

/// The highest Red Hat patch version selected for a given input PURL, used to build the recommendation.
struct Winner<'a> {
    purl_string: String,
    versioned_purl: &'a versioned_purl::Model,
    base: &'a base_purl::Model,
}

impl<'a> PurlKey<'a> {
    fn from_purl(purl: &'a Purl) -> Self {
        Self {
            ty: &purl.ty,
            namespace: purl.namespace.as_deref(),
            name: &purl.name,
        }
    }

    fn from_base_purl(bp: &'a base_purl::Model) -> Self {
        Self {
            ty: &bp.r#type,
            namespace: bp.namespace.as_deref(),
            name: &bp.name,
        }
    }

    fn as_condition(&self) -> Condition {
        let mut cond = Condition::all()
            .add(base_purl::Column::Type.eq(self.ty))
            .add(base_purl::Column::Name.eq(self.name));
        if let Some(ns) = self.namespace {
            cond = cond.add(base_purl::Column::Namespace.eq(ns));
        } else {
            cond = cond.add(base_purl::Column::Namespace.is_null());
        }
        cond
    }
}

/// A user-supplied PURL paired with its parsed semver version for version comparison.
struct InputPurl {
    purl: Purl,
    input_version: semver::Version,
}

impl InputPurl {
    fn try_from_purl(purl: &Purl) -> Option<Self> {
        let input_version_str = purl.version.as_ref()?;
        let input_version = lenient_semver::parse(input_version_str)
            .inspect_err(|_| {
                tracing::debug!(
                    "input purl {} version {:?} failed to parse",
                    purl,
                    input_version_str
                );
            })
            .ok()?;
        Some(Self {
            purl: purl.clone(),
            input_version,
        })
    }
}

pub struct PurlService {
    cache: PaginationCache,
    recommend_patterns: Vec<Regex>,
    pub(crate) report_package_limit: u64,
}

impl PurlService {
    pub fn new(cache: PaginationCache) -> Self {
        Self {
            cache,
            recommend_patterns: vec![],
            report_package_limit: 10_000,
        }
    }

    pub fn with_default_patterns(self) -> Self {
        Self {
            recommend_patterns: Self::default_recommend_patterns(),
            ..self
        }
    }

    pub fn with_recommend_patterns(self, patterns: Vec<Regex>) -> Self {
        Self {
            recommend_patterns: patterns,
            ..self
        }
    }

    /// Returns the configured recommend patterns.
    pub fn recommend_patterns(&self) -> &[Regex] {
        &self.recommend_patterns
    }

    /// Sets the maximum total package count allowed for a recommendation report request.
    pub fn with_report_package_limit(self, limit: u64) -> Self {
        Self {
            report_package_limit: limit,
            ..self
        }
    }

    /// Default recommend patterns for vendor rebuilds.
    ///
    /// Matches both dot-separated (`3.0.3.redhat-00002`) and hyphen-separated (`0.14.1-redhat-00001`) vendor rebuilds.
    /// `expect` is safe: the regex is a hardcoded literal known to be valid at compile time.
    #[allow(clippy::expect_used)]
    pub fn default_recommend_patterns() -> Vec<Regex> {
        vec![Regex::new(r"^(.+)[.-]redhat-[0-9]+$").expect("valid default pattern")]
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
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

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn base_purls_by_type<C: ConnectionTrait>(
        &self,
        r#type: &str,
        query: Query,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let limiter = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(r#type))
            .filtering(query)?
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&items).await?,
            total,
        })
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
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

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
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

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
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

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
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

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
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

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
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

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
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
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let limiter = base_purl::Entity::find().filtering(query)?.limiting(
            connection,
            paginated,
            &self.cache,
        )?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&items).await?,
            total,
        })
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn purls<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: impl Pagination,
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
        if let Some(license_query) = query
            .get_constraint_for_field(LICENSE)
            .map(|constraint| q(&format!("{constraint}")))
        {
            let base = || {
                sbom_node_purl_ref::Entity::find()
                    .select_only()
                    .distinct()
                    .column(sbom_node_purl_ref::Column::QualifiedPurlId)
                    .join(
                        JoinType::InnerJoin,
                        sbom_node_purl_ref::Relation::Node.def(),
                    )
                    .join(
                        JoinType::InnerJoin,
                        sbom_node::Relation::PackageLicense.def(),
                    )
            };

            // Apply as subquery filter using UNION to allow index lookups instead of a full table scan
            let mut spdx_select = base()
                .join(
                    JoinType::InnerJoin,
                    sbom_package_license::Relation::SbomLicenseExpanded.def(),
                )
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

            let cyclonedx_select = base()
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

            select =
                select.filter(qualified_purl::Column::Id.in_subquery(spdx_select.into_query()));
        }

        let limiter = select.limiting(connection, paginated, &self.cache)?;
        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        Ok(PaginatedResults {
            items: PurlSummary::from_entities(&items),
            total,
        })
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn recommend_purls<C: ConnectionTrait>(
        &self,
        purls: &[Purl],
        connection: &C,
    ) -> Result<HashMap<String, Vec<RecommendEntry>>, Error> {
        let mut recommendations = HashMap::with_capacity(purls.len());

        let input_purls: Vec<_> = purls.iter().filter_map(InputPurl::try_from_purl).collect();
        if input_purls.is_empty() {
            return Ok(recommendations);
        }

        let base_purls = Self::fetch_base_purls(&input_purls, connection).await?;
        if base_purls.is_empty() {
            for ip in &input_purls {
                recommendations.insert(ip.purl.to_string(), Vec::new());
            }
            return Ok(recommendations);
        }

        let versioned_by_base =
            Self::fetch_versioned_purls_by_base(&base_purls, connection).await?;

        let base_purl_map: HashMap<_, _> = base_purls
            .iter()
            .map(|bp| (PurlKey::from_base_purl(bp), bp))
            .collect();

        let mut winners = Vec::new();

        for ip in &input_purls {
            let key = PurlKey::from_purl(&ip.purl);
            let Some(&base) = base_purl_map.get(&key) else {
                recommendations.insert(ip.purl.to_string(), Vec::new());
                continue;
            };

            let highest = self
                .recommend_patterns
                .iter()
                .filter_map(|pattern| {
                    Self::find_highest_vendor_patch(
                        pattern,
                        &ip.input_version,
                        versioned_by_base.get(&base.id),
                    )
                })
                .max_by(|a, b| a.version.cmp(&b.version));

            if let Some(winner_vp) = highest {
                winners.push(Winner {
                    purl_string: ip.purl.to_string(),
                    versioned_purl: winner_vp,
                    base,
                });
            } else {
                recommendations.insert(ip.purl.to_string(), Vec::new());
            }
        }

        if winners.is_empty() {
            return Ok(recommendations);
        }

        // Match every winner against its own literal version, including synthetic winners.
        let statuses_by_vp = Self::fetch_vulnerability_statuses(
            winners.iter().map(|winner| {
                (
                    winner.base.id,
                    winner.versioned_purl.version.as_str(),
                    winner.versioned_purl.id,
                )
            }),
            connection,
        )
        .await?;

        // Assemble recommendations from per-winner statuses
        for winner in winners {
            let entry = Self::assemble_recommend_entry(&winner, &statuses_by_vp);
            recommendations.insert(winner.purl_string, vec![entry]);
        }

        Ok(recommendations)
    }

    /// Batch-loads statuses keyed by each winner's versioned PURL ID.
    ///
    /// Winners yield `(base_purl_id, version, versioned_purl_id)`. A chunked inline VALUES
    /// table matches each literal version independently, without requiring a persisted row.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn fetch_vulnerability_statuses<'a, C: ConnectionTrait>(
        winners: impl IntoIterator<Item = (Uuid, &'a str, Uuid)>,
        connection: &C,
    ) -> Result<HashMap<Uuid, Vec<StatusInfo>>, Error> {
        // Postgres names the columns of an aliased VALUES list column1, column2, ...
        let winners_table = Alias::new("recommend_winner");
        let winner_base_purl_id = Expr::col((winners_table.clone(), Alias::new("column1")));
        let winner_version = Expr::col((winners_table.clone(), Alias::new("column2")));
        let winner_versioned_purl_id = Expr::col((winners_table.clone(), Alias::new("column3")));
        let mut seen = HashSet::new();
        let winner_rows: Vec<ValueTuple> = winners
            .into_iter()
            .filter(|(_, _, id)| seen.insert(*id))
            .map(IntoValueTuple::into_value_tuple)
            .collect();
        let mut statuses_by_vp: HashMap<_, Vec<StatusInfo>> = HashMap::new();

        // Each winner binds three values. Select only status columns and the unique
        // winner alias: selecting version_range.id would overwrite remediation's status ID.
        for chunk in chunked_with(3, winner_rows) {
            let mut query = purl_status::Entity::find()
                .column_as(winner_versioned_purl_id.clone(), "winner_versioned_purl_id")
                .left_join(version_range::Entity);
            QueryTrait::query(&mut query)
                .join(
                    InnerJoin,
                    TableRef::ValuesList(chunk, winners_table.clone().into_iden()),
                    winner_base_purl_id
                        .clone()
                        .equals((purl_status::Entity, purl_status::Column::BasePurlId)),
                )
                .and_where(SimpleExpr::FunctionCall(
                    Func::cust(VersionMatches)
                        .arg(winner_version.clone())
                        .arg(Expr::col((version_range::Entity, Asterisk))),
                ));
            let all_statuses = query
                .into_model::<WinnerPurlStatus>()
                .all(connection)
                .instrument(info_span!("querying purl statuses"))
                .await?;

            for (winner_id, infos) in
                Self::load_status_infos_by_winner(all_statuses, connection).await?
            {
                statuses_by_vp.entry(winner_id).or_default().extend(infos);
            }
        }

        Ok(statuses_by_vp)
    }

    /// Loads status associations grouped by the exact winner each status matched.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn load_status_infos_by_winner<C: ConnectionTrait>(
        all_statuses: Vec<WinnerPurlStatus>,
        connection: &C,
    ) -> Result<HashMap<Uuid, Vec<StatusInfo>>, Error> {
        let mut statuses_by_vp: HashMap<_, Vec<StatusInfo>> = HashMap::new();
        let mut ranges_by_id = HashMap::<Uuid, Arc<version_range::Model>>::new();
        // Winner chunking bounds the VALUES query, not the number of matching statuses.
        // Each load_one relation binds one distinct key per status at most; chunk rows
        // as well so even disjoint high-cardinality winners stay within the bind limit.
        for batch in chunked_with(1, all_statuses) {
            let status_models = batch
                .iter()
                .map(|row| row.status.clone())
                .collect::<Vec<_>>();
            let vulns = status_models
                .load_one(vulnerability::Entity, connection)
                .instrument(info_span!("loading vulnerabilities"))
                .await?;
            let advisories_loaded = status_models
                .load_one(advisory::Entity, connection)
                .instrument(info_span!("loading advisories"))
                .await?;
            let loaded_statuses = status_models
                .load_one(status::Entity, connection)
                .instrument(info_span!("loading statuses"))
                .await?;
            let needed_ranges = status_models
                .iter()
                .map(|status| status.version_range_id)
                .filter(|id| !ranges_by_id.contains_key(id))
                .collect::<HashSet<_>>();
            if !needed_ranges.is_empty() {
                ranges_by_id.extend(
                    version_range::Entity::find()
                        .filter(version_range::Column::Id.is_in(needed_ranges))
                        .all(connection)
                        .await?
                        .into_iter()
                        .map(|range| (range.id, Arc::new(range))),
                );
            }
            let issuer_ids = advisories_loaded
                .iter()
                .flatten()
                .filter_map(|advisory| advisory.issuer_id)
                .collect::<HashSet<_>>();
            let issuers = organization::Entity::find()
                .filter(organization::Column::Id.is_in(issuer_ids))
                .all(connection)
                .await?
                .into_iter()
                .map(|issuer| (issuer.id, issuer.name))
                .collect::<HashMap<_, _>>();
            let status_slug_map = loaded_statuses
                .into_iter()
                .flatten()
                .map(|s| (s.id, s.slug))
                .collect::<HashMap<_, _>>();
            let remediations = Self::load_remediations(&status_models, connection).await?;

            for (((vuln, advisory), ps), rems) in vulns
                .into_iter()
                .zip(advisories_loaded)
                .zip(batch)
                .zip(remediations)
            {
                let range = ranges_by_id.get(&ps.status.version_range_id).cloned();
                if let (Some(v), Some(advisory), Some(range)) = (vuln, advisory, range) {
                    // Republished advisories retain superseded status rows under the same
                    // identifier. Only the current revision is eligible for recommendations.
                    if advisory.deprecated {
                        continue;
                    }
                    let slug = status_slug_map
                        .get(&ps.status.status_id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    let provider = report::ProviderIdentity::from_advisory(
                        &advisory,
                        advisory
                            .issuer_id
                            .and_then(|id| issuers.get(&id))
                            .map(String::as_str),
                    );
                    let csaf = advisory
                        .labels
                        .get("type")
                        .is_some_and(|value| value == "csaf");
                    statuses_by_vp
                        .entry(ps.winner_versioned_purl_id)
                        .or_default()
                        .push(StatusInfo {
                            vuln_id: v.id,
                            status_slug: slug,
                            remediations: rems,
                            source_id: ps.status.id,
                            status_id: ps.status.status_id,
                            advisory_pk: advisory.id,
                            context_cpe_id: ps.status.context_cpe_id,
                            range,
                            provider,
                            csaf,
                            advisory_id: Some(advisory.identifier),
                        });
                }
            }
        }

        Ok(statuses_by_vp)
    }

    /// Loads the remediations of each status row, in input order.
    ///
    /// Replaces `load_many_to_many`, whose second query binds every distinct remediation ID at
    /// once; both lookups here are chunked to stay within Postgres bind parameter limits.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn load_remediations<C: ConnectionTrait>(
        statuses: &[purl_status::Model],
        connection: &C,
    ) -> Result<Vec<Vec<remediation::Model>>, Error> {
        let mut remediation_ids_by_status = HashMap::<_, Vec<_>>::new();
        // Within this invocation, load each ranged status's associations only once,
        // even when repeated IDs would otherwise span several bind-parameter chunks.
        let status_ids = statuses
            .iter()
            .map(|status| status.id)
            .collect::<HashSet<_>>();
        for status_ids in chunked_with(1, status_ids) {
            let associations = remediation_purl_status::Entity::find()
                .filter(remediation_purl_status::Column::PurlStatusId.is_in(status_ids))
                .all(connection)
                .instrument(info_span!("loading remediation associations"))
                .await?;
            for association in associations {
                remediation_ids_by_status
                    .entry(association.purl_status_id)
                    .or_default()
                    .push(association.remediation_id);
            }
        }

        let remediation_ids = remediation_ids_by_status
            .values()
            .flatten()
            .copied()
            .collect::<HashSet<_>>();
        let mut remediations_by_id = HashMap::with_capacity(remediation_ids.len());
        for remediation_ids in chunked_with(1, remediation_ids) {
            let remediations = remediation::Entity::find()
                .filter(remediation::Column::Id.is_in(remediation_ids))
                .all(connection)
                .instrument(info_span!("loading remediations"))
                .await?;
            remediations_by_id.extend(remediations.into_iter().map(|r| (r.id, r)));
        }

        Ok(statuses
            .iter()
            .map(|status| {
                remediation_ids_by_status
                    .get(&status.id)
                    .into_iter()
                    .flatten()
                    .filter_map(|id| remediations_by_id.get(id).cloned())
                    .collect()
            })
            .collect())
    }

    /// Builds a single recommendation entry from a winner and its vulnerability statuses.
    ///
    /// Returns the versioned PURL (without qualifiers) as the recommended package string.
    /// Qualifiers are context-dependent (arch, repository_url, type) and the system cannot
    /// know which qualifiers match the caller's environment.
    fn assemble_recommend_entry(
        winner: &Winner<'_>,
        statuses_by_vp: &HashMap<Uuid, Vec<StatusInfo>>,
    ) -> RecommendEntry {
        let package_str = Purl {
            ty: winner.base.r#type.clone(),
            namespace: winner.base.namespace.clone(),
            name: winner.base.name.clone(),
            version: Some(winner.versioned_purl.version.clone()),
            qualifiers: Default::default(),
        }
        .to_string();

        // Preserve conflicting sources and statuses, collapsing only identical assessments
        // repeated under different product contexts. Sort first for deterministic responses.
        let mut statuses = statuses_by_vp
            .get(&winner.versioned_purl.id)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        // Generated `affected` ranges are inference, never a statement. Drop one only where the
        // same advisory, vulnerability and product context also holds a stated status for this
        // target, so conflicting sources and inferred-only findings are still reported. Two
        // passes keep generated rows from suppressing each other when several fixed versions
        // of one advisory cover the same target.
        let generated = statuses
            .iter()
            .copied()
            .filter(|status| is_generated_affected(status))
            .map(|status| status.source_id)
            .collect::<HashSet<_>>();
        let mut suppressed = HashSet::new();
        for status in statuses
            .iter()
            .copied()
            .filter(|status| generated.contains(&status.source_id))
        {
            let contradicted = statuses.iter().copied().any(|direct| {
                !generated.contains(&direct.source_id)
                    && direct.advisory_pk == status.advisory_pk
                    && direct.vuln_id == status.vuln_id
                    && direct.context_cpe_id == status.context_cpe_id
            });
            if contradicted {
                suppressed.insert(status.source_id);
            }
        }
        statuses.retain(|status| !suppressed.contains(&status.source_id));
        statuses.sort_by(|a, b| {
            (&a.vuln_id, &a.status_slug, &a.advisory_id).cmp(&(
                &b.vuln_id,
                &b.status_slug,
                &b.advisory_id,
            ))
        });

        RecommendEntry {
            package: package_str,
            vulnerabilities: statuses
                .chunk_by(|a, b| {
                    a.vuln_id == b.vuln_id
                        && a.status_slug == b.status_slug
                        && a.advisory_id == b.advisory_id
                })
                .map(|group| {
                    let info = group[0];
                    let mut remediations = group
                        .iter()
                        .flat_map(|status| RemediationSummary::from_entities(&status.remediations))
                        .collect::<Vec<_>>();
                    // Content, not database IDs or source-row order, defines equivalence.
                    // Include every projected field, including internal remediation data.
                    remediations.sort_by_cached_key(|remediation| {
                        (
                            remediation.category.clone().remediation_category_key(),
                            remediation.details.clone(),
                            remediation.url.clone(),
                            remediation.data.to_string(),
                        )
                    });
                    remediations.dedup();
                    let vex_status = match info.status_slug.as_str() {
                        "affected" => VexStatus::Affected,
                        "fixed" => VexStatus::Fixed,
                        "not_affected" => VexStatus::NotAffected,
                        "under_investigation" => VexStatus::UnderInvestigation,
                        "recommended" => VexStatus::Recommended,
                        other => VexStatus::Other(other.to_string()),
                    };
                    VulnerabilityStatus {
                        id: info.vuln_id.clone(),
                        status: Some(vex_status),
                        justification: None,
                        remediations,
                        advisory_id: info.advisory_id.clone(),
                    }
                })
                .collect(),
        }
    }

    /// Batch-fetches base PURL entities for the deduplicated set of input PURLs.
    /// Chunks the OR conditions to stay within Postgres bind parameter limits.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn fetch_base_purls<C: ConnectionTrait>(
        input_purls: &[InputPurl],
        connection: &C,
    ) -> Result<Vec<base_purl::Model>, Error> {
        let mut seen_keys = HashSet::new();
        let unique_keys: Vec<_> = input_purls
            .iter()
            .filter_map(|ip| {
                let key = PurlKey::from_purl(&ip.purl);
                seen_keys.insert(key).then_some(key)
            })
            .collect();

        let mut results = Vec::new();
        let key_chunks = chunked_with(3, unique_keys.into_iter());
        for chunk in key_chunks {
            let condition = chunk
                .iter()
                .fold(Condition::any(), |cond, key| cond.add(key.as_condition()));
            let batch = base_purl::Entity::find()
                .filter(condition)
                .all(connection)
                .await?;
            results.extend(batch);
        }
        Ok(results)
    }

    /// Loads all versioned PURLs for the given base PURLs, grouped by base PURL ID.
    /// Chunks the IN clause to stay within Postgres bind parameter limits.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn fetch_versioned_purls_by_base<C: ConnectionTrait>(
        base_purls: &[base_purl::Model],
        connection: &C,
    ) -> Result<HashMap<Uuid, Vec<versioned_purl::Model>>, Error> {
        let base_purl_ids: Vec<_> = base_purls.iter().map(|bp| bp.id).collect();

        let mut by_base: HashMap<_, Vec<_>> = HashMap::new();
        let id_chunks = chunked_with(1, base_purl_ids.into_iter());
        for chunk in id_chunks {
            let batch = versioned_purl::Entity::find()
                .filter(versioned_purl::Column::BasePurlId.is_in(chunk))
                .all(connection)
                .await?;
            for vp in batch {
                by_base.entry(vp.base_purl_id).or_default().push(vp);
            }
        }

        // Supplement with exact-version advisory entries (status `not_affected` or `fixed`).
        // In advisory-only deployments without vendor SBOMs, these purl_status rows are the
        // only source of vendor-rebuilt version strings. Using a deterministic UUID (v5 of
        // base_purl_id + version) lets the rest of the pipeline treat them uniformly.
        // Status lookup matches literal versions, so it needs no separate synthetic-ID tracking.
        Self::extend_with_advisory_versions(
            base_purls.iter().map(|bp| bp.id),
            &mut by_base,
            connection,
        )
        .await?;

        Ok(by_base)
    }

    /// Fetches exact-version `not_affected` and `fixed` purl_status entries and adds any
    /// version strings not already present in `by_base` as synthetic versioned_purl models.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn extend_with_advisory_versions<C: ConnectionTrait>(
        base_purl_ids: impl IntoIterator<Item = Uuid>,
        by_base: &mut HashMap<Uuid, Vec<versioned_purl::Model>>,
        connection: &C,
    ) -> Result<(), Error> {
        #[derive(FromQueryResult)]
        struct AdvisoryVersion {
            base_purl_id: Uuid,
            version: String,
        }

        let id_chunks = chunked_with(1, base_purl_ids.into_iter());
        for chunk in id_chunks {
            let rows: Vec<AdvisoryVersion> = purl_status::Entity::find()
                .select_only()
                .column_as(purl_status::Column::BasePurlId, "base_purl_id")
                .column_as(version_range::Column::HighVersion, "version")
                .join(InnerJoin, purl_status::Relation::Status.def())
                .join(InnerJoin, purl_status::Relation::VersionRange.def())
                .join(InnerJoin, purl_status::Relation::Advisory.def())
                .filter(advisory::Column::Deprecated.eq(false))
                .filter(status::Column::Slug.is_in(["not_affected", "fixed"]))
                .filter(purl_status::Column::BasePurlId.is_in(chunk))
                .filter(version_range::Column::HighVersion.is_not_null())
                .filter(
                    Expr::col(version_range::Column::LowVersion)
                        .eq(Expr::col(version_range::Column::HighVersion)),
                )
                .into_model::<AdvisoryVersion>()
                .all(connection)
                .await?;

            for row in rows {
                let entry = by_base.entry(row.base_purl_id).or_default();
                if entry.iter().any(|vp| vp.version == row.version) {
                    continue;
                }
                let id = Uuid::new_v5(&row.base_purl_id, row.version.as_bytes());
                entry.push(versioned_purl::Model {
                    id,
                    base_purl_id: row.base_purl_id,
                    version: row.version,
                });
            }
        }

        Ok(())
    }

    /// Selects the versioned PURL with the highest vendor version matching the input upstream version.
    ///
    /// Uses capture group 1 of `pattern` to extract the upstream base version from the vendor version
    /// string and matches it against `input_version` via semver. Among all matching vendor rebuilds,
    /// returns the one with the lexicographically highest full vendor version string (e.g. prefers
    /// `4.3.4.redhat-00002` over `4.3.4.redhat-00001`).
    fn find_highest_vendor_patch<'a>(
        pattern: &Regex,
        input_version: &semver::Version,
        versioned_purls: Option<&'a Vec<versioned_purl::Model>>,
    ) -> Option<&'a versioned_purl::Model> {
        versioned_purls?
            .iter()
            .filter_map(|vp| {
                let upstream_str = pattern.captures(&vp.version)?.get(1)?.as_str();
                let upstream = lenient_semver::parse(upstream_str)
                    .inspect_err(|_| {
                        tracing::debug!(
                            "extracted upstream version {:?} from {:?} failed to parse",
                            upstream_str,
                            vp.version
                        );
                    })
                    .ok()?;
                Some((vp, upstream))
            })
            .filter(|(_, upstream)| {
                upstream.major == input_version.major
                    && upstream.minor == input_version.minor
                    && upstream.patch == input_version.patch
            })
            .max_by(|(a, _), (b, _)| a.version.cmp(&b.version))
            .map(|(vp, _)| vp)
    }

    /// Counts the total number of PURL-to-SBOM associations for the given SBOM IDs.
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn count_sbom_packages<C: ConnectionTrait>(
        &self,
        sbom_ids: &[Uuid],
        connection: &C,
    ) -> Result<u64, Error> {
        use sea_orm::PaginatorTrait;
        Ok(sbom_node_purl_ref::Entity::find()
            .filter(sbom_node_purl_ref::Column::SbomId.is_in(sbom_ids.iter().copied()))
            .count(connection)
            .await?)
    }

    /// Generates an aggregated recommendation report for a set of SBOMs using query-time pattern matching.
    ///
    /// For each SBOM package whose upstream version can be matched to a vendor rebuild via
    /// `recommend_patterns`, the report collects: the recommended vendor PURL, associated
    /// vulnerabilities, the advisory that reported the status, and which SBOMs contain the package.
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn report_for_sboms<C: ConnectionTrait>(
        &self,
        sbom_ids: &[Uuid],
        storage: &DispatchBackend,
        connection: &C,
    ) -> Result<RecommendReportResponse, Error> {
        if sbom_ids.is_empty() {
            return Ok(RecommendReportResponse::default());
        }

        // --- Fetch SBOM names ---
        let sbom_name_map = Self::fetch_sbom_names(sbom_ids, connection).await?;

        // --- Fetch all (sbom_id, base_purl, version) rows for the requested SBOMs ---
        let rows = Self::fetch_sbom_purl_rows(sbom_ids, connection).await?;

        if rows.is_empty() {
            let sboms = sbom_ids
                .iter()
                .map(|id| RecommendReportSbom {
                    id: *id,
                    name: sbom_name_map.get(id).cloned().unwrap_or_default(),
                    addressable_packages: 0,
                    vulnerability_count: 0,
                })
                .collect();
            return Ok(RecommendReportResponse {
                sboms,
                ..Default::default()
            });
        }

        // Share candidate selection by base/version, but retain nodes until verdict resolution.
        let mut version_groups: HashMap<(Uuid, String), VersionGroup> = HashMap::new();
        let mut unique_base_ids: HashSet<Uuid> = HashSet::new();

        for row in &rows {
            version_groups
                .entry((row.base_purl_id, row.version.clone()))
                .or_insert_with(|| VersionGroup {
                    purl_type: row.purl_type.clone(),
                    namespace: row.purl_namespace.clone(),
                    name: row.purl_name.clone(),
                });
            unique_base_ids.insert(row.base_purl_id);
        }

        // Fetch all versioned PURLs for the relevant base PURLs to find vendor patches.
        let base_purl_ids_vec: Vec<Uuid> = unique_base_ids.into_iter().collect();
        let base_purls: Vec<base_purl::Model> = base_purl::Entity::find()
            .filter(base_purl::Column::Id.is_in(base_purl_ids_vec))
            .all(connection)
            .await?;
        let versioned_by_base =
            Self::fetch_versioned_purls_by_base(&base_purls, connection).await?;

        // Pattern-match each (base, version) to find the highest vendor patch.
        let mut winners: Vec<ReportWinner> = Vec::new();

        for ((base_id, version), group) in &version_groups {
            let Ok(input_version) = lenient_semver::parse(version) else {
                continue;
            };

            let highest = self
                .recommend_patterns
                .iter()
                .filter_map(|pattern| {
                    Self::find_highest_vendor_patch(
                        pattern,
                        &input_version,
                        versioned_by_base.get(base_id),
                    )
                })
                .max_by(|a, b| a.version.cmp(&b.version));

            let Some(winner_vp) = highest else {
                continue;
            };

            let upstream = Purl {
                ty: group.purl_type.clone(),
                namespace: group.namespace.clone(),
                name: group.name.clone(),
                version: Some(version.clone()),
                qualifiers: Default::default(),
            };
            let upstream_purl = upstream.to_string();

            let target_purl = Purl {
                ty: group.purl_type.clone(),
                namespace: group.namespace.clone(),
                name: group.name.clone(),
                version: Some(winner_vp.version.clone()),
                qualifiers: Default::default(),
            };
            let recommended_purl = target_purl.to_string();

            winners.push(ReportWinner {
                upstream_purl,
                target_purl,
                recommended_purl,
                base_purl_id: *base_id,
                winner_vp_id: winner_vp.id,
                winner_version: winner_vp.version.clone(),
                upstream_version: version.clone(),
            });
        }

        if winners.is_empty() {
            let sboms = sbom_ids
                .iter()
                .map(|id| RecommendReportSbom {
                    id: *id,
                    name: sbom_name_map.get(id).cloned().unwrap_or_default(),
                    addressable_packages: 0,
                    vulnerability_count: 0,
                })
                .collect();
            return Ok(RecommendReportResponse {
                sboms,
                ..Default::default()
            });
        }

        let statuses_by_vp = Self::fetch_vulnerability_statuses(
            winners.iter().map(|winner| {
                (
                    winner.base_purl_id,
                    winner.winner_version.as_str(),
                    winner.winner_vp_id,
                )
            }),
            connection,
        )
        .await?;

        let winner_by_input = winners
            .iter()
            .enumerate()
            .map(|(index, winner)| {
                (
                    (winner.base_purl_id, winner.upstream_version.as_str()),
                    index,
                )
            })
            .collect::<HashMap<_, _>>();
        // Recovery cannot affect a known-empty result when no assessment is addressing.
        let participating = rows
            .into_iter()
            .filter(|row| {
                winner_by_input
                    .get(&(row.base_purl_id, row.version.as_str()))
                    .is_some_and(|index| {
                        statuses_by_vp
                            .get(&winners[*index].winner_vp_id)
                            .into_iter()
                            .flatten()
                            .any(|info| {
                                matches!(info.status_slug.as_str(), "fixed" | "not_affected")
                            })
                    })
            })
            .collect::<Vec<_>>();
        let context =
            report::ReportContext::load(&participating, &statuses_by_vp, storage, connection)
                .await?;
        let mut contextual_winners = HashMap::<_, (BTreeSet<Uuid>, (Uuid, String))>::new();
        for row in &participating {
            if let Some(index) = winner_by_input.get(&(row.base_purl_id, row.version.as_str())) {
                let group = contextual_winners
                    .entry((*index, context.key(row.sbom_id, &row.node_id)))
                    .or_insert_with(|| (BTreeSet::new(), (row.sbom_id, row.node_id.to_string())));
                group.0.insert(row.sbom_id);
            }
        }

        // Per-SBOM accumulators for the sboms list.
        let mut sbom_addressable: HashMap<Uuid, HashSet<String>> = HashMap::new();
        let mut sbom_vulns: HashMap<Uuid, HashSet<String>> = HashMap::new();

        let mut package_rows = HashMap::<ReportPackageKey, BTreeSet<String>>::new();
        for ((index, _), (found_in, (sbom_id, node_id))) in contextual_winners {
            let winner = &winners[index];
            let statuses = statuses_by_vp
                .get(&winner.winner_vp_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let selected = context.resolve(sbom_id, &node_id, &winner.target_purl, statuses)?;
            let mut resolved_groups = HashMap::<(String, Option<String>), BTreeSet<String>>::new();
            // Negative selected outcomes have already defeated conflicting positive evidence.
            for info in selected
                .into_iter()
                .filter(|info| matches!(info.status_slug.as_str(), "fixed" | "not_affected"))
            {
                resolved_groups
                    .entry((info.status_slug.clone(), info.advisory_id.clone()))
                    .or_default()
                    .insert(info.vuln_id.clone());
            }
            for ((status, advisory_id), vulnerabilities) in resolved_groups {
                for id in &found_in {
                    sbom_addressable
                        .entry(*id)
                        .or_default()
                        .insert(winner.upstream_purl.clone());
                    sbom_vulns
                        .entry(*id)
                        .or_default()
                        .extend(vulnerabilities.iter().cloned());
                }
                let key = ReportPackageKey {
                    purl: winner.upstream_purl.clone(),
                    recommended_purl: winner.recommended_purl.clone(),
                    status,
                    advisory_id,
                    found_in: found_in.iter().copied().collect(),
                };
                package_rows.entry(key).or_default().extend(vulnerabilities);
            }
        }
        let mut package_rows = package_rows.into_iter().collect::<Vec<_>>();
        package_rows.sort_by(|(a, _), (b, _)| {
            (
                &a.purl,
                &a.advisory_id,
                &a.recommended_purl,
                &a.found_in,
                &a.status,
            )
                .cmp(&(
                    &b.purl,
                    &b.advisory_id,
                    &b.recommended_purl,
                    &b.found_in,
                    &b.status,
                ))
        });
        let packages = package_rows
            .into_iter()
            .map(|(key, vulnerabilities)| RecommendReportPackage {
                purl: key.purl,
                recommended_purl: key.recommended_purl,
                advisory_id: key.advisory_id,
                vulnerabilities: vulnerabilities.into_iter().collect(),
                found_in: key.found_in,
            })
            .collect::<Vec<_>>();

        let sboms: Vec<RecommendReportSbom> = sbom_ids
            .iter()
            .map(|id| RecommendReportSbom {
                id: *id,
                name: sbom_name_map.get(id).cloned().unwrap_or_default(),
                addressable_packages: sbom_addressable.get(id).map(|s| s.len()).unwrap_or(0),
                vulnerability_count: sbom_vulns.get(id).map(|s| s.len()).unwrap_or(0),
            })
            .collect();

        let sboms_with_recommendations =
            sboms.iter().filter(|s| s.addressable_packages > 0).count();
        let addressable_packages = packages
            .iter()
            .map(|package| package.purl.as_str())
            .collect::<HashSet<_>>()
            .len();

        Ok(RecommendReportResponse {
            impact_summary: RecommendReportImpactSummary {
                sboms_with_recommendations,
                addressable_packages,
            },
            sboms,
            packages,
        })
    }

    /// Fetches the root-node name for each of the given SBOM IDs.
    async fn fetch_sbom_names<C: ConnectionTrait>(
        sbom_ids: &[Uuid],
        connection: &C,
    ) -> Result<HashMap<Uuid, String>, Error> {
        let rows = sbom::Entity::find()
            .select_only()
            .column_as(sbom::Column::SbomId, "sbom_id")
            .column_as(sbom_node::Column::Name, "name")
            .join(JoinType::InnerJoin, sbom::Relation::SbomNode.def())
            .filter(sbom::Column::SbomId.is_in(sbom_ids.iter().copied()))
            .into_model::<SbomNameRow>()
            .all(connection)
            .await?;

        Ok(rows.into_iter().map(|r| (r.sbom_id, r.name)).collect())
    }

    /// Fetches all (sbom_id, base_purl, version) associations for the given SBOM IDs.
    async fn fetch_sbom_purl_rows<C: ConnectionTrait>(
        sbom_ids: &[Uuid],
        connection: &C,
    ) -> Result<Vec<SbomPurlRow>, Error> {
        let sources = sbom_node_purl_ref::Entity::find()
            .select_only()
            .column_as(sbom_node_purl_ref::Column::SbomId, "sbom_id")
            .column_as(source_document::Column::Size, "size")
            .join(InnerJoin, sbom_node_purl_ref::Relation::Sbom.def())
            .join(InnerJoin, sbom::Relation::SourceDocument.def())
            .filter(sbom_node_purl_ref::Column::SbomId.is_in(sbom_ids.iter().copied()))
            .distinct()
            .into_model::<ReportInputSource>()
            .all(connection)
            .await?;
        let mut input_bytes = 0usize;
        for source in sources {
            if source.size < 0 || source.size as u64 > report::MAX_SOURCE_BYTES as u64 {
                return Err(report::ReportError::Limit {
                    sbom_id: source.sbom_id,
                    reason: "report input source byte limit",
                }
                .into());
            }
            input_bytes = input_bytes.saturating_add(source.size as usize);
            if input_bytes > report::MAX_REQUEST_BYTES {
                return Err(report::ReportError::Limit {
                    sbom_id: source.sbom_id,
                    reason: "report input request byte limit",
                }
                .into());
            }
        }
        let nodes = sbom_node_purl_ref::Entity::find()
            .select_only()
            .column_as(sbom_node_purl_ref::Column::SbomId, "sbom_id")
            .column_as(sbom_node_purl_ref::Column::NodeId, "node_id")
            .column_as(sbom_node::Column::Name, "node_name")
            .column_as(sbom_package::Column::Group, "package_group")
            .column_as(sbom_package::Column::Version, "package_version")
            .column_as(
                SimpleExpr::FunctionCall(Func::cust(Alias::new("jsonb_agg")).arg(Expr::col((
                    qualified_purl::Entity,
                    qualified_purl::Column::Purl,
                )))),
                "purls",
            )
            .join(
                JoinType::InnerJoin,
                sbom_node_purl_ref::Relation::Purl.def(),
            )
            .join(JoinType::InnerJoin, sbom_node::Relation::Purl.def().rev())
            .join(JoinType::LeftJoin, sbom_node::Relation::Package.def())
            .filter(sbom_node_purl_ref::Column::SbomId.is_in(sbom_ids.iter().copied()))
            .group_by(sbom_node_purl_ref::Column::SbomId)
            .group_by(sbom_node_purl_ref::Column::NodeId)
            .group_by(sbom_node::Column::SbomId)
            .group_by(sbom_node::Column::NodeId)
            .group_by(sbom_package::Column::SbomId)
            .group_by(sbom_package::Column::NodeId)
            .into_model::<SbomPurlNodeRow>()
            .all(connection)
            .await?;
        let mut rows = Vec::new();
        let mut projected = 0usize;
        for node in nodes {
            projected = projected
                .saturating_add(node.node_id.len())
                .saturating_add(node.node_name.len())
                .saturating_add(node.package_group.as_ref().map_or(0, String::len))
                .saturating_add(node.package_version.as_ref().map_or(0, String::len));
            let purls: Vec<CanonicalPurl> =
                serde_json::from_value(node.purls).map_err(|err| Error::Data(err.to_string()))?;
            for purl in &purls {
                let bytes = purl.ty.len()
                    + purl.namespace.as_ref().map_or(0, String::len)
                    + purl.name.len()
                    + purl.version.as_ref().map_or(0, String::len)
                    + purl
                        .qualifiers
                        .iter()
                        .map(|(key, value)| key.len() + value.len() + 64)
                        .sum::<usize>();
                projected = projected
                    .saturating_add(bytes.saturating_mul(6))
                    .saturating_add(size_of::<SbomPurlRow>());
            }
            if projected > report::MAX_REQUEST_BYTES {
                return Err(report::ReportError::Limit {
                    sbom_id: node.sbom_id,
                    reason: "projected report metadata byte limit",
                }
                .into());
            }
            let node_id: Arc<str> = node.node_id.into();
            let node_name: Arc<str> = node.node_name.into();
            let group: Option<Arc<str>> = node.package_group.map(Arc::from);
            let version: Option<Arc<str>> = node.package_version.map(Arc::from);
            let node_purls = Arc::new(purls.iter().cloned().map(Purl::from).collect::<Vec<_>>());
            for purl in purls {
                let parsed = Purl::from(purl.clone());
                rows.push(SbomPurlRow {
                    sbom_id: node.sbom_id,
                    node_id: node_id.clone(),
                    node_name: node_name.clone(),
                    package_group: group.clone(),
                    package_version: version.clone(),
                    node_purls: node_purls.clone(),
                    base_purl_id: parsed.package_uuid(),
                    version: parsed.version.clone().unwrap_or_default(),
                    purl_type: parsed.ty,
                    purl_namespace: parsed.namespace,
                    purl_name: parsed.name,
                });
            }
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod test;
