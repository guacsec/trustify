use std::collections::{HashMap, HashSet};

use crate::{
    Error,
    common::license_filtering::LICENSE,
    purl::model::{
        RecommendEntry, VexStatus, VulnerabilityStatus,
        details::{
            base_purl::BasePurlDetails, purl::PurlDetails, versioned_purl::VersionedPurlDetails,
        },
        summary::{
            base_purl::BasePurlSummary, purl::PurlSummary, remediation::RemediationSummary,
            r#type::TypeSummary,
        },
    },
};
use itertools::Itertools;
use regex::Regex;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, FromQueryResult, LoaderTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, RelationTrait, prelude::Uuid,
};
use sea_query::{Asterisk, ColumnType, Expr, Func, JoinType, Order, SimpleExpr, UnionType};
use tracing::{Instrument, info_span, instrument};
use trustify_common::{
    db::{
        chunk::chunked_with,
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Columns, Filtering, IntoColumns, Query, q},
    },
    model::{Paginated, PaginatedResults},
    purl::{Purl, PurlErr},
};
use trustify_entity::{
    advisory, base_purl, license, purl_status,
    qualified_purl::{self, CanonicalPurl},
    remediation, remediation_purl_status, sbom_license_expanded, sbom_node, sbom_node_purl_ref,
    sbom_package_license, status, version_range, versioned_purl, vulnerability,
};
use trustify_module_ingestor::common::Deprecation;

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
    /// The most recent date from the advisory that reported this status, used to pick the
    /// latest assessment when the same vulnerability appears in multiple advisories.
    advisory_date: Option<time::OffsetDateTime>,
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
                log::debug!(
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
}

impl PurlService {
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
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
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let limiter = base_purl::Entity::find()
            .filter(base_purl::Column::Type.eq(r#type))
            .filtering(query)?
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total).await?;

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
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<BasePurlSummary>, Error> {
        let limiter = base_purl::Entity::find().filtering(query)?.limiting(
            connection,
            paginated,
            &self.cache,
        )?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total).await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&items).await?,
            total,
        })
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
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
        let total = total.requested(paginated.total).await?;

        Ok(PaginatedResults {
            items: PurlSummary::from_entities(&items),
            total,
        })
    }

    #[instrument(skip(self, connection), err)]
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

        #[allow(clippy::unwrap_used)]
        let pattern = Regex::new("redhat-[0-9]+$").unwrap();

        let mut winners = Vec::new();

        for ip in &input_purls {
            let key = PurlKey::from_purl(&ip.purl);
            let Some(&base) = base_purl_map.get(&key) else {
                recommendations.insert(ip.purl.to_string(), Vec::new());
                continue;
            };

            let highest = Self::find_highest_redhat_patch(
                &pattern,
                &ip.input_version,
                versioned_by_base.get(&base.id),
            );

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

        // Batch fetch vulnerability statuses and qualified PURLs for all winners
        let statuses_by_base = Self::fetch_vulnerability_statuses(
            winners.iter().map(|w| w.base.id).unique(),
            winners.iter().map(|w| w.versioned_purl.id),
            connection,
        )
        .await?;

        // Assemble recommendations from batched data
        for winner in winners {
            let entry = Self::assemble_recommend_entry(&winner, &statuses_by_base);
            recommendations.insert(winner.purl_string, vec![entry]);
        }

        Ok(recommendations)
    }

    /// Batch-loads vulnerability statuses for the winning versioned PURLs, grouped by base PURL ID.
    /// Chunks by base PURL IDs to stay within Postgres bind parameter limits.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn fetch_vulnerability_statuses<C: ConnectionTrait>(
        winner_base_ids: impl IntoIterator<Item = Uuid>,
        winner_vp_ids: impl IntoIterator<Item = Uuid>,
        connection: &C,
    ) -> Result<HashMap<Uuid, Vec<StatusInfo>>, Error> {
        let mut statuses_by_base: HashMap<_, Vec<StatusInfo>> = HashMap::new();
        let winner_vp_ids: Vec<_> = winner_vp_ids.into_iter().collect();

        let base_chunks = chunked_with(1, winner_base_ids.into_iter());
        for base_chunk in &base_chunks {
            let base_chunk: Vec<_> = base_chunk.collect();
            let all_statuses = purl_status::Entity::find()
                .columns([
                    version_range::Column::Id,
                    version_range::Column::LowVersion,
                    version_range::Column::LowInclusive,
                    version_range::Column::HighVersion,
                    version_range::Column::HighInclusive,
                ])
                .left_join(base_purl::Entity)
                .join(
                    JoinType::LeftJoin,
                    base_purl::Relation::VersionedPurls.def(),
                )
                .left_join(version_range::Entity)
                .filter(purl_status::Column::BasePurlId.is_in(base_chunk))
                .filter(versioned_purl::Column::Id.is_in(winner_vp_ids.iter().copied()))
                .filter(SimpleExpr::FunctionCall(
                    Func::cust(trustify_common::db::VersionMatches)
                        .arg(Expr::col(versioned_purl::Column::Version))
                        .arg(Expr::col((version_range::Entity, Asterisk))),
                ))
                .all(connection)
                .instrument(info_span!("querying purl statuses"))
                .await?;

            let vulns = all_statuses
                .load_one(vulnerability::Entity, connection)
                .instrument(info_span!("loading vulnerabilities"))
                .await?;
            let advisories_loaded = all_statuses
                .load_one(advisory::Entity, connection)
                .instrument(info_span!("loading advisories"))
                .await?;
            let status_models = all_statuses
                .load_one(status::Entity, connection)
                .instrument(info_span!("loading statuses"))
                .await?;
            let status_slug_map: HashMap<_, _> = status_models
                .into_iter()
                .flatten()
                .map(|s| (s.id, s.slug))
                .collect();
            let remediations = all_statuses
                .load_many_to_many(
                    remediation::Entity,
                    remediation_purl_status::Entity,
                    connection,
                )
                .instrument(info_span!("loading remediations"))
                .await?;

            for (((vuln, advisory), ps), rems) in vulns
                .into_iter()
                .zip(advisories_loaded)
                .zip(all_statuses)
                .zip(remediations)
            {
                if let (Some(v), Some(advisory)) = (vuln, advisory) {
                    let slug = status_slug_map
                        .get(&ps.status_id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    statuses_by_base
                        .entry(ps.base_purl_id)
                        .or_default()
                        .push(StatusInfo {
                            vuln_id: v.id,
                            status_slug: slug,
                            remediations: rems,
                            advisory_date: advisory.modified.or(advisory.published),
                        });
                }
            }
        }

        Ok(statuses_by_base)
    }

    /// Builds a single recommendation entry from a winner and its vulnerability statuses.
    ///
    /// Returns the versioned PURL (without qualifiers) as the recommended package string.
    /// Qualifiers are context-dependent (arch, repository_url, type) and the system cannot
    /// know which qualifiers match the caller's environment.
    fn assemble_recommend_entry(
        winner: &Winner<'_>,
        statuses_by_base: &HashMap<Uuid, Vec<StatusInfo>>,
    ) -> RecommendEntry {
        let package_str = Purl {
            ty: winner.base.r#type.clone(),
            namespace: winner.base.namespace.clone(),
            name: winner.base.name.clone(),
            version: Some(winner.versioned_purl.version.clone()),
            qualifiers: Default::default(),
        }
        .to_string();

        // When the same vulnerability appears in multiple advisories with different statuses,
        // keep the one from the most recent advisory so that newer assessments (e.g. "fixed")
        // take precedence over older ones (e.g. "affected").
        let mut best_by_vuln: HashMap<&str, &StatusInfo> = HashMap::new();
        for info in statuses_by_base.get(&winner.base.id).into_iter().flatten() {
            best_by_vuln
                .entry(&info.vuln_id)
                .and_modify(|existing| {
                    if info.advisory_date > existing.advisory_date {
                        *existing = info;
                    }
                })
                .or_insert(info);
        }

        RecommendEntry {
            package: package_str,
            vulnerabilities: best_by_vuln
                .into_values()
                .map(|info| {
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
                        remediations: RemediationSummary::from_entities(&info.remediations),
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
        for chunk in &key_chunks {
            let chunk: Vec<_> = chunk.collect();
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
        for chunk in &id_chunks {
            let chunk: Vec<_> = chunk.collect();
            let batch = versioned_purl::Entity::find()
                .filter(versioned_purl::Column::BasePurlId.is_in(chunk))
                .all(connection)
                .await?;
            for vp in batch {
                by_base.entry(vp.base_purl_id).or_default().push(vp);
            }
        }
        Ok(by_base)
    }

    /// Selects the versioned PURL with the highest Red Hat pre-release suffix matching the input version.
    fn find_highest_redhat_patch<'a>(
        pattern: &Regex,
        input_version: &semver::Version,
        versioned_purls: Option<&'a Vec<versioned_purl::Model>>,
    ) -> Option<&'a versioned_purl::Model> {
        versioned_purls?
            .iter()
            .filter(|vp| pattern.is_match(&vp.version))
            .filter_map(|vp| {
                lenient_semver::parse(&vp.version)
                    .inspect_err(|_| {
                        log::debug!("purl version {:?} failed to parse", vp.version);
                    })
                    .ok()
                    .map(|v| (vp, v))
            })
            .filter(|(_, version)| {
                version.major == input_version.major
                    && version.minor == input_version.minor
                    && version.patch == input_version.patch
            })
            .max_by(|(_, a), (_, b)| a.pre.cmp(&b.pre))
            .map(|(vp, _)| vp)
    }
}

#[cfg(test)]
mod test;
