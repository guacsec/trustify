use std::collections::{HashMap, HashSet};

use crate::{
    Error,
    common::license_filtering::LICENSE,
    purl::model::{
        RecommendEntry, VulnerabilityStatus,
        details::{
            base_purl::BasePurlDetails, purl::PurlDetails, versioned_purl::VersionedPurlDetails,
        },
        summary::{base_purl::BasePurlSummary, purl::PurlSummary, r#type::TypeSummary},
    },
};
use itertools::Itertools;
use regex::Regex;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, RelationTrait, prelude::Uuid,
};
use sea_query::{ColumnType, JoinType, Order, UnionType};
use tracing::instrument;
use trustify_common::{
    db::{
        limiter::LimiterTrait,
        query::{Columns, Filtering, IntoColumns, Query, q},
    },
    model::{Paginated, PaginatedResults},
    purl::{Purl, PurlErr},
};
use trustify_entity::{
    base_purl, license,
    qualified_purl::{self, CanonicalPurl},
    sbom_license_expanded, sbom_node, sbom_node_purl_ref, sbom_package_license, versioned_purl,
};
use trustify_module_ingestor::common::Deprecation;

#[derive(Clone, PartialEq, Eq, Hash)]
struct PurlKey {
    ty: String,
    namespace: Option<String>,
    name: String,
}

impl PurlKey {
    fn from_purl(purl: &Purl) -> Self {
        Self {
            ty: purl.ty.clone(),
            namespace: purl.namespace.clone(),
            name: purl.name.clone(),
        }
    }

    fn from_base_purl(bp: &base_purl::Model) -> Self {
        Self {
            ty: bp.r#type.clone(),
            namespace: bp.namespace.clone(),
            name: bp.name.clone(),
        }
    }

    fn as_condition(&self) -> Condition {
        let mut cond = Condition::all()
            .add(base_purl::Column::Type.eq(&self.ty))
            .add(base_purl::Column::Name.eq(&self.name));
        if let Some(ns) = &self.namespace {
            cond = cond.add(base_purl::Column::Namespace.eq(ns));
        } else {
            cond = cond.add(base_purl::Column::Namespace.is_null());
        }
        cond
    }
}

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

#[derive(Default)]
pub struct PurlService {}

impl PurlService {
    pub fn new() -> Self {
        Self {}
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
            .limiting(connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&limiter.fetch().await?).await?,
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
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: BasePurlSummary::from_entities(&limiter.fetch().await?).await?,
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

        let limiter = select.limiting(connection, paginated.offset, paginated.limit);
        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: PurlSummary::from_entities(&limiter.fetch().await?),
            total,
        })
    }

    #[instrument(skip(self, connection), err)]
    pub async fn recommend_purls<C: ConnectionTrait>(
        &self,
        purls: &[Purl],
        connection: &C,
    ) -> Result<HashMap<String, Vec<RecommendEntry>>, Error> {
        let mut recommendations = HashMap::new();

        let input_purls: Vec<InputPurl> =
            purls.iter().filter_map(InputPurl::try_from_purl).collect();
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

        let base_purl_map: HashMap<PurlKey, &base_purl::Model> = base_purls
            .iter()
            .map(|bp| (PurlKey::from_base_purl(bp), bp))
            .collect();

        let versioned_by_base =
            Self::fetch_versioned_purls_by_base(&base_purls, connection).await?;

        #[allow(clippy::unwrap_used)]
        let pattern = Regex::new("redhat-[0-9]+$").unwrap();

        for ip in &input_purls {
            let key = PurlKey::from_purl(&ip.purl);
            let Some(base) = base_purl_map.get(&key) else {
                recommendations.insert(ip.purl.to_string(), Vec::new());
                continue;
            };

            let highest = Self::find_highest_redhat_patch(
                &pattern,
                &ip.input_version,
                versioned_by_base.get(&base.id),
            );

            if let Some(winner_vp) = highest {
                let entry = self.build_recommend_entry(winner_vp, connection).await?;
                recommendations.insert(ip.purl.to_string(), vec![entry]);
            } else {
                recommendations.insert(ip.purl.to_string(), Vec::new());
            }
        }

        Ok(recommendations)
    }

    async fn fetch_base_purls<C: ConnectionTrait>(
        input_purls: &[InputPurl],
        connection: &C,
    ) -> Result<Vec<base_purl::Model>, Error> {
        let mut condition = Condition::any();
        let mut seen_keys: HashSet<PurlKey> = HashSet::new();
        for ip in input_purls {
            let key = PurlKey::from_purl(&ip.purl);
            if seen_keys.insert(key.clone()) {
                condition = condition.add(key.as_condition());
            }
        }
        Ok(base_purl::Entity::find()
            .filter(condition)
            .all(connection)
            .await?)
    }

    async fn fetch_versioned_purls_by_base<C: ConnectionTrait>(
        base_purls: &[base_purl::Model],
        connection: &C,
    ) -> Result<HashMap<Uuid, Vec<versioned_purl::Model>>, Error> {
        let base_purl_ids: Vec<Uuid> = base_purls.iter().map(|bp| bp.id).collect();
        let all_versioned: Vec<versioned_purl::Model> = versioned_purl::Entity::find()
            .filter(versioned_purl::Column::BasePurlId.is_in(base_purl_ids))
            .all(connection)
            .await?;

        let mut by_base: HashMap<Uuid, Vec<versioned_purl::Model>> = HashMap::new();
        for vp in all_versioned {
            by_base.entry(vp.base_purl_id).or_default().push(vp);
        }
        Ok(by_base)
    }

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

    async fn build_recommend_entry<C: ConnectionTrait>(
        &self,
        versioned_purl: &versioned_purl::Model,
        connection: &C,
    ) -> Result<RecommendEntry, Error> {
        let purl_details = self
            .versioned_purl_by_uuid(&versioned_purl.id, connection)
            .await?;

        let Some(purl_details) = purl_details else {
            return Ok(RecommendEntry {
                package: String::new(),
                vulnerabilities: Vec::new(),
            });
        };

        let package = purl_details
            .purls
            .first()
            .map(|p| p.purl.to_string())
            .unwrap_or_else(|| {
                Purl {
                    ty: purl_details.head.purl.ty.clone(),
                    namespace: purl_details.head.purl.namespace.clone(),
                    name: purl_details.head.purl.name.clone(),
                    version: purl_details.head.purl.version.clone(),
                    qualifiers: Default::default(),
                }
                .to_string()
            });

        let vulnerabilities = purl_details
            .advisories
            .iter()
            .flat_map(|advisory| &advisory.status)
            .unique_by(|status| &status.vulnerability.identifier)
            .map(|status| VulnerabilityStatus {
                id: status.vulnerability.identifier.clone(),
                status: Some(status.into()),
                justification: None,
                remediations: status.remediations.clone(),
            })
            .collect();

        Ok(RecommendEntry {
            package,
            vulnerabilities,
        })
    }
}

#[cfg(test)]
mod test;
