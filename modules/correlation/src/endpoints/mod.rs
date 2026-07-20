#[cfg(test)]
mod test;

use crate::service::{CorrelationService, hydrate};
use actix_web::{HttpResponse, Responder, get, post, web};
use regex::Regex;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter, QuerySelect,
    RelationTrait, SelectColumns,
};
use sea_query::JoinType;
use serde_qs::actix::QsQuery;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::LazyLock;
use tracing::instrument;
use trustify_auth::{
    Permission, ReadAdvisory, ReadSbom,
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require},
    utoipa::AuthResponse,
};
use trustify_common::db;
use trustify_common::db::chunk::chunked_with;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::db::query::Query;
use trustify_common::id::IdError;
use trustify_common::memo::Memo;
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_common::purl::Purl;
use trustify_common::requested_field::BoolRequestedField;
use trustify_common::requested_field::RequestedField;
use trustify_entity::{
    advisory_vulnerability, advisory_vulnerability_score, base_purl, qualified_purl,
    sbom_license_expanded, sbom_node, sbom_node_purl_ref, sbom_package_license, versioned_purl,
    vulnerability,
};
use trustify_module_fundamental::common::LicenseInfo;
use trustify_module_fundamental::common::license_filtering::license_text_coalesce;
use trustify_module_fundamental::common::model::ScoredVector;
use trustify_module_fundamental::purl::model::details::purl::{PurlDetails, PurlLicenseResult};
use trustify_module_fundamental::purl::model::{
    BasePurlHead, PurlHead, RecommendRequest, RecommendResponse, VersionedPurlHead,
};
use trustify_module_fundamental::sbom::model::{SbomPackageSummary, SbomSummary};
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_fundamental::sbom::service::sbom::{FetchOptions, LicenseBasicInfo};
use trustify_module_fundamental::vulnerability::model::{
    VulnerabilityDetails, VulnerabilityHead,
    analyze::{AnalysisRequest, AnalysisResponseV3},
};
use utoipa_actix_web::service_config::ServiceConfig;
use uuid::Uuid;

/// Registers in-memory correlation endpoints (replaces the SQL-based v3a path).
pub fn configure(
    config: &mut ServiceConfig,
    db: db::ReadOnly,
    correlation: CorrelationService,
    cache: PaginationCache,
) {
    let sbom_service = SbomService::new(cache);

    config
        .app_data(web::Data::new(correlation))
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(sbom_service))
        .service(get_sbom_advisories)
        .service(list_sboms)
        .service(analyze_v3)
        .service(get_purl)
        .service(get_vulnerability)
        .service(recommend)
        .service(correlation_status);
}

#[utoipa::path(
    tag = "correlation",
    operation_id = "getCorrelationSbomAdvisories",
    params(
        ("id" = Uuid, Path, description = "SBOM ID"),
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Advisories affecting this SBOM"),
        (status = 404, description = "SBOM not found"),
        (status = 503, description = "Correlation service not ready"),
    ),
)]
#[get("/v3/sbom/{id}/advisory")]
/// Find advisories affecting an SBOM using in-memory correlation.
async fn get_sbom_advisories(
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<uuid::Uuid>,
    _user: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let matches = service.correlate_sbom(*id)?;
    let statuses = service.status_slugs();
    let txn = db.begin().await?;
    let advisories = hydrate::hydrate_matches(matches, &statuses, &txn).await?;

    Ok(HttpResponse::Ok().json(advisories))
}

/// List SBOMs with in-memory severity counts replacing the SQL-based advisory summary.
#[utoipa::path(
    tag = "correlation",
    operation_id = "listSboms",
    params(
        Query,
        Paginated,
        GroupFilterQuery,
        SbomListParams,
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Matching SBOMs", body = PaginatedResults<SbomSummary<SbomPackageSummary>>),
    ),
)]
#[get("/v3/sbom")]
#[allow(clippy::too_many_arguments)]
async fn list_sboms(
    sbom_service: web::Data<SbomService>,
    correlation: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(params): web::Query<SbomListParams>,
    QsQuery(group_filter): QsQuery<GroupFilterQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let tx = db.begin().await?;

    // Always fetch without advisories — we'll patch in-memory counts if requested.
    let mut options = FetchOptions::default();
    if !group_filter.group.is_empty() {
        options = options.groups(group_filter.group);
    }

    let mut result = sbom_service
        .fetch_sboms::<_, SbomPackageSummary>(search, paginated, options, &tx)
        .await?;

    if params.advisories {
        let sbom_ids: Vec<_> = result.items.iter().map(|s| s.head.id).collect();
        let counts = correlation.batch_severity_counts(&sbom_ids);

        for item in &mut result.items {
            let summary = counts.get(&item.head.id).cloned().unwrap_or_default();
            item.advisories = RequestedField::Requested(Some(summary));
        }
    }

    Ok(HttpResponse::Ok().json(result))
}

/// Analyze PURLs for known vulnerabilities using in-memory correlation.
#[utoipa::path(
    operation_id = "analyze_v3",
    tag = "correlation",
    request_body = AnalysisRequest,
    responses(
        AuthResponse,
        (status = 200, description = "Vulnerability analysis results", body = AnalysisResponseV3),
    ),
)]
#[post("/v3/vulnerability/analyze")]
async fn analyze_v3(
    correlation: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    web::Json(AnalysisRequest { purls }): web::Json<AnalysisRequest>,
    _: Require<ReadAdvisory>,
) -> actix_web::Result<impl Responder> {
    let parsed: Vec<_> = purls
        .iter()
        .filter_map(|p| Purl::try_from(p.as_str()).ok())
        .collect();

    let matches = correlation.correlate_purls(&parsed)?;
    let statuses = correlation.status_slugs();
    let tx = db.begin().await?;
    let response = hydrate::hydrate_analysis(matches, &statuses, &tx).await?;

    Ok(HttpResponse::Ok().json(response))
}

#[derive(Clone, Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct GroupFilterQuery {
    #[serde(default)]
    group: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Deserialize, utoipa::IntoParams)]
struct SbomListParams {
    /// Include advisory severity summary per SBOM.
    #[serde(default)]
    pub advisories: bool,
}

/// Retrieve PURL details with in-memory advisory correlation.
///
/// Loads PURL head/version/base/license data from the database, then replaces
/// the advisory matching with in-memory correlation results.
#[utoipa::path(
    operation_id = "getPurl",
    tag = "correlation",
    params(
        ("key" = String, Path, description = "opaque identifier for a fully-qualified PURL, or URL-encoded pURL itself")
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Details for the qualified PURL", body = PurlDetails),
        (status = 404, description = "PURL not found"),
        (status = 503, description = "Correlation service not ready"),
    ),
)]
#[get("/v3/purl/{key}")]
#[allow(clippy::too_many_arguments)]
async fn get_purl(
    correlation: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    key: web::Path<String>,
    _: Require<ReadSbom>,
) -> Result<impl Responder, crate::Error> {
    let tx = db.begin().await?;

    // Resolve qualified_purl by PURL string or UUID
    let qualified = if key.starts_with("pkg") {
        let purl = Purl::from_str(&key).map_err(|e| crate::Error::Any(e.into()))?;
        let canonical = qualified_purl::CanonicalPurl::from(purl);
        qualified_purl::Entity::find()
            .filter(qualified_purl::Column::Purl.eq(canonical))
            .one(&tx)
            .await?
    } else {
        let id =
            Uuid::from_str(&key).map_err(|e| crate::Error::Any(IdError::InvalidUuid(e).into()))?;
        qualified_purl::Entity::find_by_id(id).one(&tx).await?
    };

    let qualified = match qualified {
        Some(q) => q,
        None => return Ok(HttpResponse::NotFound().finish()),
    };

    // Resolve versioned_purl and base_purl
    let versioned = qualified
        .find_related(versioned_purl::Entity)
        .one(&tx)
        .await?
        .ok_or_else(|| crate::Error::Any(anyhow::anyhow!("underlying versioned purl missing")))?;

    let base = versioned
        .find_related(base_purl::Entity)
        .one(&tx)
        .await?
        .ok_or_else(|| crate::Error::Any(anyhow::anyhow!("underlying base purl missing")))?;

    // Build head types
    let head = PurlHead::from_entity(&base, &versioned, &qualified);
    let version = VersionedPurlHead::from_entity(&base, &versioned);
    let base_head = BasePurlHead::from_entity(&base);

    // In-memory advisory correlation
    let purl = Purl {
        ty: base.r#type.clone(),
        namespace: base.namespace.clone(),
        name: base.name.clone(),
        version: Some(versioned.version.clone()),
        qualifiers: Default::default(),
    };

    let matches = correlation.correlate_purls(&[purl])?;
    let statuses = correlation.status_slugs();

    // Get matches for the PURL we looked up (correlate_purls keys by purl string)
    let purl_matches = matches.into_values().next().unwrap_or_default();

    let advisories = hydrate::hydrate_purl_advisories(purl_matches, &statuses, &tx).await?;

    // Load licenses (same query as PurlDetails::from_entity)
    let licenses = load_purl_licenses(qualified.id, &tx).await?;

    #[allow(deprecated)]
    let details = PurlDetails {
        head,
        version,
        base: base_head,
        advisories,
        licenses,
        licenses_ref_mapping: vec![],
    };

    Ok(HttpResponse::Ok().json(details))
}

/// Loads license information for a qualified PURL.
async fn load_purl_licenses(
    qualified_purl_id: Uuid,
    connection: &impl ConnectionTrait,
) -> Result<Vec<LicenseInfo>, crate::Error> {
    let licenses = sbom_node_purl_ref::Entity::find()
        .distinct()
        .select_only()
        .column_as(license_text_coalesce(), "license_name")
        .select_column(sbom_package_license::Column::LicenseType)
        .filter(sbom_node_purl_ref::Column::QualifiedPurlId.eq(qualified_purl_id))
        .join(JoinType::Join, sbom_node_purl_ref::Relation::Node.def())
        .join(JoinType::Join, sbom_node::Relation::PackageLicense.def())
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
        .into_model::<PurlLicenseResult>()
        .all(connection)
        .await?
        .iter()
        .map(|r| {
            LicenseInfo::from(LicenseBasicInfo {
                license_name: r.license_name.clone(),
                license_type: r.license_type,
            })
        })
        .collect();

    Ok(licenses)
}

#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Deserialize, utoipa::IntoParams)]
struct VulnerabilityGetParams {
    /// Include the full scores array from the advisory that contributed the base_score.
    #[serde(default)]
    pub scores: bool,
}

/// Retrieve vulnerability details using in-memory correlation and DB hydration.
///
/// Loads the vulnerability entity from the database, uses in-memory correlation
/// to identify affected SBOMs, then hydrates the response from the database.
#[utoipa::path(
    operation_id = "getVulnerability",
    tag = "correlation",
    params(
        ("id", Path, description = "ID of the vulnerability"),
        VulnerabilityGetParams,
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Specified vulnerability", body = VulnerabilityDetails),
        (status = 404, description = "The vulnerability could not be found"),
        (status = 503, description = "Correlation service not ready"),
    ),
)]
#[get("/v3/vulnerability/{id}")]
async fn get_vulnerability(
    correlation: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    web::Query(VulnerabilityGetParams {
        scores: include_scores,
    }): web::Query<VulnerabilityGetParams>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, crate::Error> {
    let tx = db.begin().await?;

    // Load vulnerability from DB
    let vuln = vulnerability::Entity::find_by_id(&*id).one(&tx).await?;

    let Some(vuln) = vuln else {
        return Ok(HttpResponse::NotFound().finish());
    };

    // Load advisory_vulnerabilities and scores from DB
    let (advisory_vulns, vuln_scores) = tokio::try_join!(
        advisory_vulnerability::Entity::find()
            .filter(advisory_vulnerability::Column::VulnerabilityId.eq(&*id))
            .all(&tx),
        advisory_vulnerability_score::Entity::find()
            .filter(advisory_vulnerability_score::Column::VulnerabilityId.eq(&*id))
            .all(&tx),
    )?;

    // In-memory correlation for SBOM matches
    let matches = correlation.correlate_vulnerability(&id)?;
    let vuln_entries = correlation.vulnerability_entries(&id);
    let statuses = correlation.status_slugs();

    // Hydrate from DB
    let advisories = hydrate::hydrate_vulnerability_advisories(
        &vuln,
        &advisory_vulns,
        &vuln_scores,
        matches,
        &vuln_entries,
        &statuses,
        &tx,
    )
    .await?;

    let head = VulnerabilityHead::from_vulnerability_entity(&vuln, Memo::NotProvided, &tx).await?;

    // Build authoritative scores from DB when requested
    let authoritative_scores = include_scores.then_requested(|| {
        vuln.authoritative_advisory_id.map(|advisory_id| {
            vuln_scores
                .iter()
                .filter(|s| s.advisory_id == advisory_id)
                .map(|s| ScoredVector::from(s.clone()))
                .collect()
        })
    });

    let details = VulnerabilityDetails {
        head,
        advisories,
        scores: authoritative_scores,
    };

    Ok(HttpResponse::Ok().json(details))
}

/// Recommend Red Hat patched versions using in-memory correlation.
///
/// Finds the highest Red Hat patch version for each input PURL (same major.minor.patch
/// with a `redhat-NNNNN` suffix), then uses in-memory correlation to determine
/// which vulnerabilities affect those patched versions.
#[utoipa::path(
    operation_id = "recommend",
    tag = "correlation",
    request_body = RecommendRequest,
    responses(
        AuthResponse,
        (status = 200, description = "Recommendations and remediations for provided PURLs", body = RecommendResponse),
        (status = 503, description = "Correlation service not ready"),
    ),
)]
#[post("/v3/purl/recommend")]
async fn recommend(
    correlation: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    web::Json(RecommendRequest { purls }): web::Json<RecommendRequest>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, crate::Error> {
    let tx = db.begin().await?;

    let input_purls: Vec<_> = purls.iter().filter_map(parse_input_purl).collect();
    if input_purls.is_empty() {
        return Ok(HttpResponse::Ok().json(RecommendResponse::default()));
    }

    let base_purls = fetch_base_purls(&input_purls, &tx).await?;
    if base_purls.is_empty() {
        let mut recommendations = HashMap::with_capacity(input_purls.len());
        for ip in &input_purls {
            recommendations.insert(ip.purl.to_string(), Vec::new());
        }
        return Ok(HttpResponse::Ok().json(RecommendResponse { recommendations }));
    }

    let versioned_by_base = fetch_versioned_purls_by_base(&base_purls, &tx).await?;

    let base_purl_map: HashMap<_, _> = base_purls
        .iter()
        .map(|bp| {
            (
                (
                    bp.r#type.as_str(),
                    bp.namespace.as_deref(),
                    bp.name.as_str(),
                ),
                bp,
            )
        })
        .collect();

    static REDHAT_PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("redhat-[0-9]+$").unwrap_or_else(|_| unreachable!()));
    let pattern = &*REDHAT_PATTERN;

    let mut recommendations = HashMap::with_capacity(input_purls.len());
    let mut winner_purls = Vec::new();
    let mut winner_purl_strings = Vec::new();

    for ip in &input_purls {
        let key = (
            ip.purl.ty.as_str(),
            ip.purl.namespace.as_deref(),
            ip.purl.name.as_str(),
        );
        let Some(&base) = base_purl_map.get(&key) else {
            recommendations.insert(ip.purl.to_string(), Vec::new());
            continue;
        };

        let highest =
            find_highest_redhat_patch(pattern, &ip.input_version, versioned_by_base.get(&base.id));

        if let Some(winner_vp) = highest {
            let winner_purl = Purl {
                ty: base.r#type.clone(),
                namespace: base.namespace.clone(),
                name: base.name.clone(),
                version: Some(winner_vp.version.clone()),
                qualifiers: Default::default(),
            };
            let winner_purl_string = winner_purl.to_string();
            winner_purls.push((ip.purl.to_string(), winner_purl));
            winner_purl_strings.push(winner_purl_string);
        } else {
            recommendations.insert(ip.purl.to_string(), Vec::new());
        }
    }

    if winner_purls.is_empty() {
        return Ok(HttpResponse::Ok().json(RecommendResponse { recommendations }));
    }

    // Correlate winner PURLs in-memory
    let purl_refs: Vec<_> = winner_purls.iter().map(|(_, p)| p.clone()).collect();
    let matches = correlation.correlate_purls(&purl_refs)?;

    // Remap from winner PURL strings to input PURL strings
    let winner_to_input: HashMap<String, String> = winner_purls
        .iter()
        .map(|(input, winner)| (winner.to_string(), input.clone()))
        .collect();

    let mut matches_by_input: HashMap<String, Vec<_>> = HashMap::new();
    for (winner_str, match_vec) in matches {
        let input_str = winner_to_input
            .get(&winner_str)
            .cloned()
            .unwrap_or(winner_str.clone());
        // Keep the winner purl string as the package name in the entry
        matches_by_input
            .entry(input_str)
            .or_default()
            .extend(match_vec);
    }

    let statuses = correlation.status_slugs();

    // Build a separate map for hydration keyed by winner PURL string
    let mut hydration_matches = HashMap::new();
    for (input_str, match_vec) in &matches_by_input {
        let winner_str = winner_purls
            .iter()
            .find(|(inp, _)| inp == input_str)
            .map(|(_, w)| w.to_string())
            .unwrap_or_default();
        hydration_matches.insert(winner_str, match_vec.clone());
    }

    let mut hydrated =
        hydrate::hydrate_recommend_matches(hydration_matches, &statuses, &tx).await?;

    // Map hydrated results back to input PURL strings
    for (input_str, _) in &winner_purls {
        let winner_str = winner_purls
            .iter()
            .find(|(inp, _)| inp == input_str)
            .map(|(_, w)| w.to_string())
            .unwrap_or_default();
        let entries = hydrated.remove(&winner_str).unwrap_or_default();
        recommendations.insert(input_str.clone(), entries);
    }

    Ok(HttpResponse::Ok().json(RecommendResponse { recommendations }))
}

/// A user-supplied PURL paired with its parsed semver version for version comparison.
struct InputPurl {
    purl: Purl,
    input_version: semver::Version,
}

/// Parses a PURL into an InputPurl if it has a valid semver version.
fn parse_input_purl(purl: &Purl) -> Option<InputPurl> {
    let version_str = purl.version.as_ref()?;
    let input_version = lenient_semver::parse(version_str)
        .inspect_err(|_| {
            tracing::debug!(
                "input purl {} version {:?} failed to parse",
                purl,
                version_str
            );
        })
        .ok()?;
    Some(InputPurl {
        purl: purl.clone(),
        input_version,
    })
}

/// Batch-fetches base PURL entities matching the deduplicated set of input PURLs.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
async fn fetch_base_purls(
    input_purls: &[InputPurl],
    connection: &impl ConnectionTrait,
) -> Result<Vec<base_purl::Model>, crate::Error> {
    let mut seen_keys = HashSet::new();
    let mut unique_conditions = Vec::new();

    for ip in input_purls {
        let key = (
            ip.purl.ty.clone(),
            ip.purl.namespace.clone(),
            ip.purl.name.clone(),
        );
        if seen_keys.insert(key) {
            let mut cond = Condition::all()
                .add(base_purl::Column::Type.eq(&ip.purl.ty))
                .add(base_purl::Column::Name.eq(&ip.purl.name));
            if let Some(ns) = &ip.purl.namespace {
                cond = cond.add(base_purl::Column::Namespace.eq(ns));
            } else {
                cond = cond.add(base_purl::Column::Namespace.is_null());
            }
            unique_conditions.push(cond);
        }
    }

    let mut results = Vec::new();
    let chunks = chunked_with(3, unique_conditions.into_iter());
    for chunk in &chunks {
        let chunk: Vec<_> = chunk.collect();
        let condition = chunk
            .into_iter()
            .fold(Condition::any(), |c, cond| c.add(cond));
        let batch = base_purl::Entity::find()
            .filter(condition)
            .all(connection)
            .await?;
        results.extend(batch);
    }
    Ok(results)
}

/// Loads all versioned PURLs for the given base PURLs, grouped by base PURL ID.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
async fn fetch_versioned_purls_by_base(
    base_purls: &[base_purl::Model],
    connection: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, Vec<versioned_purl::Model>>, crate::Error> {
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
                    tracing::debug!("purl version {:?} failed to parse", vp.version);
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

#[utoipa::path(
    tag = "correlation",
    operation_id = "getCorrelationStatus",
    responses(
        AuthResponse,
        (status = 200, description = "Correlation service status"),
    ),
)]
#[get("/v3/correlation/status")]
/// Get the status of the correlation service.
async fn correlation_status(
    service: web::Data<CorrelationService>,
    _user: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let state = service.state();
    let advisory_count = state.advisory_index.by_purl.len();
    let sbom_count = state.sbom_index.by_sbom.len();
    let catalog_count = state.sbom_index.catalog.len();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "advisory_purl_keys": advisory_count,
        "sboms": sbom_count,
        "catalog_entries": catalog_count,
    })))
}
