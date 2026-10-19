use super::value::OnInvalidData;
use crate::{
    graph::{
        Graph,
        advisory::{
            context::{AssertionContext, ContextCreator},
            cpe_assertion::{CpeAssertion, CpeAssertionCreator},
            product_status::{ProductStatus as GraphProductStatus, ProductVersionRange},
            purl_status::PurlStatus,
            vers::parse_range,
            version::{VersionInfo, VersionSpec},
        },
        cpe::CpeCreator,
        organization::creator::OrganizationCreator,
        product::ProductInformation,
        purl::creator::PurlCreator,
    },
    service::{
        Error,
        advisory::csaf::{
            product_status::ProductStatus,
            util::{ResolveProductIdCache, branch_cpe},
            value,
        },
    },
};
use csaf::schema::csaf2_0::schema::{
    CategoryOfTheBranch, CommonSecurityAdvisoryFramework as Csaf, ProductsT, RelationshipCategory,
    Remediation,
};
use sbom_walker::report::ReportSink;
use sea_orm::{ActiveEnum, ActiveValue::Set, ConnectionTrait, EntityTrait};
use sea_query::OnConflict;
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::instrument;
use trustify_common::{
    cpe::{Component, Cpe},
    db::chunk::EntityChunkedIter,
    hashing::normalize_algorithm,
    purl::Purl,
};
use trustify_entity::{
    advisory_vulnerability_hash, advisory_vulnerability_product_identifier,
    advisory_vulnerability_product_identifier::ProductIdentifierType,
    assertion_context::AssertionContextCategory,
    assertion_context_identifier::ContextIdentifierKind,
    correlation_evidence::AssertionStatus,
    organization, product, product_status, product_version_range, purl_status,
    remediation::{self, RemediationCategory},
    remediation_product_status, remediation_purl_status, version_range,
    version_scheme::{PurlType, VersionScheme},
};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ProductIdStatusMapping {
    pub purl_status_ids: Vec<Uuid>,
    pub product_status_ids: Vec<Uuid>,
}

/// Namespace of the IDs of `advisory_vulnerability_hash` rows.
const ADVISORY_HASH_NAMESPACE: Uuid = Uuid::from_bytes([
    0x91, 0x3a, 0x5d, 0x0e, 0x6b, 0x24, 0x4c, 0x7f, 0x8d, 0x12, 0xa9, 0x3e, 0x50, 0xc7, 0x1b, 0x64,
]);

/// Namespace of the IDs of `advisory_vulnerability_product_identifier` rows.
const ADVISORY_PRODUCT_IDENTIFIER_NAMESPACE: Uuid = Uuid::from_bytes([
    0x46, 0xe2, 0x08, 0xb9, 0x3c, 0x71, 0x4a, 0xd5, 0x92, 0x6f, 0x1d, 0x84, 0xe0, 0x3b, 0xa7, 0x58,
]);

/// A CPE (pattern) an advisory makes an assertion about, optionally constrained by a version
/// range, in a context.
type CpeEntry = (Cpe, Option<VersionInfo>, AssertionStatus, Option<Uuid>);

/// A file hash (algorithm, value) an advisory makes an assertion about, in a context.
type HashEntry = (String, String, AssertionStatus, Option<Uuid>);

/// A product identifier an advisory makes an assertion about, optionally constrained by the
/// versions of the identified product, in a context.
type ProductIdentifierEntry = (
    ProductIdentifierType,
    String,
    Option<VersionInfo>,
    AssertionStatus,
    Option<Uuid>,
);

#[derive(Debug)]
pub struct StatusCreator<'a> {
    cache: ResolveProductIdCache<'a>,
    advisory_id: Uuid,
    vulnerability_id: String,
    entries: HashSet<PurlStatus>,
    products: HashSet<ProductStatus>,
    product_id_to_product: HashMap<String, ProductStatus>,
    product_to_purl_statuses: HashMap<ProductStatus, Vec<PurlStatus>>,
    hash_entries: HashSet<HashEntry>,
    product_identifier_entries: HashSet<ProductIdentifierEntry>,
    cpe_entries: HashSet<CpeEntry>,
    contexts: ContextCreator,
}

impl<'a> StatusCreator<'a> {
    pub fn new(csaf: &'a Csaf, advisory_id: Uuid, vulnerability_identifier: String) -> Self {
        let cache = ResolveProductIdCache::new(csaf);
        Self {
            cache,
            advisory_id,
            vulnerability_id: vulnerability_identifier,
            entries: HashSet::new(),
            products: HashSet::new(),
            product_id_to_product: HashMap::new(),
            product_to_purl_statuses: HashMap::new(),
            hash_entries: HashSet::new(),
            product_identifier_entries: HashSet::new(),
            cpe_entries: HashSet::new(),
            contexts: ContextCreator::new(),
        }
    }

    pub fn add_all(
        &mut self,
        ps: &Option<ProductsT>,
        status: &'static str,
        on_invalid: OnInvalidData,
        report: &dyn ReportSink,
    ) -> Result<(), Error> {
        let assertion_status = match status {
            "affected" => Some(AssertionStatus::Affected),
            "fixed" => Some(AssertionStatus::Fixed),
            "not_affected" => Some(AssertionStatus::NotAffected),
            "under_investigation" => Some(AssertionStatus::UnderInvestigation),
            // `first_*` / `last_*` are only stored for PURLs (see `TODO.md`)
            _ => None,
        };

        for r in ps.iter().flat_map(|ps| &ps.0) {
            let mut product = ProductStatus {
                status,
                ..Default::default()
            };
            // The products to resolve, and whether each is the subject of the status: for a
            // relationship, the component is, the platform it relates to isn't.
            let parts = self.cache.parts(r);
            let context = self.context(r, &parts, on_invalid, report)?;
            product.context = context;
            for (product_id, subject) in &parts {
                let trace = self.cache.trace_product(product_id);
                if trace.is_empty() {
                    if let Some(full_name) = self.cache.definition(product_id) {
                        product.update_from_full_product_name(
                            full_name, *subject, on_invalid, report,
                        )?;
                    }
                    continue;
                }
                for branch in trace {
                    product.update_from_branch(branch, *subject, on_invalid, report)?;
                }
            }

            if let Some(assertion) = assertion_status {
                // Only the component carries the assertion, not the platform it relates to. A
                // relationship's own hashes identify a file, which is the component's. Its SKUs,
                // model and serial numbers identify hardware, which tells where the component is
                // installed, not which version of it is (CSAF 2.0, 3.1.3.3.3 and 3.1.3.3.7), so
                // those go into the context instead.
                for (product_id, _) in parts.iter().filter(|(_, subject)| *subject) {
                    let combination = self.cache.get_relationship(product_id).is_some();
                    let mut identifiers = Vec::new();
                    for pih in self.cache.helpers(product_id) {
                        for hc in &pih.hashes {
                            for fh in &hc.file_hashes {
                                let algo = normalize_algorithm(&fh.algorithm);
                                self.hash_entries.insert((
                                    algo,
                                    fh.value.to_string(),
                                    assertion,
                                    context,
                                ));
                            }
                        }
                        if combination {
                            continue;
                        }
                        identifiers.extend(
                            pih.model_numbers
                                .iter()
                                .flatten()
                                .map(|value| {
                                    (ProductIdentifierType::ModelNumber, value.to_string())
                                })
                                .chain(pih.serial_numbers.iter().flatten().map(|value| {
                                    (ProductIdentifierType::SerialNumber, value.to_string())
                                }))
                                .chain(
                                    pih.skus.iter().map(|value| {
                                        (ProductIdentifierType::Sku, value.to_string())
                                    }),
                                ),
                        );
                    }
                    if identifiers.is_empty() {
                        continue;
                    }
                    // the identifiers name the product, its versions are the ones of its branch
                    let Some(ranges) = self.version_ranges(product_id) else {
                        continue;
                    };
                    for (id_type, value) in identifiers {
                        for range in &ranges {
                            self.product_identifier_entries.insert((
                                id_type,
                                value.clone(),
                                range.clone(),
                                assertion,
                                context,
                            ));
                        }
                    }
                }

                // For a relationship, only the component carries the assertion. The platform it
                // relates to (e.g. hardware a firmware is installed on) is typically listed with
                // both affected and fixed combinations.
                for (product_id, subject) in &parts {
                    if *subject {
                        self.add_cpe_entries(product_id, assertion, context, on_invalid, report)?;
                    }
                }
            }

            self.product_id_to_product
                .insert(r.to_string(), product.clone());
            self.products.insert(product);
        }
        Ok(())
    }

    /// Collect the CPE assertions of a product.
    ///
    /// The CPE is the nearest one on the path to the product, or the one of its definition outside
    /// of branches. If its version is ANY, the version is constrained by the product's version
    /// range or version branch, which for a relationship is the one of its component.
    fn add_cpe_entries(
        &mut self,
        product_id: &str,
        assertion: AssertionStatus,
        context: Option<Uuid>,
        on_invalid: OnInvalidData,
        report: &dyn ReportSink,
    ) -> Result<(), Error> {
        let trace = self.cache.trace_product(product_id);

        let mut cpe = None;
        for branch in trace.iter().rev() {
            if let Some(found) = branch_cpe(branch, on_invalid, report)? {
                cpe = Some(found);
                break;
            }
        }
        // a product defined outside of branches carries at most its own CPE
        if trace.is_empty()
            && let Some(value) = self
                .cache
                .definition(product_id)
                .and_then(|name| name.product_identification_helper.as_ref())
                .and_then(|helper| helper.cpe.as_deref())
        {
            cpe = on_invalid.validate(value::cpe(value), report)?;
        }
        let Some(cpe) = cpe else {
            return Ok(());
        };

        // too broad, and can't be looked up
        if matches!(cpe.vendor(), Component::Any) || matches!(cpe.product(), Component::Any) {
            tracing::debug!(%cpe, "skipping CPE without vendor or product");
            return Ok(());
        }

        let ranges = if !matches!(cpe.version(), Component::Any) {
            // the CPE's own version is the constraint
            vec![None]
        } else {
            // for a relationship, the component states the version (e.g. a firmware range,
            // installed on a device which is identified by the relationship's CPE)
            match self.version_ranges(product_id) {
                Some(ranges) => ranges,
                None => return Ok(()),
            }
        };

        for range in ranges {
            self.cpe_entries
                .insert((cpe.clone(), range, assertion, context));
        }

        Ok(())
    }

    /// The versions of a product: the range or version of its version branch, which for a
    /// relationship is the one of its component. `[None]` without a version branch (all versions),
    /// `None` for a range which can't be parsed, which must never widen to all versions.
    fn version_ranges(&self, product_id: &str) -> Option<Vec<Option<VersionInfo>>> {
        let Some(leaf) = self.cache.version_branch(product_id) else {
            return Some(vec![None]);
        };
        match leaf.category {
            CategoryOfTheBranch::ProductVersionRange => match parse_range(&leaf.name) {
                Ok(infos) => Some(infos.into_iter().map(Some).collect()),
                Err(err) => {
                    tracing::debug!(
                        product_id,
                        range = leaf.name.as_str(),
                        "skipping product with invalid range: {err}"
                    );
                    None
                }
            },
            CategoryOfTheBranch::ProductVersion => Some(vec![Some(VersionInfo {
                scheme: VersionScheme::Generic,
                spec: VersionSpec::Exact(leaf.name.to_string()),
            })]),
            _ => Some(vec![None]),
        }
    }

    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn create<C: ConnectionTrait>(
        &mut self,
        graph: &Graph,
        connection: &C,
    ) -> Result<HashMap<String, ProductIdStatusMapping>, Error> {
        let mut product_status_models = Vec::new();
        let mut purls = PurlCreator::new();
        let mut cpes = CpeCreator::new();

        let mut product_models = Vec::new();
        let mut version_ranges = Vec::new();
        let mut product_version_ranges = Vec::new();

        let mut package_statuses = Vec::new();
        let product_statuses = self.products.clone();

        let mut product_to_status_uuids: HashMap<ProductStatus, ProductIdStatusMapping> =
            HashMap::new();

        // Build reverse map: (ProductStatus) -> Vec<csaf_product_id>
        let mut product_to_csaf_ids: HashMap<ProductStatus, Vec<String>> = HashMap::new();
        for (csaf_id, product) in &self.product_id_to_product {
            product_to_csaf_ids
                .entry(product.clone())
                .or_default()
                .push(csaf_id.clone());
        }

        // Batch create all organizations to prevent race conditions and deadlocks
        let mut org_creator = OrganizationCreator::new();
        let mut vendor_names = HashSet::new();

        for product in &product_statuses {
            if let Some(vendor) = &product.vendor
                && vendor_names.insert(vendor.clone())
            {
                let organization_cpe_key = product
                    .cpe
                    .as_ref()
                    .map(|cpe| cpe.vendor().as_ref().to_string());

                org_creator.add(vendor, organization_cpe_key, None);
            }
        }

        org_creator.create(connection).await?;

        // Query back all organizations and populate cache for later use
        let mut org_cache: HashMap<String, organization::Model> = HashMap::new();
        for vendor in vendor_names {
            if let Some(org_ctx) = graph.get_organization_by_name(&vendor, connection).await? {
                org_cache.insert(vendor, org_ctx.organization);
            }
        }

        for product in product_statuses {
            let status_id = graph
                .db_context
                .lock()
                .await
                .get_status_id(product.status, connection)
                .await?;

            // Organizations have been pre-ingested, just look up from cache
            let org_id = product
                .vendor
                .as_ref()
                .and_then(|vendor| org_cache.get(vendor).map(|org| org.id));

            // Create all product entities for batch ingesting
            let product_cpe_key = product
                .cpe
                .clone()
                .map(|cpe| cpe.product().as_ref().to_string());

            let product_id = ProductInformation::create_uuid(org_id, product.product.clone());

            // Warn: id must be Set(), required for sorting
            let product_entity = product::ActiveModel {
                id: Set(product_id),
                name: Set(product.product.clone()),
                vendor_id: Set(org_id),
                cpe_key: Set(product_cpe_key),
            };
            product_models.push(product_entity);

            if let Some(ref info) = product.version {
                let range = ProductVersionRange {
                    product_id,
                    info: info.clone(),
                    cpe: product.cpe.clone(),
                };

                // Warn: into_active_model() sets id with Set(), required for sorting
                let (version_range_entity, product_version_range_entity) =
                    range.clone().into_active_model();
                version_ranges.push(version_range_entity);
                product_version_ranges.push(product_version_range_entity);

                let packages = if product.packages.is_empty() {
                    // If there are no packages associated to this product, ingest just a product status
                    vec![None]
                } else {
                    product
                        .packages
                        .iter()
                        .map(|c| Some(c.to_string()))
                        .collect()
                };

                // Find the CSAF product_id(s) that resolved to this product
                let csaf_product_ids = product_to_csaf_ids.get(&product).cloned();

                for package in packages {
                    let product_status = GraphProductStatus {
                        cpe: product.cpe.clone(),
                        package,
                        status: status_id,
                        product_version_range_id: range.uuid(),
                        csaf_product_ids: csaf_product_ids.clone(),
                    };

                    let product_status_uuid =
                        product_status.uuid(self.advisory_id, self.vulnerability_id.clone());

                    product_to_status_uuids
                        .entry(product.clone())
                        .or_default()
                        .product_status_ids
                        .push(product_status_uuid);

                    // Warn: into_active_model() sets id with Set(), required for sorting
                    let base_product = product_status
                        .into_active_model(self.advisory_id, self.vulnerability_id.clone());

                    if let Some(cpe) = &product.cpe {
                        cpes.add(cpe.clone());
                    }

                    product_status_models.push(base_product);
                }
            }

            // purls without the range they are bound to would claim all versions
            let purls = if product.invalid_range {
                &[][..]
            } else {
                &product.purls[..]
            };
            for purl in purls {
                if !product.vers_specs.is_empty() {
                    for vers_info in &product.vers_specs {
                        self.create_purl_status(
                            &product,
                            purl,
                            vers_info.scheme,
                            vers_info.spec.clone(),
                            status_id,
                        );
                    }
                } else {
                    let (scheme, spec) = match &purl.version {
                        Some(_) => (
                            purl.ty
                                .parse::<PurlType>()
                                .map_or(VersionScheme::Generic, VersionScheme::from),
                            VersionSpec::Exact(purl.effective_version()),
                        ),
                        None => (VersionScheme::Generic, VersionSpec::Exact(String::new())),
                    };
                    self.create_purl_status(&product, purl, scheme, spec, status_id);
                }
            }
        }

        for (product, purl_statuses) in &self.product_to_purl_statuses {
            for ps in purl_statuses {
                let purl_status_uuid = ps.uuid(self.advisory_id, self.vulnerability_id.clone());
                product_to_status_uuids
                    .entry(product.clone())
                    .or_default()
                    .purl_status_ids
                    .push(purl_status_uuid);
            }
        }

        for ps in &self.entries {
            // add to PURL creator
            purls.add(ps.purl.clone());

            if let Some(cpe) = &ps.cpe {
                cpes.add(cpe.clone());
            }
        }

        purls.create(connection).await?;
        cpes.create(connection).await?;
        // contexts are referenced by all assertions below
        std::mem::take(&mut self.contexts)
            .create(connection)
            .await?;

        for ps in &self.entries {
            // Warn: into_active_model() sets id with Set(), required for sorting
            let (version_range, purl_status) = ps
                .clone()
                .into_active_model(self.advisory_id, self.vulnerability_id.clone());
            version_ranges.push(version_range);
            package_statuses.push(purl_status);
        }

        // Sort all collections by ID before batch inserting to ensure consistent lock acquisition
        // order across transactions. This prevents deadlocks from index page lock contention
        // when multiple concurrent transactions insert overlapping data.
        // Warn: as_ref() requires id fields to be Set() (never NotSet), guaranteed by constructors above.
        product_models.sort_by_key(|model| *model.id.as_ref());
        version_ranges.sort_by_key(|model| *model.id.as_ref());
        package_statuses.sort_by_key(|model| *model.id.as_ref());
        product_version_ranges.sort_by_key(|model| *model.id.as_ref());
        product_status_models.sort_by_key(|model| *model.id.as_ref());

        for batch in product_models.chunked() {
            product::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in version_ranges.chunked() {
            version_range::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in package_statuses.chunked() {
            purl_status::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in product_version_ranges.chunked() {
            product_version_range::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in product_status_models.chunked() {
            product_status::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        if !self.hash_entries.is_empty() {
            let mut hash_models: Vec<advisory_vulnerability_hash::ActiveModel> = self
                .hash_entries
                .iter()
                .map(
                    |(algo, value, status, context)| advisory_vulnerability_hash::ActiveModel {
                        id: Set(self.entry_id(
                            ADVISORY_HASH_NAMESPACE,
                            &[algo, value],
                            *status,
                            *context,
                        )),
                        advisory_id: Set(self.advisory_id),
                        vulnerability_id: Set(self.vulnerability_id.clone()),
                        algorithm: Set(algo.clone()),
                        value: Set(value.clone()),
                        status: Set(*status),
                        assertion_context_id: Set(*context),
                    },
                )
                .collect();

            hash_models.sort_by_key(|model| *model.id.as_ref());

            for batch in hash_models.chunked() {
                advisory_vulnerability_hash::Entity::insert_many(batch)
                    .on_conflict_do_nothing()
                    .exec(connection)
                    .await?;
            }
        }

        if !self.product_identifier_entries.is_empty() {
            let mut version_ranges = BTreeMap::new();
            let mut pid_models = self
                .product_identifier_entries
                .iter()
                .map(|(id_type, value, range, status, context)| {
                    let version_range_id = range.as_ref().map(|range| {
                        let id = range.uuid();
                        version_ranges
                            .entry(id)
                            .or_insert_with(|| range.clone().into_active_model());
                        id
                    });
                    let range_id = version_range_id.unwrap_or_default().to_string();
                    advisory_vulnerability_product_identifier::ActiveModel {
                        id: Set(self.entry_id(
                            ADVISORY_PRODUCT_IDENTIFIER_NAMESPACE,
                            &[&id_type.to_value(), value, &range_id],
                            *status,
                            *context,
                        )),
                        advisory_id: Set(self.advisory_id),
                        vulnerability_id: Set(self.vulnerability_id.clone()),
                        identifier_type: Set(*id_type),
                        value: Set(value.clone()),
                        status: Set(*status),
                        assertion_context_id: Set(*context),
                        version_range_id: Set(version_range_id),
                    }
                })
                .collect::<Vec<_>>();

            pid_models.sort_by_key(|model| *model.id.as_ref());

            for batch in version_ranges.into_values().chunked() {
                version_range::Entity::insert_many(batch)
                    .on_conflict(OnConflict::new().do_nothing().to_owned())
                    .try_insert()
                    .exec_without_returning(connection)
                    .await?;
            }

            for batch in pid_models.chunked() {
                advisory_vulnerability_product_identifier::Entity::insert_many(batch)
                    .on_conflict_do_nothing()
                    .exec(connection)
                    .await?;
            }
        }

        let mut cpe_assertions = CpeAssertionCreator::new(self.advisory_id);
        for (cpe, range, status, context) in &self.cpe_entries {
            cpe_assertions.add(CpeAssertion {
                source_provider: None,
                vulnerability_id: self.vulnerability_id.clone(),
                cpe: cpe.clone(),
                range: range.clone(),
                status: *status,
                context: *context,
                default: false,
            });
        }
        cpe_assertions.create(connection).await?;

        let mut result: HashMap<String, ProductIdStatusMapping> = HashMap::new();
        for (product_id, product) in &self.product_id_to_product {
            if let Some(mapping) = product_to_status_uuids.get(product) {
                result.insert(product_id.clone(), mapping.clone());
            }
        }

        Ok(result)
    }

    /// Deterministic ID of an assertion row (hash, product identifier).
    fn entry_id(
        &self,
        namespace: Uuid,
        values: &[&str],
        status: AssertionStatus,
        context: Option<Uuid>,
    ) -> Uuid {
        let mut id = Uuid::new_v5(&namespace, self.advisory_id.as_bytes());
        id = Uuid::new_v5(&id, self.vulnerability_id.as_bytes());
        for value in values {
            id = Uuid::new_v5(&id, value.as_bytes());
        }
        id = Uuid::new_v5(&id, status.to_value().as_bytes());
        Uuid::new_v5(&id, context.unwrap_or_default().as_bytes())
    }

    /// The context a product is stated in: the platform parts of a relationship (not the
    /// subject), with their identifiers and name, and the SKUs, model and serial numbers of the
    /// relationships themselves, which identify the hardware of the combination. `None` for a product which isn't a
    /// relationship.
    fn context(
        &mut self,
        product_id: &str,
        parts: &[(&str, bool)],
        on_invalid: OnInvalidData,
        report: &dyn ReportSink,
    ) -> Result<Option<Uuid>, Error> {
        let Some(relationship) = self.cache.get_relationship(product_id) else {
            return Ok(None);
        };

        let mut context = AssertionContext {
            category: Some(match relationship.category {
                RelationshipCategory::DefaultComponentOf => {
                    AssertionContextCategory::DefaultComponentOf
                }
                RelationshipCategory::ExternalComponentOf => {
                    AssertionContextCategory::ExternalComponentOf
                }
                RelationshipCategory::InstalledOn => AssertionContextCategory::InstalledOn,
                RelationshipCategory::InstalledWith => AssertionContextCategory::InstalledWith,
                RelationshipCategory::OptionalComponentOf => {
                    AssertionContextCategory::OptionalComponentOf
                }
            }),
            ..Default::default()
        };

        let mut names = Vec::new();
        for (part, subject) in parts {
            // a subject contributes only if it's a relationship, identifying the combination
            if *subject && self.cache.get_relationship(part).is_none() {
                continue;
            }
            if !subject {
                let name = match self.cache.trace_product(part).last() {
                    Some(leaf) => leaf.product.as_ref().map(|name| name.name.as_str()),
                    None => self.cache.definition(part).map(|name| name.name.as_str()),
                };
                names.extend(name);
            }

            for helper in self.cache.helpers(part) {
                let hardware =
                    helper
                        .model_numbers
                        .iter()
                        .flatten()
                        .map(|value| (ContextIdentifierKind::ModelNumber, value.to_string()))
                        .chain(
                            helper.serial_numbers.iter().flatten().map(|value| {
                                (ContextIdentifierKind::SerialNumber, value.to_string())
                            }),
                        )
                        .chain(
                            helper
                                .skus
                                .iter()
                                .map(|value| (ContextIdentifierKind::Sku, value.to_string())),
                        );
                for (kind, value) in hardware {
                    context.add(kind, value);
                }
                // of a combination, only the hardware identifies the platform
                if *subject {
                    continue;
                }

                if let Some(cpe) = helper.cpe.as_deref()
                    && let Some(cpe) = on_invalid.validate(value::cpe(cpe), report)?
                {
                    context.add_cpe(cpe);
                }
                if let Some(purl) = helper.purl.as_deref()
                    && let Some(purl) = on_invalid.validate(value::purl(purl), report)?
                {
                    context.add(ContextIdentifierKind::Purl, purl.to_string());
                }
                for hashes in &helper.hashes {
                    for hash in &hashes.file_hashes {
                        context.add(
                            ContextIdentifierKind::Digest,
                            format!("{}:{}", normalize_algorithm(&hash.algorithm), *hash.value),
                        );
                    }
                }
            }
        }
        context.name = names.join(", ");

        Ok(Some(self.contexts.add(context)))
    }

    fn create_purl_status(
        &mut self,
        product: &ProductStatus,
        purl: &Purl,
        scheme: VersionScheme,
        spec: VersionSpec,
        status: Uuid,
    ) {
        let purl_status = PurlStatus {
            source_provider: None,
            cpe: product.cpe.clone(),
            purl: purl.clone(),
            status,
            info: VersionInfo { scheme, spec },
            context_id: product.context,
            default: false,
        };
        self.product_to_purl_statuses
            .entry(product.clone())
            .or_default()
            .push(purl_status.clone());
        self.entries.insert(purl_status);
    }
}

const REMEDIATION_NAMESPACE: Uuid = Uuid::from_bytes([
    0x7a, 0x3b, 0x9c, 0x2d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3,
]);

#[derive(Debug)]
pub struct RemediationCreator<'a> {
    advisory_id: Uuid,
    vulnerability_id: String,
    product_id_mapping: HashMap<String, ProductIdStatusMapping>,
    remediations: Vec<&'a Remediation>,
}

impl<'a> RemediationCreator<'a> {
    pub fn new(
        advisory_id: Uuid,
        vulnerability_id: String,
        product_id_mapping: HashMap<String, ProductIdStatusMapping>,
    ) -> Self {
        Self {
            advisory_id,
            vulnerability_id,
            product_id_mapping,
            remediations: Vec::new(),
        }
    }

    pub fn add(&mut self, remediation: &'a Remediation) {
        self.remediations.push(remediation);
    }

    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn create<C: ConnectionTrait>(&self, connection: &C) -> Result<(), Error> {
        let mut remediation_models = Vec::new();
        let mut remediation_purl_status_models = Vec::new();
        let mut remediation_product_status_models = Vec::new();

        for rem in &self.remediations {
            let remediation_id = self.generate_remediation_uuid(rem);

            let remediation_model = remediation::ActiveModel {
                id: Set(remediation_id),
                advisory_id: Set(self.advisory_id),
                vulnerability_id: Set(self.vulnerability_id.clone()),
                category: Set((&rem.category).into()),
                details: Set(Some(rem.details.to_string())),
                url: Set(rem.url.clone()),
                data: Set(serde_json::to_value(rem)?),
            };
            remediation_models.push(remediation_model);

            if let Some(product_ids) = &rem.product_ids {
                for product_id in &product_ids.0 {
                    if let Some(mapping) = self.product_id_mapping.get(product_id.as_str()) {
                        for purl_status_id in &mapping.purl_status_ids {
                            remediation_purl_status_models.push(
                                remediation_purl_status::ActiveModel {
                                    remediation_id: Set(remediation_id),
                                    purl_status_id: Set(*purl_status_id),
                                },
                            );
                        }
                        for product_status_id in &mapping.product_status_ids {
                            remediation_product_status_models.push(
                                remediation_product_status::ActiveModel {
                                    remediation_id: Set(remediation_id),
                                    product_status_id: Set(*product_status_id),
                                },
                            );
                        }
                    }
                }
            }
        }

        remediation_models.sort_by_key(|model| *model.id.as_ref());

        for batch in remediation_models.chunked() {
            remediation::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in remediation_purl_status_models.chunked() {
            remediation_purl_status::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in remediation_product_status_models.chunked() {
            remediation_product_status::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        Ok(())
    }

    fn generate_remediation_uuid(&self, rem: &Remediation) -> Uuid {
        let category: RemediationCategory = (&rem.category).into();
        let mut result = Uuid::new_v5(&REMEDIATION_NAMESPACE, self.advisory_id.as_bytes());
        result = Uuid::new_v5(&result, self.vulnerability_id.as_bytes());
        result = Uuid::new_v5(&result, category.remediation_category_key().as_bytes());
        result = Uuid::new_v5(&result, rem.details.as_bytes());
        if let Some(url) = &rem.url {
            result = Uuid::new_v5(&result, url.as_bytes());
        }
        result
    }
}
