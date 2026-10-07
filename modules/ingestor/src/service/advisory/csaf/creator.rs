use super::value::OnInvalidData;
use crate::{
    graph::{
        Graph,
        advisory::{
            product_status::{ProductStatus as GraphProductStatus, ProductVersionRange},
            purl_status::PurlStatus,
            vers::parse_vers,
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
        },
    },
};
use csaf::schema::csaf2_0::schema::{
    CategoryOfTheBranch, CommonSecurityAdvisoryFramework as Csaf, ProductsT, Remediation,
};
use sbom_walker::report::ReportSink;
use sea_orm::{ActiveEnum, ActiveValue::Set, ConnectionTrait, EntityTrait};
use std::collections::{HashMap, HashSet};
use tracing::instrument;
use trustify_common::{
    cpe::{Component, Cpe},
    db::chunk::EntityChunkedIter,
    hashing::normalize_algorithm,
    purl::Purl,
};
use trustify_entity::{
    advisory_vulnerability_cpe, advisory_vulnerability_hash,
    advisory_vulnerability_product_identifier,
    advisory_vulnerability_product_identifier::ProductIdentifierType,
    correlation_evidence::AssertionStatus,
    organization, product, product_status, product_version_range, purl_status,
    remediation::{self, RemediationCategory},
    remediation_product_status, remediation_purl_status, version_range,
    version_scheme::VersionScheme,
};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ProductIdStatusMapping {
    pub purl_status_ids: Vec<Uuid>,
    pub product_status_ids: Vec<Uuid>,
}

/// Namespace of the IDs of `advisory_vulnerability_cpe` rows.
const ADVISORY_CPE_NAMESPACE: Uuid = Uuid::from_bytes([
    0x5c, 0x1e, 0x8b, 0x3f, 0x92, 0x7d, 0x4a, 0x06, 0xb4, 0x2e, 0x61, 0xc9, 0x0f, 0xd8, 0x37, 0xa5,
]);

/// A CPE (pattern) an advisory makes an assertion about, optionally constrained by a version range.
type CpeEntry = (Cpe, Option<VersionInfo>, AssertionStatus);

#[derive(Debug)]
pub struct StatusCreator<'a> {
    cache: ResolveProductIdCache<'a>,
    advisory_id: Uuid,
    vulnerability_id: String,
    entries: HashSet<PurlStatus>,
    products: HashSet<ProductStatus>,
    product_id_to_product: HashMap<String, ProductStatus>,
    product_to_purl_statuses: HashMap<ProductStatus, Vec<PurlStatus>>,
    hash_entries: HashSet<(String, String, AssertionStatus)>,
    product_identifier_entries: HashSet<(ProductIdentifierType, String, AssertionStatus)>,
    cpe_entries: HashSet<CpeEntry>,
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
            _ => None,
        };

        for r in ps.iter().flat_map(|ps| &ps.0) {
            let mut product = ProductStatus {
                status,
                ..Default::default()
            };
            let mut product_ids = vec![];
            match self.cache.get_relationship(r) {
                Some(rel) => {
                    // Find all products
                    product_ids.push(rel.relates_to_product_reference.as_str());
                    // Find all components/packages within
                    product_ids.push(rel.product_reference.as_str());
                }
                None => {
                    // If there's no relationship, find only products
                    product_ids.push(r.as_str());
                }
            };
            for product_id in &product_ids {
                product = self.cache.trace_product(product_id).iter().try_fold(
                    product,
                    |mut product, branch| {
                        product.update_from_branch(branch, on_invalid, report)?;
                        Ok::<_, Error>(product)
                    },
                )?;
            }

            if let Some(assertion) = assertion_status {
                for product_id in &product_ids {
                    for branch in self.cache.trace_product(product_id) {
                        if let Some(full_name) = &branch.product
                            && let Some(pih) = &full_name.product_identification_helper
                        {
                            for hc in &pih.hashes {
                                for fh in &hc.file_hashes {
                                    let algo = normalize_algorithm(&fh.algorithm);
                                    self.hash_entries.insert((
                                        algo,
                                        fh.value.to_string(),
                                        assertion,
                                    ));
                                }
                            }
                            for mn in pih.model_numbers.iter().flatten() {
                                self.product_identifier_entries.insert((
                                    ProductIdentifierType::ModelNumber,
                                    mn.to_string(),
                                    assertion,
                                ));
                            }
                            for sn in pih.serial_numbers.iter().flatten() {
                                self.product_identifier_entries.insert((
                                    ProductIdentifierType::SerialNumber,
                                    sn.to_string(),
                                    assertion,
                                ));
                            }
                            for sku in &pih.skus {
                                self.product_identifier_entries.insert((
                                    ProductIdentifierType::Sku,
                                    sku.to_string(),
                                    assertion,
                                ));
                            }
                        }
                    }
                }

                // For a relationship, only the component carries the assertion. The platform it
                // relates to (e.g. hardware a firmware is installed on) is typically listed with
                // both affected and fixed combinations.
                let component = match self.cache.get_relationship(r) {
                    Some(rel) => rel.product_reference.as_str(),
                    None => r.as_str(),
                };
                self.add_cpe_entries(component, assertion, on_invalid, report)?;
            }

            self.product_id_to_product
                .insert(r.to_string(), product.clone());
            self.products.insert(product);
        }
        Ok(())
    }

    /// Collect the CPE assertions of a product.
    ///
    /// The CPE is the nearest one on the path to the product. If its version is ANY, the version
    /// is constrained by the product's version range or version branch.
    fn add_cpe_entries(
        &mut self,
        product_id: &str,
        assertion: AssertionStatus,
        on_invalid: OnInvalidData,
        report: &dyn ReportSink,
    ) -> Result<(), Error> {
        let trace = self.cache.trace_product(product_id);
        let Some(leaf) = trace.last() else {
            return Ok(());
        };

        let mut cpe = None;
        for branch in trace.iter().rev() {
            if let Some(found) = branch_cpe(branch, on_invalid, report)? {
                cpe = Some(found);
                break;
            }
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
            match leaf.category {
                CategoryOfTheBranch::ProductVersionRange => match parse_vers(&leaf.name) {
                    Ok(infos) => infos.into_iter().map(Some).collect(),
                    Err(err) => {
                        // never widen an unparsable range to "all versions"
                        tracing::debug!(%cpe, range = leaf.name.as_str(), "skipping CPE with invalid range: {err}");
                        return Ok(());
                    }
                },
                CategoryOfTheBranch::ProductVersion => vec![Some(VersionInfo {
                    scheme: VersionScheme::Generic,
                    spec: VersionSpec::Exact(leaf.name.to_string()),
                })],
                _ => vec![None],
            }
        };

        for range in ranges {
            self.cpe_entries.insert((cpe.clone(), range, assertion));
        }

        Ok(())
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

            for purl in &product.purls {
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
                            VersionScheme::from(purl.ty.as_str()),
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

        for (cpe, range, _) in &self.cpe_entries {
            cpes.add(cpe.clone());
            if let Some(range) = range {
                version_ranges.push(range.clone().into_active_model());
            }
        }

        purls.create(connection).await?;
        cpes.create(connection).await?;

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

        for batch in &product_models.chunked() {
            product::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in &version_ranges.chunked() {
            version_range::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in &package_statuses.chunked() {
            purl_status::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in &product_version_ranges.chunked() {
            product_version_range::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in &product_status_models.chunked() {
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
                    |(algo, value, status)| advisory_vulnerability_hash::ActiveModel {
                        advisory_id: Set(self.advisory_id),
                        vulnerability_id: Set(self.vulnerability_id.clone()),
                        algorithm: Set(algo.clone()),
                        value: Set(value.clone()),
                        status: Set(*status),
                    },
                )
                .collect();

            hash_models.sort_by(|a, b| {
                a.algorithm
                    .as_ref()
                    .cmp(b.algorithm.as_ref())
                    .then_with(|| a.value.as_ref().cmp(b.value.as_ref()))
            });

            for batch in &hash_models.chunked() {
                advisory_vulnerability_hash::Entity::insert_many(batch)
                    .on_conflict_do_nothing()
                    .exec(connection)
                    .await?;
            }
        }

        if !self.product_identifier_entries.is_empty() {
            let mut pid_models: Vec<advisory_vulnerability_product_identifier::ActiveModel> = self
                .product_identifier_entries
                .iter()
                .map(|(id_type, value, status)| {
                    advisory_vulnerability_product_identifier::ActiveModel {
                        advisory_id: Set(self.advisory_id),
                        vulnerability_id: Set(self.vulnerability_id.clone()),
                        identifier_type: Set(*id_type),
                        value: Set(value.clone()),
                        status: Set(*status),
                    }
                })
                .collect();

            pid_models.sort_by(|a, b| {
                a.value.as_ref().cmp(b.value.as_ref()).then_with(|| {
                    format!("{:?}", a.identifier_type.as_ref())
                        .cmp(&format!("{:?}", b.identifier_type.as_ref()))
                })
            });

            for batch in &pid_models.chunked() {
                advisory_vulnerability_product_identifier::Entity::insert_many(batch)
                    .on_conflict_do_nothing()
                    .exec(connection)
                    .await?;
            }
        }

        if !self.cpe_entries.is_empty() {
            let mut cpe_models = self
                .cpe_entries
                .iter()
                .map(|(cpe, range, status)| {
                    let cpe_id = cpe.uuid();
                    let version_range_id = range.as_ref().map(VersionInfo::uuid);
                    advisory_vulnerability_cpe::ActiveModel {
                        id: Set(self.advisory_cpe_id(cpe_id, version_range_id, *status)),
                        advisory_id: Set(self.advisory_id),
                        vulnerability_id: Set(self.vulnerability_id.clone()),
                        status: Set(*status),
                        cpe_id: Set(cpe_id),
                        version_range_id: Set(version_range_id),
                    }
                })
                .collect::<Vec<_>>();

            cpe_models.sort_by_key(|model| *model.id.as_ref());

            for batch in &cpe_models.chunked() {
                advisory_vulnerability_cpe::Entity::insert_many(batch)
                    .on_conflict_do_nothing()
                    .exec(connection)
                    .await?;
            }
        }

        let mut result: HashMap<String, ProductIdStatusMapping> = HashMap::new();
        for (product_id, product) in &self.product_id_to_product {
            if let Some(mapping) = product_to_status_uuids.get(product) {
                result.insert(product_id.clone(), mapping.clone());
            }
        }

        Ok(result)
    }

    /// Deterministic ID of an `advisory_vulnerability_cpe` row.
    fn advisory_cpe_id(
        &self,
        cpe_id: Uuid,
        version_range_id: Option<Uuid>,
        status: AssertionStatus,
    ) -> Uuid {
        let mut id = Uuid::new_v5(&ADVISORY_CPE_NAMESPACE, self.advisory_id.as_bytes());
        id = Uuid::new_v5(&id, self.vulnerability_id.as_bytes());
        id = Uuid::new_v5(&id, cpe_id.as_bytes());
        id = Uuid::new_v5(&id, version_range_id.unwrap_or_default().as_bytes());
        Uuid::new_v5(&id, status.to_value().as_bytes())
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
            cpe: product.cpe.clone(),
            purl: purl.clone(),
            status,
            info: VersionInfo { scheme, spec },
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

        for batch in &remediation_models.chunked() {
            remediation::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in &remediation_purl_status_models.chunked() {
            remediation_purl_status::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .await?;
        }

        for batch in &remediation_product_status_models.chunked() {
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
