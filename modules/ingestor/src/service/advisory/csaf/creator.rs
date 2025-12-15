use crate::{
    graph::{
        Graph,
        advisory::{
            product_status::ProductVersionRange,
            purl_status::PurlStatus,
            version::{Version, VersionInfo, VersionSpec},
        },
        cpe::CpeCreator,
        organization::creator::OrganizationCreator,
        product::ProductInformation,
        purl::creator::PurlCreator,
    },
    service::{
        Error,
        advisory::csaf::{product_status::ProductStatus, util::ResolveProductIdCache},
    },
};
use csaf::{Csaf, definitions::ProductIdT, vulnerability::Remediation};
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use tracing::instrument;
use trustify_common::{db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity::{
    organization, product, product_status, product_version_range, purl_status,
    remediation::{self, RemediationCategory},
    remediation_product_status, remediation_purl_status,
    status::Status,
    version_range,
    version_scheme::VersionScheme,
};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ProductIdStatusMapping {
    pub purl_status_ids: Vec<Uuid>,
    pub product_status_ids: Vec<Uuid>,
}

#[derive(Debug)]
pub struct StatusCreator<'a> {
    cache: ResolveProductIdCache<'a>,
    advisory_id: Uuid,
    vulnerability_id: String,
    entries: HashSet<PurlStatus>,
    products: HashSet<ProductStatus>,
    product_id_to_product: HashMap<String, ProductStatus>,
    product_to_purl_statuses: HashMap<ProductStatus, Vec<PurlStatus>>,
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
        }
    }

    pub fn add_all(&mut self, ps: &Option<Vec<ProductIdT>>, status: &'static str) {
        for r in ps.iter().flatten() {
            let mut product = ProductStatus {
                status,
                ..Default::default()
            };
            let mut product_ids = vec![];
            match self.cache.get_relationship(&r.0) {
                Some(rel) => {
                    let inner_id: &ProductIdT = &rel.product_reference;
                    let context = &rel.relates_to_product_reference;

                    // Find all products
                    product_ids.push(&context.0);
                    // Find all components/packages within
                    product_ids.push(&inner_id.0);
                }
                None => {
                    // If there's no relationship, find only products
                    product_ids.push(&r.0);
                }
            };
            for product_id in product_ids {
                product = self.cache.trace_product(product_id).iter().fold(
                    product,
                    |mut product, branch| {
                        product.update_from_branch(branch);
                        product
                    },
                );
            }

            self.product_id_to_product
                .insert(r.0.clone(), product.clone());
            self.products.insert(product);
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

                for package in packages {
                    let product_status = crate::graph::advisory::product_status::ProductStatus {
                        cpe: product.cpe.clone(),
                        package,
                        status: status_id,
                        product_version_range_id: range.uuid(),
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
                let scheme = VersionScheme::from(purl.ty.as_str());

                // Insert purl status
                let spec = match &purl.version {
                    Some(version) => VersionSpec::Exact(version.clone()),
                    None => VersionSpec::Range(Version::Unbounded, Version::Unbounded),
                };
                self.create_purl_status(&product, purl, scheme, spec, status_id);

                // For "fixed" status and Red Hat CSAF advisories,
                // insert "affected" status up until this version.
                // Let's keep this here for now as a special case. If more exceptions arise,
                // we can refactor and provide support for vendor-specific parsing.
                if let Ok(Status::Fixed) = Status::from_str(product.status)
                    && let Some(cpe_vendor) = product
                        .cpe
                        .as_ref()
                        .map(|cpe| cpe.vendor().as_ref().to_string())
                    && cpe_vendor == "redhat"
                    && let Some(version) = &purl.version
                {
                    let spec =
                        VersionSpec::Range(Version::Unbounded, Version::Exclusive(version.clone()));
                    self.create_purl_status(
                        &product,
                        purl,
                        scheme,
                        spec,
                        graph
                            .db_context
                            .lock()
                            .await
                            .get_status_id(&Status::Affected.to_string(), connection)
                            .await?,
                    );
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

        let mut result: HashMap<String, ProductIdStatusMapping> = HashMap::new();
        for (product_id, product) in &self.product_id_to_product {
            if let Some(mapping) = product_to_status_uuids.get(product) {
                result.insert(product_id.clone(), mapping.clone());
            }
        }

        Ok(result)
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
                details: Set(Some(rem.details.clone())),
                url: Set(rem.url.as_ref().map(|u| u.to_string())),
                data: Set(serde_json::to_value(rem)?),
            };
            remediation_models.push(remediation_model);

            if let Some(product_ids) = &rem.product_ids {
                for product_id in product_ids {
                    if let Some(mapping) = self.product_id_mapping.get(&product_id.0) {
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
            result = Uuid::new_v5(&result, url.as_str().as_bytes());
        }
        result
    }
}
