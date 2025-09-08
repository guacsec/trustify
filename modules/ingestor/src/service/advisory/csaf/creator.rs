use crate::{
    graph::{
        Graph,
        advisory::{
            product_status::ProductVersionRange,
            purl_status::PurlStatus,
            version::{Version, VersionInfo, VersionSpec},
        },
        cpe::CpeCreator,
        organization::{OrganizationContext, OrganizationInformation},
        product::ProductInformation,
        purl::creator::PurlCreator,
    },
    service::{
        Error,
        advisory::csaf::{product_status::ProductStatus, util::ResolveProductIdCache},
    },
};
use csaf::{Csaf, definitions::ProductIdT};
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use tracing::instrument;
use trustify_common::{db::chunk::EntityChunkedIter, purl::Purl};
use trustify_entity::{
    organization, product, product_status, product_version_range, purl_status, status::Status,
    version_range, version_scheme::VersionScheme,
};
use uuid::Uuid;

#[derive(Debug)]
pub struct StatusCreator<'a> {
    cache: ResolveProductIdCache<'a>,
    advisory_id: Uuid,
    vulnerability_id: String,
    entries: HashSet<PurlStatus>,
    products: HashSet<ProductStatus>,
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
            self.products.insert(product);
        }
    }

    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn create<C: ConnectionTrait>(
        &mut self,
        graph: &Graph,
        connection: &C,
    ) -> Result<(), Error> {
        let mut product_status_models = Vec::new();
        let mut purls = PurlCreator::new();
        let mut cpes = CpeCreator::new();

        let mut org_cache: HashMap<String, organization::Model> = HashMap::new();
        let mut product_models = Vec::new();
        let mut version_ranges = Vec::new();
        let mut product_version_ranges = Vec::new();

        let mut package_statuses = Vec::new();
        let product_statuses = self.products.clone();

        for product in product_statuses {
            let status_id = graph
                .db_context
                .lock()
                .await
                .get_status_id(product.status, connection)
                .await?;

            // There should be only a few organizations per document,
            // so simple caching should work here.
            // If we find examples where this is not a case, we can switch to
            // batch ingesting of organizations as well.
            let org_id = match product.vendor.clone() {
                Some(vendor) => match org_cache.get(&vendor) {
                    Some(entry) => Some(entry.id),
                    None => {
                        let organization_cpe_key = product
                            .cpe
                            .clone()
                            .map(|cpe| cpe.vendor().as_ref().to_string());

                        let org = OrganizationInformation {
                            cpe_key: organization_cpe_key,
                            website: None,
                        };

                        let org: OrganizationContext<'_> =
                            graph.ingest_organization(&vendor, org, connection).await?;
                        org_cache
                            .entry(vendor.clone())
                            .or_insert(org.organization.clone());

                        Some(org.organization.id)
                    }
                },
                None => None,
            };

            // Create all product entities for batch ingesting
            let product_cpe_key = product
                .cpe
                .clone()
                .map(|cpe| cpe.product().as_ref().to_string());

            let product_id = ProductInformation::create_uuid(org_id, product.product.clone());

            let product_entity = product::ActiveModel {
                id: Set(product_id),
                name: Set(product.product.clone()),
                vendor_id: Set(org_id),
                cpe_key: Set(product_cpe_key),
            };
            product_models.push(product_entity.clone());

            if let Some(ref info) = product.version {
                let range = ProductVersionRange {
                    product_id,
                    info: info.clone(),
                    cpe: product.cpe.clone(),
                };

                let (version_range_entity, product_version_range_entity) =
                    range.clone().into_active_model();
                version_ranges.push(version_range_entity.clone());
                product_version_ranges.push(product_version_range_entity.clone());

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
            let (version_range, purl_status) = ps
                .clone()
                .into_active_model(self.advisory_id, self.vulnerability_id.clone());
            version_ranges.push(version_range.clone());
            package_statuses.push(purl_status);
        }

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

        Ok(())
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
        self.entries.insert(purl_status);
    }
}
