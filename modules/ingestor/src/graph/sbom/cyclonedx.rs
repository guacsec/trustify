use crate::{
    graph::{
        cpe::CpeCreator,
        product::ProductInformation,
        purl::creator::PurlCreator,
        sbom::{
            CryptographicAssetCreator, CycloneDx as CycloneDxProcessor, DeviceIdentifierCreator,
            LicenseCreator, LicenseInfo, LicensingInfo, LicensingInfoCreator,
            MachineLearningModelCreator, NodeInfoParam, PackageCreator, PackageLicensenInfo,
            PackageReference, References, RelationshipCreator, SbomContext, SbomInformation,
            populate_expanded_license,
            processor::{
                InitContext, PostContext, Processor, RedHatProductComponentRelationships,
                RunProcessors,
            },
            sbom_package_license::LicenseCategory,
        },
    },
    service::Error,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use cyclonedx_rs::cyclonedx::v_1_7::{
    Attachment, Component, ComponentEvidenceIdentity, CycloneDx, License, LicenseChoiceItemUrl,
    OrganizationalContact,
};
use sbom_walker::{
    model::sbom::serde_cyclonedx::Sbom,
    report::{ReportSink, check},
};
use sea_orm::ConnectionTrait;
use std::{borrow::Cow, collections::HashMap, str::FromStr};
use time::{OffsetDateTime, format_description::well_known::Iso8601};
use tracing::instrument;
use trustify_common::{advisory::cyclonedx::extract_properties_json, cpe::Cpe, purl::Purl};
use trustify_entity::{
    advisory_vulnerability_product_identifier::ProductIdentifierType, relationship::Relationship,
};
use uuid::Uuid;

use super::FileCreator;

/// Marker we use for identifying the document itself.
///
/// Similar to the SPDX doc id, which is attached to the document itself. CycloneDX doesn't have
/// such a concept, but can still attach a component to the document via a dedicated metadata
/// component.
pub const CYCLONEDX_DOC_REF: &str = "CycloneDX-doc-ref";

pub struct Information<'a>(pub &'a CycloneDx);

fn from_contact(contact: &OrganizationalContact) -> Option<String> {
    match (&contact.name, &contact.email) {
        (Some(name), Some(email)) => Some(format!("{name} <{email}>")),
        (Some(name), None) => Some(name.to_string()),
        (None, Some(email)) => Some(email.to_string()),
        (None, None) => None,
    }
}

/// Extract the textual content of a license attachment, decoding it if necessary.
///
/// `base64` is the only encoding CycloneDX defines; anything else is taken verbatim.
fn license_text(text: &Attachment) -> Option<String> {
    match text.encoding.as_deref() {
        Some("base64") => match BASE64_STANDARD.decode(&text.content) {
            Ok(decoded) => String::from_utf8(decoded)
                .inspect_err(|err| tracing::info!("Skipping non-UTF-8 license text: {err}"))
                .ok(),
            Err(err) => {
                tracing::info!("Skipping license text which failed to base64-decode: {err}");
                None
            }
        },
        _ => Some(text.content.clone()),
    }
}

impl<'a> From<Information<'a>> for SbomInformation {
    fn from(value: Information<'a>) -> Self {
        let sbom = value.0;

        let published = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.timestamp.as_ref())
            .and_then(|timestamp| {
                OffsetDateTime::parse(timestamp.as_ref(), &Iso8601::DEFAULT).ok()
            });

        let authors = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.authors.as_ref())
            .into_iter()
            .flatten()
            .filter_map(from_contact)
            .collect();

        // supplier

        let suppliers = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.supplier.as_ref())
            .into_iter()
            .flat_map(|oe| {
                // try name first
                oe.name
                    .clone()
                    .map(|name| vec![name])
                    .or_else(|| {
                        // then contact
                        oe.contact
                            .as_ref()
                            .map(|c| c.iter().filter_map(from_contact).collect())
                    })
                    // last URL
                    .or_else(|| oe.url.clone())
            })
            .flatten()
            .collect();

        let name = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.component.as_ref())
            .map(|component| component.name.to_string())
            // otherwise use the serial number
            .or_else(|| sbom.serial_number.as_ref().map(|id| id.to_string()))
            // TODO: not sure what to use instead, the version will most likely be `1`.
            .or_else(|| sbom.version.as_ref().map(|v| v.to_string()))
            .unwrap_or_else(|| "<unknown>".to_string());

        let data_licenses = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.licenses.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|license| match license {
                LicenseChoiceItemUrl::Variant0(l) => {
                    l.license.id.as_ref().or(l.license.name.as_ref()).cloned()
                }
                LicenseChoiceItemUrl::Variant1(l) => Some(l.expression.clone()),
            })
            .collect();

        Self {
            node_id: CYCLONEDX_DOC_REF.to_string(),
            name,
            published,
            authors,
            suppliers,
            data_licenses,
            properties: extract_properties_json(sbom),
        }
    }
}

impl SbomContext {
    #[instrument(skip(connection, sbom, warnings), err(level=tracing::Level::INFO))]
    pub async fn ingest_cyclonedx(
        &self,
        mut sbom: Box<CycloneDx>,
        warnings: &dyn ReportSink,
        connection: &impl ConnectionTrait,
    ) -> Result<(), Error> {
        // pre-flight checks

        check::serde_cyclonedx::all(warnings, &Sbom::V1_7(Cow::Borrowed(&sbom)));

        let mut creator = Creator::new(self.sbom.sbom_id);

        // TODO: find a way to dynamically set up processors
        let mut processors: Vec<Box<dyn Processor>> =
            vec![Box::new(RedHatProductComponentRelationships::new())];

        // init processors

        let suppliers = sbom
            .metadata
            .as_ref()
            .and_then(|m| m.supplier.as_ref().and_then(|org| org.name.as_deref()))
            .into_iter()
            .collect::<Vec<_>>();
        InitContext {
            document_node_id: CYCLONEDX_DOC_REF,
            suppliers: &suppliers,
        }
        .run(&mut processors);

        // extract "describes"

        if let Some(metadata) = &mut sbom.metadata
            && let Some(component) = &mut metadata.component
        {
            let bom_ref = component
                .bom_ref
                .get_or_insert_with(|| Uuid::new_v4().to_string())
                .to_string();

            let product_cpe = component
                .cpe
                .as_ref()
                .map(|cpe| Cpe::from_str(cpe.as_ref()))
                .transpose()
                .map_err(|err| Error::InvalidContent(err.into()))?;
            let pr = self
                .graph
                .ingest_product(
                    component.name.clone(),
                    ProductInformation {
                        vendor: component.publisher.clone(),
                        cpe: product_cpe,
                    },
                    connection,
                )
                .await?;

            if let Some(ver) = component.version.clone() {
                pr.ingest_product_version(ver.to_string(), Some(self.sbom.sbom_id), connection)
                    .await?;
            }

            // create component

            creator.add(component);

            // create a relationship

            creator.relate(
                CYCLONEDX_DOC_REF.to_string(),
                Relationship::Describes,
                bom_ref,
            );
        }

        // record components

        creator.add_all(&sbom.components);

        // create relationships

        for left in sbom.dependencies.iter().flatten() {
            for target in left.depends_on.iter().flatten() {
                tracing::debug!("Adding dependency - left: {}, right: {}", left.ref_, target);
                creator.relate(left.ref_.clone(), Relationship::Dependency, target.clone());
            }

            // https://github.com/guacsec/trustify/issues/1131
            // Do we need to qualify this so that only "arch=src" refs
            // get the GeneratedFrom relationship?
            for target in left.provides.iter().flatten() {
                tracing::debug!("Adding generates - left: {}, right: {}", left.ref_, target);
                creator.relate(left.ref_.clone(), Relationship::Generates, target.clone());
            }
        }

        // create

        creator.create(connection, &mut processors).await?;

        self.populate_describing_cpes(connection).await?;
        self.populate_ancestors(connection).await?;

        // done

        Ok(())
    }
}

/// Creator of CycloneDX components and dependencies
#[derive(Debug, Default)]
struct Creator<'a> {
    sbom_id: Uuid,
    components: Vec<&'a Component>,
    relations: Vec<(String, Relationship, String)>,
}

impl<'a> Creator<'a> {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            components: Default::default(),
            relations: Default::default(),
        }
    }

    pub fn add_all(&mut self, components: &'a Option<Vec<Component>>) {
        self.extend(components.iter().flatten())
    }

    /// Add a component, and the components nested in it. Nesting is an assembly ("system →
    /// subsystem → parts"), so the component contains them. Without a `bom-ref` on both sides,
    /// there is nothing to relate.
    pub fn add(&mut self, component: &'a Component) {
        self.components.push(component);
        for nested in component.components.iter().flatten() {
            if let (Some(parent), Some(child)) = (&component.bom_ref, &nested.bom_ref) {
                self.relate(parent.clone(), Relationship::Contains, child.clone());
            }
            self.add(nested);
        }
    }

    pub fn extend<I>(&mut self, i: I)
    where
        I: IntoIterator<Item = &'a Component>,
    {
        for c in i.into_iter() {
            self.add(c);
        }
    }

    pub fn relate(&mut self, left: String, rel: Relationship, right: String) {
        self.relations.push((left, rel, right));
    }

    #[instrument(skip(self, db, processors), err(level=tracing::Level::INFO))]
    pub async fn create(
        self,
        db: &impl ConnectionTrait,
        processors: &mut [Box<dyn Processor>],
    ) -> Result<(), Error> {
        let mut creator = ComponentCreator::new(self.sbom_id, self.components.len());

        for comp in self.components {
            creator.add_component(comp)?;
        }

        for (left, rel, right) in self.relations {
            creator.add_relation(left, rel, right);
        }

        // post process
        creator.post_process(processors);

        // validate relationships before inserting
        creator.validate()?;

        // write to db
        creator.create(db).await?;

        // done

        Ok(())
    }
}

struct ComponentCreator {
    sbom_id: Uuid,
    cpes: CpeCreator,
    purls: PurlCreator,
    licenses: LicenseCreator,
    licensing_infos: LicensingInfoCreator,
    packages: PackageCreator,
    files: FileCreator,
    models: MachineLearningModelCreator,
    crypto: CryptographicAssetCreator,
    devices: DeviceIdentifierCreator,
    relationships: RelationshipCreator<CycloneDxProcessor>,
    // Map each node to a collection of references
    refs: HashMap<String, Vec<PackageReference>>,
}

impl ComponentCreator {
    pub fn new(sbom_id: Uuid, capacity: usize) -> Self {
        Self {
            sbom_id,
            cpes: CpeCreator::new(),
            purls: PurlCreator::new(),
            licenses: LicenseCreator::new(),
            licensing_infos: LicensingInfoCreator::new(),
            packages: PackageCreator::with_capacity(sbom_id, capacity),
            files: FileCreator::new(sbom_id),
            models: MachineLearningModelCreator::new(sbom_id),
            crypto: CryptographicAssetCreator::new(sbom_id),
            devices: DeviceIdentifierCreator::new(sbom_id),
            relationships: RelationshipCreator::new(sbom_id, CycloneDxProcessor),
            refs: Default::default(),
        }
    }

    pub fn add_component(&mut self, comp: &Component) -> Result<(), Error> {
        let node_id = comp
            .bom_ref
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let licenses_uuid = self.add_license(comp);

        if let Some(cpe) = &comp.cpe {
            match Cpe::from_str(cpe.as_ref()) {
                Ok(cpe) => {
                    self.add_cpe(node_id.clone(), cpe);
                }
                Err(err) => {
                    tracing::info!("Skipping CPE due to parsing error: {err}");
                }
            }
        }

        if let Some(purl) = &comp.purl {
            match Purl::from_str(purl.as_ref()) {
                Ok(purl) => {
                    self.add_purl(node_id.clone(), purl);
                }
                Err(err) => {
                    tracing::info!("Skipping PURL due to parsing error: {err}");
                }
            }
        }

        for identity in comp
            .evidence
            .as_ref()
            .and_then(|evidence| evidence.identity.as_ref())
            .iter()
            .flat_map(|id| match id {
                ComponentEvidenceIdentity::Variant0(value) => value.iter().collect::<Vec<_>>(),
                ComponentEvidenceIdentity::Variant1(value) => vec![value],
            })
        {
            match (identity.field.as_str(), &identity.concluded_value) {
                ("cpe", Some(cpe)) => {
                    if let Ok(cpe) = Cpe::from_str(cpe.as_ref()) {
                        self.add_cpe(node_id.clone(), cpe);
                    }
                }
                ("purl", Some(purl)) => {
                    if let Ok(purl) = Purl::from_str(purl.as_ref()) {
                        self.add_purl(node_id.clone(), purl);
                    }
                }

                _ => {}
            }
        }

        let cyclone_licenses = licenses_uuid
            .iter()
            .map(|l| PackageLicensenInfo {
                license_id: *l,
                license_type: LicenseCategory::Declared,
            })
            .collect::<Vec<_>>();

        match ComponentType::from_str(&comp.type_) {
            Ok(ty) => {
                use ComponentType::*;
                const EMPTY: Vec<PackageReference> = vec![];
                match ty {
                    // We treat all these types as "packages", hardware and firmware included:
                    // they have versions and identifiers (PURL, CPE) like software
                    Application | Framework | Library | Container | OperatingSystem | Device
                    | DeviceDriver | Firmware => {
                        self.packages.add(
                            NodeInfoParam {
                                supplier: comp.supplier.as_ref().map(|supplier| {
                                    let mut ids = Vec::new();
                                    if let Some(name) = &supplier.name {
                                        ids.push(format!("name:{name}"));
                                    }
                                    if let Some(urls) = &supplier.url {
                                        ids.extend(
                                            urls.iter().map(|url| format!("namespace:{url}")),
                                        );
                                    }
                                    serde_json::json!({"identifiers":ids,"name":supplier.name})
                                }),
                                node_id: node_id.clone(),
                                name: comp.name.to_string(),
                                group: comp.group.as_ref().map(|v| v.to_string()),
                                version: comp.version.as_ref().map(|v| v.to_string()),
                                package_license_info: cyclone_licenses,
                            },
                            self.refs.get(&node_id).unwrap_or(&EMPTY).iter(),
                            comp.hashes.clone().into_iter().flatten(),
                        );
                        if matches!(ty, Device | DeviceDriver | Firmware) {
                            self.devices
                                .add(node_id.clone(), extract_device_identifiers(comp));
                        }
                    }
                    File => {
                        self.files.add(
                            node_id.clone(),
                            comp.name.to_string(),
                            comp.hashes.clone().into_iter().flatten(),
                        );
                    }
                    MachineLearningModel => {
                        self.models.add(
                            node_id.clone(),
                            comp.name.to_string(),
                            self.refs.get(&node_id).unwrap_or(&EMPTY).iter(),
                            comp.hashes.clone().into_iter().flatten(),
                            comp.into(),
                        );
                    }
                    CryptographicAsset => {
                        self.crypto.add(
                            node_id.clone(),
                            comp.name.to_string(),
                            comp.hashes.clone().into_iter().flatten(),
                            comp.try_into()?,
                        );
                    }
                    _ => tracing::error!("Unsupported component type: '{ty}'"),
                }
            }
            Err(e) => {
                return Err(Error::InvalidContent(anyhow::anyhow!(
                    "Invalid component type: {e}"
                )));
            }
        }

        for ancestor in comp
            .pedigree
            .iter()
            .flat_map(|pedigree| pedigree.ancestors.iter().flatten())
        {
            let target = ancestor
                .bom_ref
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string());

            self.add_component(ancestor)?;

            self.add_relation(target, Relationship::AncestorOf, node_id.clone());
        }

        for variant in comp
            .pedigree
            .iter()
            .flat_map(|pedigree| pedigree.variants.iter().flatten())
        {
            let target = variant
                .bom_ref
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string());

            self.add_component(variant)?;

            self.add_relation(node_id.clone(), Relationship::Variant, target);
        }

        Ok(())
    }

    fn add_relation(&mut self, left: String, rel: Relationship, right: String) {
        self.relationships.relate(left, rel, right);
    }

    fn add_cpe(&mut self, node_id: String, cpe: Cpe) {
        let id = cpe.uuid();
        self.refs
            .entry(node_id)
            .or_default()
            .push(PackageReference::Cpe(id));
        self.cpes.add(cpe);
    }

    fn add_purl(&mut self, node_id: String, purl: Purl) {
        self.refs
            .entry(node_id)
            .or_default()
            .push(PackageReference::Purl(purl.clone()));
        self.purls.add(purl);
    }

    fn add_license(&mut self, component: &Component) -> Vec<Uuid> {
        let mut license_uuid = vec![];
        for license in component.licenses.iter().flatten() {
            let license = match license {
                LicenseChoiceItemUrl::Variant0(license) => {
                    self.add_licensing_info(&license.license);

                    let Some(license) = license
                        .license
                        .id
                        .clone()
                        .or_else(|| license.license.name.clone())
                    else {
                        continue;
                    };
                    license
                }
                LicenseChoiceItemUrl::Variant1(license) => license.expression.clone(),
            };

            let license = LicenseInfo { license };

            self.licenses.add(&license);
            license_uuid.push(license.uuid());
        }
        license_uuid
    }

    /// Record a license's extended details (name, text, URL) in `licensing_infos`, so that
    /// license expressions referring to it can be expanded later on.
    ///
    /// Licenses with a BOM-internal identifier or a name are recorded: a plain SPDX `id` is
    /// already self-describing and needs no mapping.
    fn add_licensing_info(&mut self, license: &License) {
        let Some(license_id) = license.bom_ref.as_ref().or(license.name.as_ref()) else {
            return;
        };

        self.licensing_infos.add(&LicensingInfo::with_sbom_id(
            self.sbom_id,
            license.name.clone().unwrap_or_else(|| license_id.clone()),
            license_id.clone(),
            license
                .text
                .as_ref()
                .and_then(license_text)
                .unwrap_or_default(),
            license.url.clone(),
        ));
    }

    fn post_process(&mut self, processors: &mut [Box<dyn Processor>]) {
        PostContext {
            cpes: &self.cpes,
            purls: &self.purls,
            packages: &mut self.packages,
            relationships: &mut self.relationships.rels,
            externals: &mut self.relationships.externals,
        }
        .run(processors);
    }

    fn validate(&self) -> Result<(), Error> {
        let sources = References::new()
            .add_source(&[CYCLONEDX_DOC_REF])
            .add_source(&self.packages)
            .add_source(&self.files)
            .add_source(&self.models)
            .add_source(&self.crypto);
        self.relationships
            .validate(sources)
            .map_err(Error::InvalidContent)
    }

    // order matters to prevent cross-table deadlocks when running
    // concurrent SBOM ingestions. All SBOM loaders must use the same
    // table insertion order.
    async fn create(self, db: &impl ConnectionTrait) -> Result<(), Error> {
        self.licensing_infos.create(db).await?;
        self.licenses.create(db).await?;
        self.purls.create(db).await?;
        self.cpes.create(db).await?;
        self.packages.create(db).await?;
        self.files.create(db).await?;
        self.models.create(db).await?;
        self.crypto.create(db).await?;
        self.devices.create(db).await?;
        self.relationships.create(db).await?;

        // Populate expanded license tables
        populate_expanded_license(self.sbom_id, db).await?;

        Ok(())
    }
}

/// Extract device identifiers from CycloneDX component properties.
///
/// Maps `cdx:device:*` property taxonomy names to `ProductIdentifierType` values.
fn extract_device_identifiers(comp: &Component) -> Vec<(ProductIdentifierType, String)> {
    comp.properties
        .iter()
        .flatten()
        .filter_map(|p| {
            let id_type = match p.name.as_str() {
                "cdx:device:serialNumber" => Some(ProductIdentifierType::SerialNumber),
                "cdx:device:sku" => Some(ProductIdentifierType::Sku),
                "cdx:device:gs1:gmn" => Some(ProductIdentifierType::ModelNumber),
                "cdx:device:gs1:gtin-8"
                | "cdx:device:gs1:gtin-12"
                | "cdx:device:gs1:gtin-13"
                | "cdx:device:gs1:gtin-14" => Some(ProductIdentifierType::Sku),
                _ => None,
            };
            id_type.zip(p.value.clone())
        })
        .collect()
}

/// Type of the components within an SBOM, mostly based on
/// https://cyclonedx.org/docs/1.6/json/#components_items_type
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    strum::EnumString,
    strum::Display,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum ComponentType {
    /// A software application
    Application,
    /// A software framework
    Framework,
    /// A software library
    Library,
    /// A packaging and/or runtime format
    Container,
    /// A runtime environment which interprets or executes software
    Platform,
    /// A software operating system without regard to deployment model
    OperatingSystem,
    /// A hardware device such as a processor or chip-set
    Device,
    /// A special type of software that operates or controls a particular type of device
    DeviceDriver,
    /// A special type of software that provides low-level control over a device's hardware
    Firmware,
    /// A computer file
    File,
    /// A model based on training data that can make predictions or decisions without being explicitly programmed to do so
    MachineLearningModel,
    /// A collection of discrete values that convey information
    Data,
    /// A cryptographic asset including algorithms, protocols, certificates, keys, tokens, and secrets
    CryptographicAsset,
}

#[cfg(test)]
mod test {
    use super::*;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
    use serde_json::json;
    use std::str::FromStr;
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::package_relates_to_package;
    use trustify_test_context::TrustifyContext;

    /// Nested components are contained in the component they are nested in.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn nested_components_are_contained(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let result = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4_assembly.cdx.json")
            .await?;
        let sbom_id = result.id.parse::<Uuid>()?;

        let relationships = package_relates_to_package::Entity::find()
            .filter(package_relates_to_package::Column::SbomId.eq(sbom_id))
            .order_by_asc(package_relates_to_package::Column::Relationship)
            .order_by_asc(package_relates_to_package::Column::LeftNodeId)
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|rel| (rel.left_node_id, rel.relationship, rel.right_node_id))
            .collect::<Vec<_>>();

        let rel = |left: &str, relationship, right: &str| {
            (left.to_string(), relationship, right.to_string())
        };
        assert_eq!(
            relationships,
            vec![
                rel("comp-flip4-device", Relationship::Contains, "comp-flip4-fw"),
                rel("comp-flip4-fw", Relationship::Contains, "comp-bt-lib"),
                rel(
                    "jbl-flip4-root",
                    Relationship::Dependency,
                    "comp-flip4-device"
                ),
                rel(CYCLONEDX_DOC_REF, Relationship::Describes, "jbl-flip4-root"),
            ]
        );

        Ok(())
    }

    /// Devices and firmware are packages: they keep their version, CPE, and product identifiers.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn firmware_is_package(ctx: &TrustifyContext) -> anyhow::Result<()> {
        use trustify_entity::{
            advisory_vulnerability_product_identifier::ProductIdentifierType, cpe,
            sbom_node_cpe_ref, sbom_node_product_identifier, sbom_package,
        };

        let result = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4_assembly.cdx.json")
            .await?;
        let sbom_id = result.id.parse::<Uuid>()?;

        let packages = sbom_package::Entity::find()
            .filter(sbom_package::Column::SbomId.eq(sbom_id))
            .order_by_asc(sbom_package::Column::NodeId)
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|package| (package.node_id, package.version))
            .collect::<Vec<_>>();
        let package = |node: &str, version: &str| (node.to_string(), Some(version.to_string()));
        assert_eq!(
            packages,
            vec![
                package("comp-bt-lib", "3.0.0"),
                package("comp-flip4-device", "1.0.0"),
                package("comp-flip4-fw", "2.3.1"),
                package("jbl-flip4-root", "1.0.0"),
            ]
        );

        let identifiers = sbom_node_product_identifier::Entity::find()
            .filter(sbom_node_product_identifier::Column::SbomId.eq(sbom_id))
            .order_by_asc(sbom_node_product_identifier::Column::NodeId)
            .order_by_asc(sbom_node_product_identifier::Column::Value)
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|id| (id.node_id, id.identifier_type, id.value))
            .collect::<Vec<_>>();
        let id = |node: &str, ty, value: &str| (node.to_string(), ty, value.to_string());
        assert_eq!(
            identifiers,
            vec![
                id(
                    "comp-flip4-device",
                    ProductIdentifierType::Sku,
                    "050036337366"
                ),
                id(
                    "comp-flip4-device",
                    ProductIdentifierType::Sku,
                    "6925281924439"
                ),
                id(
                    "comp-flip4-device",
                    ProductIdentifierType::SerialNumber,
                    "SN-JBL-FLIP4-001"
                ),
                id(
                    "comp-flip4-fw",
                    ProductIdentifierType::ModelNumber,
                    "Flip 4"
                ),
            ]
        );

        // a firmware's CPE
        let result = ctx
            .ingest_document(
                "scenarios/S22_cpe_third_party_openssl_phoenix/sbom/mguard_4302_fw_10.5.0.cdx.json",
            )
            .await?;
        let sbom_id = result.id.parse::<Uuid>()?;
        let mut cpes = sbom_node_cpe_ref::Entity::find()
            .filter(sbom_node_cpe_ref::Column::SbomId.eq(sbom_id))
            .find_also_related(cpe::Entity)
            .all(&ctx.db)
            .await?
            .into_iter()
            .map(|(r, cpe)| (r.node_id, cpe.and_then(|cpe| cpe.product)))
            .collect::<Vec<_>>();
        cpes.sort();
        assert_eq!(
            cpes,
            vec![
                (
                    "firmware".to_string(),
                    Some("fl_mguard_firmware".to_string())
                ),
                ("openssl".to_string(), Some("openssl".to_string())),
            ]
        );

        Ok(())
    }

    #[test]
    fn component_types() {
        use ComponentType::*;

        // The standard conversions
        for (s, t) in [
            ("application", Application),
            ("framework", Framework),
            ("library", Library),
            ("container", Container),
            ("platform", Platform),
            ("operating-system", OperatingSystem),
            ("device", Device),
            ("device-driver", DeviceDriver),
            ("firmware", Firmware),
            ("file", File),
            ("machine-learning-model", MachineLearningModel),
            ("data", Data),
            ("cryptographic-asset", CryptographicAsset),
        ] {
            assert_eq!(ComponentType::from_str(s), Ok(t));
            assert_eq!(t.to_string(), s);
            assert_eq!(json!(t), json!(s));
        }

        // Error handling
        assert!(ComponentType::from_str("missing").is_err());
        assert_eq!(ComponentType::from_str("FiLe"), Ok(File));
    }
}
