use crate::{
    graph::{
        cpe::CpeCreator,
        product::ProductInformation,
        purl::creator::PurlCreator,
        sbom::{
            CycloneDx as CycloneDxProcessor, LicenseCreator, LicenseInfo, NodeInfoParam,
            PackageCreator, PackageLicensenInfo, PackageReference, References, RelationshipCreator,
            SbomContext, SbomInformation,
            processor::{
                InitContext, PostContext, Processor, RedHatProductComponentRelationships,
                RunProcessors,
            },
            sbom_package_license::LicenseCategory,
        },
    },
    service::Error,
};
use sbom_walker::{
    model::sbom::serde_cyclonedx::Sbom,
    report::{ReportSink, check},
};
use sea_orm::ConnectionTrait;
use serde_cyclonedx::cyclonedx::v_1_6::{
    Component, ComponentEvidenceIdentity, CycloneDx, LicenseChoiceUrl, OrganizationalContact,
};
use std::{borrow::Cow, str::FromStr};
use time::{OffsetDateTime, format_description::well_known::Iso8601};
use tracing::instrument;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::relationship::Relationship;
use uuid::Uuid;

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
            .flat_map(|licenses| match licenses {
                LicenseChoiceUrl::Variant0(license) => license
                    .iter()
                    .flat_map(|l| l.license.id.as_ref().or(l.license.name.as_ref()).cloned())
                    .collect::<Vec<_>>(),
                LicenseChoiceUrl::Variant1(license) => {
                    license.iter().map(|l| l.expression.clone()).collect()
                }
            })
            .collect();

        Self {
            node_id: CYCLONEDX_DOC_REF.to_string(),
            name,
            published,
            authors,
            suppliers,
            data_licenses,
        }
    }
}

impl SbomContext {
    #[instrument(skip(connection, sbom, warnings), err(level=tracing::Level::INFO))]
    pub async fn ingest_cyclonedx<C: ConnectionTrait>(
        &self,
        mut sbom: Box<CycloneDx>,
        warnings: &dyn ReportSink,
        connection: &C,
    ) -> Result<(), Error> {
        // pre-flight checks

        check::serde_cyclonedx::all(warnings, &Sbom::V1_6(Cow::Borrowed(&sbom)));

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

        if let Some(metadata) = &mut sbom.metadata {
            if let Some(component) = &mut metadata.component {
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
                            vendor: component.publisher.clone().map(|p| p.to_string()),
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
        }

        // record components

        creator.add_all(&sbom.components);

        // create relationships

        for left in sbom.dependencies.iter().flatten() {
            for target in left.depends_on.iter().flatten() {
                log::debug!("Adding dependency - left: {}, right: {}", left.ref_, target);
                creator.relate(left.ref_.clone(), Relationship::Dependency, target.clone());
            }

            // https://github.com/guacsec/trustify/issues/1131
            // Do we need to qualify this so that only "arch=src" refs
            // get the GeneratedFrom relationship?
            for target in left.provides.iter().flatten() {
                log::debug!("Adding generates - left: {}, right: {}", left.ref_, target);
                creator.relate(left.ref_.clone(), Relationship::Generates, target.clone());
            }
        }

        // create

        creator.create(connection, &mut processors).await?;

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

    pub fn add(&mut self, component: &'a Component) {
        self.components.push(component);
        self.extend(component.components.iter().flatten());
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
        let mut purls = PurlCreator::new();
        let mut cpes = CpeCreator::new();
        let mut packages = PackageCreator::with_capacity(self.sbom_id, self.components.len());
        let mut relationships = RelationshipCreator::with_capacity(
            self.sbom_id,
            self.relations.len(),
            CycloneDxProcessor,
        );
        let mut licenses = LicenseCreator::new();

        for comp in self.components {
            let creator = ComponentCreator::new(
                &mut cpes,
                &mut purls,
                &mut licenses,
                &mut packages,
                &mut relationships,
            );
            creator.create(comp);
        }

        for (left, rel, right) in self.relations {
            relationships.relate(left, rel, right);
        }

        // post process

        PostContext {
            cpes: &cpes,
            purls: &purls,
            packages: &mut packages,
            relationships: &mut relationships.rels,
            externals: &mut relationships.externals,
        }
        .run(processors);

        // validate relationships before inserting

        let sources = References::new()
            .add_source(&[CYCLONEDX_DOC_REF])
            .add_source(&packages);
        relationships
            .validate(sources)
            .map_err(Error::InvalidContent)?;

        // create

        purls.create(db).await?;
        cpes.create(db).await?;
        licenses.create(db).await?;
        packages.create(db).await?;
        relationships.create(db).await?;

        // done

        Ok(())
    }
}

struct ComponentCreator<'a> {
    cpes: &'a mut CpeCreator,
    purls: &'a mut PurlCreator,
    licenses: &'a mut LicenseCreator,
    packages: &'a mut PackageCreator,
    relationships: &'a mut RelationshipCreator<CycloneDxProcessor>,

    refs: Vec<PackageReference>,
}

impl<'a> ComponentCreator<'a> {
    pub fn new(
        cpes: &'a mut CpeCreator,
        purls: &'a mut PurlCreator,
        licenses: &'a mut LicenseCreator,
        packages: &'a mut PackageCreator,
        relationships: &'a mut RelationshipCreator<CycloneDxProcessor>,
    ) -> Self {
        Self {
            cpes,
            purls,
            licenses,
            refs: Default::default(),
            packages,
            relationships,
        }
    }

    pub fn create(mut self, comp: &Component) {
        let node_id = comp
            .bom_ref
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let licenses_uuid = self.add_license(comp);

        if let Some(cpe) = &comp.cpe {
            if let Ok(cpe) = Cpe::from_str(cpe.as_ref()) {
                self.add_cpe(cpe);
            }
        }

        if let Some(purl) = &comp.purl {
            if let Ok(purl) = Purl::from_str(purl.as_ref()) {
                self.add_purl(purl);
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
                        self.add_cpe(cpe);
                    }
                }
                ("purl", Some(purl)) => {
                    if let Ok(purl) = Purl::from_str(purl.as_ref()) {
                        self.add_purl(purl);
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

        self.packages.add(
            NodeInfoParam {
                node_id: node_id.clone(),
                name: comp.name.to_string(),
                group: comp.group.as_ref().map(|v| v.to_string()),
                version: comp.version.as_ref().map(|v| v.to_string()),
                package_license_info: cyclone_licenses,
            },
            self.refs,
            comp.hashes.clone().into_iter().flatten(),
        );

        for ancestor in comp
            .pedigree
            .iter()
            .flat_map(|pedigree| pedigree.ancestors.iter().flatten())
        {
            let target = ancestor
                .bom_ref
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string());

            // create the component

            let creator = Box::new(ComponentCreator::new(
                self.cpes,
                self.purls,
                self.licenses,
                self.packages,
                self.relationships,
            ));

            creator.create(ancestor);

            // and store a relationship
            self.relationships
                .relate(target, Relationship::AncestorOf, node_id.clone());
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

            // create the component

            let creator = Box::new(ComponentCreator::new(
                self.cpes,
                self.purls,
                self.licenses,
                self.packages,
                self.relationships,
            ));

            creator.create(variant);

            self.relationships
                .relate(node_id.clone(), Relationship::Variant, target);
        }
    }

    pub fn add_cpe(&mut self, cpe: Cpe) {
        let id = cpe.uuid();
        self.refs.push(PackageReference::Cpe(id));
        self.cpes.add(cpe);
    }

    pub fn add_purl(&mut self, purl: Purl) {
        self.refs.push(PackageReference::Purl(purl.clone()));
        self.purls.add(purl);
    }

    fn add_license(&mut self, component: &Component) -> Vec<Uuid> {
        let mut license_uuid = vec![];
        if let Some(licenses) = &component.licenses {
            match licenses {
                LicenseChoiceUrl::Variant0(licenses) => {
                    'l: for license in licenses {
                        let license = if let Some(id) = license.license.id.clone() {
                            id
                        } else if let Some(name) = license.license.name.clone() {
                            name
                        } else {
                            continue 'l;
                        };

                        let license = LicenseInfo { license };

                        self.licenses.add(&license);
                        license_uuid.push(license.uuid());
                    }
                }
                LicenseChoiceUrl::Variant1(licenses) => {
                    for license in licenses {
                        let license = LicenseInfo {
                            license: license.expression.clone(),
                        };

                        self.licenses.add(&license);
                        license_uuid.push(license.uuid());
                    }
                }
            }
        }
        license_uuid
    }
}
