use crate::{
    graph::{
        cpe::CpeCreator,
        product::ProductInformation,
        purl::creator::PurlCreator,
        sbom::{
            LicenseCreator, LicenseInfo, LicensingInfo, LicensingInfoCreator, NodeCreator,
            NodeInfoParam, PackageLicensenInfo, PackageReference, References, RelationshipCreator,
            SbomContext, SbomInformation, Spdx,
            processor::{
                InitContext, PostContext, Processor, RedHatProductComponentRelationships,
                RunProcessors,
            },
        },
    },
    service::Error,
};
use sbom_walker::report::{ReportSink, check};
use sea_orm::ConnectionTrait;
use spdx_rs::models::{RelationshipType, SPDX};
use std::collections::HashSet;
use std::str::FromStr;
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::{relationship::Relationship, sbom_package_license::LicenseCategory};

pub struct Information<'a>(pub &'a SPDX);

/// get the describing packages
fn describing_packages(sbom: &SPDX) -> HashSet<&str> {
    let mut packages = HashSet::<&str>::new();

    for rel in &sbom.relationships {
        match rel.relationship_type {
            RelationshipType::Describes => {
                packages.insert(&rel.spdx_element_id);
            }
            RelationshipType::DescribedBy => {
                packages.insert(&rel.related_spdx_element);
            }
            _ => continue,
        }
    }

    packages.extend(
        sbom.document_creation_information
            .document_describes
            .iter()
            .map(|s| s.as_str()),
    );

    packages
}

/// Extract suppliers for a SPDX SBOM by collecting suppliers of describing packages
fn suppliers(sbom: &SPDX) -> Vec<String> {
    // packages describing the SBOM
    let describing = describing_packages(sbom);

    // collect suppliers for matching packages
    let mut result = HashSet::new();
    for p in &sbom.package_information {
        if !describing.contains(p.package_spdx_identifier.as_str()) {
            continue;
        }
        if let Some(supplier) = &p.package_supplier {
            result.insert(supplier.clone());
        }
    }

    Vec::from_iter(result)
}

impl<'a> From<Information<'a>> for SbomInformation {
    fn from(value: Information<'a>) -> Self {
        let sbom = value.0;

        let published = OffsetDateTime::from_unix_timestamp(
            sbom.document_creation_information
                .creation_info
                .created
                .timestamp(),
        )
        .ok();

        Self {
            node_id: sbom.document_creation_information.spdx_identifier.clone(),
            name: sbom.document_creation_information.document_name.clone(),
            published,
            authors: value
                .0
                .document_creation_information
                .creation_info
                .creators
                .clone(),
            suppliers: suppliers(sbom),
            data_licenses: vec![value.0.document_creation_information.data_license.clone()],
            properties: Default::default(),
        }
    }
}

impl SbomContext {
    #[instrument(skip(db, sbom_data, warnings), ret(level=tracing::Level::DEBUG))]
    pub async fn ingest_spdx<C: ConnectionTrait>(
        &self,
        sbom_data: SPDX,
        warnings: &dyn ReportSink,
        db: &C,
    ) -> Result<(), Error> {
        // pre-flight checks

        check::spdx::all(warnings, &sbom_data);

        // processors

        // TODO: find a way to dynamically set up processors
        let mut processors: Vec<Box<dyn Processor>> =
            vec![Box::new(RedHatProductComponentRelationships::new())];

        // init processors

        let suppliers = sbom_data
            .document_creation_information
            .creation_info
            .creators
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>();
        InitContext {
            document_node_id: &sbom_data.document_creation_information.spdx_identifier,
            suppliers: &suppliers,
        }
        .run(&mut processors);

        // prepare packages

        let mut purls = PurlCreator::new();
        let mut cpes = CpeCreator::new();

        // prepare relationships

        let mut relationships = RelationshipCreator::with_capacity(
            self.sbom.sbom_id,
            sbom_data.relationships.len(),
            Spdx(
                &sbom_data
                    .document_creation_information
                    .external_document_references,
            ),
        );

        for described in &sbom_data.document_creation_information.document_describes {
            log::debug!("Adding 'document_describes': {described}");
            relationships.relate(
                sbom_data
                    .document_creation_information
                    .spdx_identifier
                    .clone(),
                Relationship::Describes,
                described.clone(),
            );
        }

        let mut product_packages = vec![];
        product_packages.push(
            sbom_data
                .document_creation_information
                .spdx_identifier
                .clone(),
        );

        for rel in &sbom_data.relationships {
            log::debug!("Relationship: {rel:?}");

            let Ok(SpdxRelationship(left, rel, right)) = rel.try_into() else {
                continue;
            };

            relationships.relate(left.to_string(), rel, right.to_string());

            if rel == Relationship::Describes {
                product_packages.push(right.to_string());
            }
        }

        let mut licenses = LicenseCreator::new();
        let mut license_extracted_refs = LicensingInfoCreator::new();

        for license_ref in sbom_data.other_licensing_information_detected.clone() {
            let extracted_licensing_info = &LicensingInfo::with_sbom_id(
                self.sbom.sbom_id,
                license_ref.license_name,
                license_ref.license_identifier.clone(),
                license_ref.extracted_text,
                license_ref.license_comment,
            );
            license_extracted_refs.add(extracted_licensing_info);
        }

        let mut nodes = NodeCreator::new(self.sbom.sbom_id);

        for package in sbom_data.package_information {
            let declared_license_info = package.declared_license.as_ref().map(|e| LicenseInfo {
                license: e.to_string(),
            });

            let concluded_license_info = package.concluded_license.as_ref().map(|e| LicenseInfo {
                license: e.to_string(),
            });

            let mut refs = Vec::new();
            // let mut license_refs = Vec::new();
            let mut declared_license_ref = None;
            let mut concluded_license_ref = None;
            if let Some(declared_license) = declared_license_info {
                let _ = declared_license_ref.insert(declared_license.clone());
                licenses.add(&declared_license);
            }

            if let Some(concluded_license) = concluded_license_info {
                let _ = concluded_license_ref.insert(concluded_license.clone());
                licenses.add(&concluded_license);
            }

            let mut product_cpe = None;

            for r in &package.external_reference {
                match &*r.reference_type {
                    "purl" => match Purl::from_str(&r.reference_locator) {
                        Ok(purl) => {
                            refs.push(PackageReference::Purl(purl.clone()));
                            purls.add(purl);
                        }
                        Err(err) => {
                            log::info!("Failed to parse PURL ({}): {err}", r.reference_locator);
                        }
                    },
                    "cpe22Type" => match Cpe::from_str(&r.reference_locator) {
                        Ok(cpe) => {
                            refs.push(PackageReference::Cpe(cpe.uuid()));
                            cpes.add(cpe.clone());
                            // TODO: Product can have multiple CPE references
                            // possibly leading to multiple cpe keys.
                            // We need to investigate how to improve the design
                            // to support these use cases.
                            product_cpe = product_cpe.or(Some(cpe));
                        }
                        Err(err) => {
                            log::info!("Failed to parse CPE ({}): {err}", r.reference_locator);
                        }
                    },
                    _ => {}
                }
            }

            if product_packages.contains(&package.package_spdx_identifier) {
                let pr = self
                    .graph
                    .ingest_product(
                        package.package_name.clone(),
                        ProductInformation {
                            vendor: package.package_supplier.clone(),
                            cpe: product_cpe,
                        },
                        db,
                    )
                    .await?;

                if let Some(ver) = package.package_version.clone() {
                    pr.ingest_product_version(ver, Some(self.sbom.sbom_id), db)
                        .await?;
                }
            }

            let mut package_license_info = Vec::new();
            package_license_info.append(
                &mut declared_license_ref
                    .iter()
                    .map(|license| PackageLicensenInfo {
                        license_id: license.uuid(),
                        license_type: LicenseCategory::Declared,
                    })
                    .collect::<Vec<_>>(),
            );
            package_license_info.append(
                &mut concluded_license_ref
                    .iter()
                    .map(|license| PackageLicensenInfo {
                        license_id: license.uuid(),
                        license_type: LicenseCategory::Concluded,
                    })
                    .collect::<Vec<_>>(),
            );

            nodes.add_package(
                NodeInfoParam {
                    node_id: package.package_spdx_identifier,
                    group: None,
                    version: package.package_version,
                    package_license_info,
                },
                package.package_name,
                package.package_checksum,
                refs.iter(),
            );
        }

        // prepare files

        for file in sbom_data.file_information {
            nodes.add_file(
                file.file_spdx_identifier,
                file.file_name,
                file.file_checksum,
            );
        }

        // run post-processor

        PostContext {
            cpes: &cpes,
            purls: &purls,
            packages: nodes.get_packages_mut(),
            relationships: &mut relationships.rels,
            externals: &mut relationships.externals,
        }
        .run(&mut processors);

        // create all purls and CPEs

        license_extracted_refs.create(db).await?;
        licenses.create(db).await?;
        purls.create(db).await?;
        cpes.create(db).await?;

        // validate relationships before inserting

        let doc_id = [sbom_data
            .document_creation_information
            .spdx_identifier
            .as_str()];
        let sources = References::new().add_source(&doc_id).add_source(&nodes);
        relationships
            .validate(sources)
            .map_err(Error::InvalidContent)?;

        // create nodes, packages, files, and relationships
        nodes.create(db).await?;
        relationships.create(db).await?;

        // done

        Ok(())
    }
}

pub struct SpdxRelationship<'spdx>(pub &'spdx str, pub Relationship, pub &'spdx str);

impl<'spdx> TryFrom<(&'spdx str, &'spdx RelationshipType, &'spdx str)> for SpdxRelationship<'spdx> {
    type Error = ();

    fn try_from(
        (left, rel, right): (&'spdx str, &'spdx RelationshipType, &'spdx str),
    ) -> Result<Self, Self::Error> {
        match rel {
            RelationshipType::AncestorOf => Ok((left, Relationship::AncestorOf, right)),
            RelationshipType::BuildToolOf => Ok((right, Relationship::BuildTool, left)),
            RelationshipType::ContainedBy => Ok((right, Relationship::Contains, left)),
            RelationshipType::Contains => Ok((left, Relationship::Contains, right)),
            RelationshipType::DependencyOf => Ok((right, Relationship::Dependency, left)),
            RelationshipType::DependsOn => Ok((left, Relationship::Dependency, right)),
            RelationshipType::DescendantOf => Ok((right, Relationship::AncestorOf, left)),
            RelationshipType::DescribedBy => Ok((right, Relationship::Describes, left)),
            RelationshipType::Describes => Ok((left, Relationship::Describes, right)),
            RelationshipType::DevDependencyOf => Ok((right, Relationship::DevDependency, left)),
            RelationshipType::DevToolOf => Ok((right, Relationship::DevTool, left)),
            RelationshipType::ExampleOf => Ok((right, Relationship::Example, left)),
            RelationshipType::GeneratedFrom => Ok((right, Relationship::Generates, left)),
            RelationshipType::Generates => Ok((left, Relationship::Generates, right)),
            RelationshipType::OptionalDependencyOf => {
                Ok((right, Relationship::OptionalDependency, left))
            }
            RelationshipType::PackageOf => Ok((right, Relationship::Package, left)),
            RelationshipType::ProvidedDependencyOf => {
                Ok((right, Relationship::ProvidedDependency, left))
            }
            RelationshipType::RuntimeDependencyOf => {
                Ok((right, Relationship::RuntimeDependency, left))
            }
            RelationshipType::TestDependencyOf => Ok((right, Relationship::TestDependency, left)),
            RelationshipType::VariantOf => Ok((right, Relationship::Variant, left)),
            _ => Err(()),
        }
        .map(|(left, rel, right)| Self(left, rel, right))
    }
}

impl<'spdx> TryFrom<&'spdx spdx_rs::models::Relationship> for SpdxRelationship<'spdx> {
    type Error = ();

    fn try_from(value: &'spdx spdx_rs::models::Relationship) -> Result<Self, Self::Error> {
        (
            value.spdx_element_id.as_str(),
            &value.relationship_type,
            value.related_spdx_element.as_str(),
        )
            .try_into()
    }
}
