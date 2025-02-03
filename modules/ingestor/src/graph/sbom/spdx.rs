use crate::{
    graph::{
        cpe::CpeCreator,
        product::ProductInformation,
        purl::creator::PurlCreator,
        sbom::{
            FileCreator, LicenseCreator, LicenseInfo, PackageCreator, PackageReference, References,
            RelationshipCreator, SbomContext, SbomInformation,
        },
    },
    service::Error,
};
use sbom_walker::report::{check, ReportSink};
use sea_orm::ConnectionTrait;
use spdx_rs::models::{RelationshipType, SPDX};
use std::{collections::HashMap, str::FromStr};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::relationship::Relationship;

pub struct Information<'a>(pub &'a SPDX);

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
            data_licenses: vec![value.0.document_creation_information.data_license.clone()],
        }
    }
}

impl SbomContext {
    #[instrument(skip(db, sbom_data, warnings), ret)]
    pub async fn ingest_spdx<C: ConnectionTrait>(
        &self,
        sbom_data: SPDX,
        warnings: &dyn ReportSink,
        db: &C,
    ) -> Result<(), Error> {
        // pre-flight checks

        check::spdx::all(warnings, &sbom_data);

        // prepare packages

        let mut purls = PurlCreator::new();
        let mut cpes = CpeCreator::new();

        // prepare relationships

        let mut relationships =
            RelationshipCreator::with_capacity(self.sbom.sbom_id, sbom_data.relationships.len());

        let mut product_packages = vec![];

        for describes in sbom_data.document_creation_information.document_describes {
            relationships.relate(
                describes,
                Relationship::Describes,
                sbom_data
                    .document_creation_information
                    .spdx_identifier
                    .clone(),
            );
            product_packages.push(
                sbom_data
                    .document_creation_information
                    .spdx_identifier
                    .clone(),
            );
        }

        for rel in &sbom_data.relationships {
            let Ok(SpdxRelationship(left, rel, right)) = rel.try_into() else {
                continue;
            };

            relationships.relate(left.to_string(), rel, right.to_string());

            if rel == Relationship::Describes {
                product_packages.push(right.to_string());
            }
        }

        let mut licenses = LicenseCreator::new();

        let license_refs = sbom_data
            .other_licensing_information_detected
            .iter()
            .map(|e| (e.license_identifier.clone(), e.license_name.clone()))
            .collect::<HashMap<_, _>>();

        let mut packages =
            PackageCreator::with_capacity(self.sbom.sbom_id, sbom_data.package_information.len());

        for package in &sbom_data.package_information {
            let declared_license_info = package.declared_license.as_ref().map(|e| LicenseInfo {
                license: e.to_string(),
                refs: license_refs.clone(),
            });

            let concluded_license_info = package.concluded_license.as_ref().map(|e| LicenseInfo {
                license: e.to_string(),
                refs: license_refs.clone(),
            });

            let mut refs = Vec::new();
            let mut license_refs = Vec::new();

            if let Some(declared_license) = declared_license_info {
                if declared_license.license != "NOASSERTION" {
                    licenses.add(&declared_license);
                    license_refs.push(declared_license);
                }
            }

            if let Some(concluded_license) = concluded_license_info {
                if concluded_license.license != "NOASSERTION" {
                    licenses.add(&concluded_license);
                    license_refs.push(concluded_license);
                }
            }

            let mut product_cpe = None;

            for r in &package.external_reference {
                match &*r.reference_type {
                    "purl" => match Purl::from_str(&r.reference_locator) {
                        Ok(purl) => {
                            refs.push(PackageReference::Purl {
                                versioned_purl: purl.version_uuid(),
                                qualified_purl: purl.qualifier_uuid(),
                            });
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

            packages.add(
                package.package_spdx_identifier.clone(),
                package.package_name.clone(),
                package.package_version.clone(),
                refs,
                license_refs,
            );

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
        }

        // prepare files

        let mut files =
            FileCreator::with_capacity(self.sbom.sbom_id, sbom_data.file_information.len());

        for file in sbom_data.file_information {
            files.add(file.file_spdx_identifier, file.file_name);
        }

        // create all purls and CPEs

        licenses.create(db).await?;
        purls.create(db).await?;
        cpes.create(db).await?;

        // validate relationships before inserting

        let doc_id = [sbom_data
            .document_creation_information
            .spdx_identifier
            .as_str()];
        let sources = References::new()
            .add_source(&doc_id)
            .add_source(&packages)
            .add_source(&files);
        relationships.validate(sources).map_err(Error::Generic)?;

        // create packages, files, and relationships

        packages.create(db).await?;
        files.create(db).await?;
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
