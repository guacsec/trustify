use crate::graph::{
    cpe::CpeCreator,
    sbom::{
        ExternalReference,
        processor::{InitContext, PostContext},
    },
};
use sea_orm::ActiveValue::Set;
use std::collections::HashSet;
use tracing::instrument;
use trustify_entity::{
    package_relates_to_package, relationship::Relationship, sbom_external_node::ExternalType,
    sbom_package, sbom_package_cpe_ref,
};

#[derive(Default, Debug)]
pub struct RedHatProductComponentRelationships {
    active: bool,
    document_node_id: String,
}

impl RedHatProductComponentRelationships {
    pub fn new() -> Self {
        Default::default()
    }
}

const SUPPLIERS: &[&str] = &["Red Hat", "Organization: Red Hat"];

impl super::Processor for RedHatProductComponentRelationships {
    fn init(
        &mut self,
        InitContext {
            suppliers,
            document_node_id,
        }: InitContext,
    ) {
        self.document_node_id = document_node_id.to_string();

        for supplier in suppliers {
            if SUPPLIERS.contains(supplier) {
                self.active = true;
            }
        }
    }

    #[instrument(skip_all, fields(active=self.active))]
    fn post(
        &self,
        PostContext {
            cpes,
            purls: _,
            packages,
            relationships,
            externals,
        }: &mut PostContext,
    ) {
        if !self.active {
            return;
        }

        log::debug!("Processing Red Hat inter-document relationships");

        // the node IDs of top level packages
        let top_level: HashSet<String> = packages
            .packages
            .iter()
            .filter_map(|package| {
                is_relevant(
                    &self.document_node_id,
                    cpes,
                    &packages.cpe_refs,
                    package,
                    relationships,
                )
            })
            .collect();

        log::debug!("Top-level components: {top_level:?}");

        let mut new_rels = vec![];

        for rel in relationships.iter() {
            let package_relates_to_package::ActiveModel {
                sbom_id: _,
                left_node_id: Set(left_node_id),
                relationship: Set(relationship),
                right_node_id: Set(right_node_id),
            } = rel
            else {
                continue;
            };

            // the source node id
            let prod_node_id = left_node_id;
            // the internal target node id, which we turn into the external target id
            let comp_node_id = right_node_id;

            if log::log_enabled!(log::Level::Trace) {
                log::trace!(
                    "rel: {relationship:?}, top-level: {}",
                    top_level.contains(prod_node_id)
                );
            }

            if relationship != &Relationship::Variant {
                // if it is a top level component, described by the SBOM, packaging components,
                // then we process those
                if !((relationship == &Relationship::Generates
                    || relationship == &Relationship::Package)
                    && top_level.contains(prod_node_id))
                {
                    continue;
                }
            }

            // artificial external node ID
            let ext_comp_node_id = format!("{prod_node_id}:{comp_node_id}");

            // add external link
            externals.add(
                &ext_comp_node_id,
                ExternalReference {
                    external_type: ExternalType::RedHatProductComponent,
                    external_document_id: comp_node_id.clone(),
                    external_node_id: comp_node_id.clone(),
                    discriminator: None,
                },
            );
            new_rels.push(package_relates_to_package::ActiveModel {
                sbom_id: rel.sbom_id.clone(),
                left_node_id: Set(comp_node_id.to_string()),
                relationship: Set(Relationship::Package),
                right_node_id: Set(ext_comp_node_id),
            });
        }

        log::debug!("New relationships to add: {new_rels:?}");

        relationships.extend(new_rels);
    }
}

fn is_relevant(
    document_node_id: &str,
    cpes: &CpeCreator,
    cpes_refs: &[sbom_package_cpe_ref::ActiveModel],
    package: &sbom_package::ActiveModel,
    relationships: &[package_relates_to_package::ActiveModel],
) -> Option<String> {
    let Set(node_id) = &package.node_id else {
        return None;
    };

    // is root: described by the SBOM

    fn is_root(
        node_id: &str,
        document_node_id: &str,
        relationships: &[package_relates_to_package::ActiveModel],
    ) -> bool {
        for relationship in relationships {
            let package_relates_to_package::ActiveModel {
                sbom_id: _,
                left_node_id: Set(left_node_id),
                relationship: Set(relationship),
                right_node_id: Set(right_node_id),
            } = relationship
            else {
                continue;
            };

            log::trace!(
                "Checking node: {node_id} - left: {left_node_id}, rel: {relationship}, right: {right_node_id}"
            );

            if relationship == &Relationship::Describes
                && (left_node_id == document_node_id)
                && right_node_id == node_id
            {
                return true;
            }
        }

        false
    }

    if !is_root(node_id, document_node_id, relationships) {
        return None;
    }

    //check if we have imageindex variant
    let mut has_imageindex_variant: bool = false;
    for relationship in relationships {
        if let sea_orm::ActiveValue::Set(Relationship::Variant) = relationship.relationship {
            has_imageindex_variant = true;
        }
    }

    // it must have CPEs if not imageindex
    if !has_imageindex_variant && find_cpes(cpes, cpes_refs, node_id).is_empty() {
        return None;
    }

    Some(node_id.to_string())
}

fn find_cpes(
    cpes: &CpeCreator,
    cpes_refs: &[sbom_package_cpe_ref::ActiveModel],
    node_id: &str,
) -> Vec<String> {
    cpes_refs
        .iter()
        .filter_map(|cpe| match (&cpe.node_id, &cpe.cpe_id) {
            (Set(cpe_node_id), Set(cpe_id)) if cpe_node_id == node_id => Some(cpe_id),
            _ => None,
        })
        .filter_map(|cpe| cpes.find(*cpe))
        .map(|cpe| cpe.to_string())
        .collect()
}
