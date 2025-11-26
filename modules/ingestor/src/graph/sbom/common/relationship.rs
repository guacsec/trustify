use crate::graph::sbom::{Discriminator, ExternalNodeCreator};
use anyhow::bail;
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use spdx_rs::models::{Algorithm, ExternalDocumentReference};
use std::collections::HashSet;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::sbom_external_node::{DiscriminatorType, ExternalType};
use trustify_entity::{package_relates_to_package, relationship::Relationship};
use uuid::Uuid;

pub struct ExternalReference {
    pub external_type: ExternalType,
    pub external_document_id: String,
    pub external_node_id: String,
    pub discriminator: Option<Discriminator>,
}

pub trait ExternalReferenceProcessor {
    fn eval_external_node(&self, node_id: &str) -> Option<ExternalReference>;
}

/// A no-op implementation
impl ExternalReferenceProcessor for () {
    fn eval_external_node(&self, _node_id: &str) -> Option<ExternalReference> {
        None
    }
}

pub struct Spdx<'a>(pub &'a [ExternalDocumentReference]);

impl ExternalReferenceProcessor for Spdx<'_> {
    fn eval_external_node(&self, node_id: &str) -> Option<ExternalReference> {
        match node_id.split_once(":") {
            Some((external_document_ref, external_node_id))
                if node_id.starts_with("DocumentRef-") =>
            {
                let external = self
                    .0
                    .iter()
                    .find(|e| e.id_string == external_document_ref)?;

                let discriminator = match external.checksum.algorithm {
                    Algorithm::SHA256 => Some(Discriminator::new(
                        DiscriminatorType::Sha256,
                        external.checksum.value.clone(),
                    )),
                    Algorithm::SHA384 => Some(Discriminator::new(
                        DiscriminatorType::Sha384,
                        external.checksum.value.clone(),
                    )),
                    Algorithm::SHA512 => Some(Discriminator::new(
                        DiscriminatorType::Sha512,
                        external.checksum.value.clone(),
                    )),
                    _ => None,
                };

                Some(ExternalReference {
                    external_type: ExternalType::SPDX,
                    external_document_id: external.spdx_document_uri.clone(),
                    external_node_id: external_node_id.to_string(),
                    discriminator,
                })
            }
            _ => None,
        }
    }
}

pub struct CycloneDx;

impl ExternalReferenceProcessor for CycloneDx {
    fn eval_external_node(&self, node_id: &str) -> Option<ExternalReference> {
        let reference = node_id.strip_prefix("urn:cdx:")?;
        let (serial, version) = reference.split_once('/')?;
        let (version, component) = version.split_once('#')?;

        Some(ExternalReference {
            external_type: ExternalType::CycloneDx,
            external_document_id: serial.to_string(),
            external_node_id: component.to_string(),
            discriminator: Some(Discriminator::new(
                DiscriminatorType::CycloneDxVersion,
                version.to_string(),
            )),
        })
    }
}

// Creator of relationships.
pub struct RelationshipCreator<ER: ExternalReferenceProcessor> {
    sbom_id: Uuid,

    pub(crate) externals: ExternalNodeCreator,
    pub(crate) rels: Vec<package_relates_to_package::ActiveModel>,

    external_references: ER,
}

impl<ER: ExternalReferenceProcessor> RelationshipCreator<ER> {
    pub fn new(sbom_id: Uuid, external_references: ER) -> Self {
        Self {
            sbom_id,
            externals: ExternalNodeCreator::new(sbom_id),

            rels: Vec::new(),
            external_references,
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity_rel: usize, external_references: ER) -> Self {
        Self {
            sbom_id,
            externals: ExternalNodeCreator::new(sbom_id),

            rels: Vec::with_capacity(capacity_rel),
            external_references,
        }
    }

    /// Record a relationship.
    ///
    /// To store those relationships, it is required to call [`Self::create`].
    ///
    /// It is possible to record invalid relationship targets, which might fail the actual creation
    /// process later on. It is possible to validate relationships using [`Self::validate`].
    pub fn relate(&mut self, left: String, rel: Relationship, right: String) {
        // The idea of `NOASSERTION` is to state that there is a relationship, but the element it
        // relates to is unknown.
        //
        // The idea of `NONE` is to state there it is known that there is no relationship to that
        // element.
        //
        // At the moment, both those pieces of information don't add value to our system and
        // only cause complexity when storing. So we simply drop it.

        // TODO: If, in the future, we want to have this information, this should be removed.

        log::trace!("Recording relationship - left: {left}, rel: {rel}, right: {right}");

        if let ("NONE" | "NOASSERTION", _) | (_, "NONE" | "NOASSERTION") = (&*left, &*right) {
            // either side is NONE or NOASSERTION, which we don't ingest at the moment.
            return;
        }

        self.handle_ext(&left);
        self.handle_ext(&right);

        self.rels.push(package_relates_to_package::ActiveModel {
            sbom_id: Set(self.sbom_id),
            left_node_id: Set(left),
            relationship: Set(rel),
            right_node_id: Set(right),
        });
    }

    fn handle_ext(&mut self, node_id: &str) {
        if let Some(externals) = self.external_references.eval_external_node(node_id) {
            self.externals.add(node_id, externals);
        }
    }

    /// Pre-flight check to see if all relationships can be inserted.
    ///
    /// This expects a source of references to check against. If creating a fresh set of nodes and
    /// relationships, these sources would most likely be the creators (like [`super::PackageCreator`]).
    /// If nodes already exist in the database, those nodes would need to be extracted and provided.
    #[instrument(skip_all, ret)]
    pub fn validate(&self, sources: References) -> Result<(), anyhow::Error> {
        let sources = sources.add_source(&self.externals);

        for rel in &self.rels {
            if let Set(left) = &rel.left_node_id
                && !sources.refs.contains(left.as_str())
            {
                bail!("Invalid reference: {left}");
            }
            if let Set(right) = &rel.right_node_id
                && !sources.refs.contains(right.as_str())
            {
                bail!("Invalid reference: {right}");
            }
        }

        Ok(())
    }

    #[instrument(skip_all, fields(num=self.rels.len()), err(level=tracing::Level::INFO))]
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        self.externals.create(db).await?;

        for batch in &self.rels.into_iter().chunked() {
            package_relates_to_package::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        package_relates_to_package::Column::SbomId,
                        package_relates_to_package::Column::LeftNodeId,
                        package_relates_to_package::Column::Relationship,
                        package_relates_to_package::Column::RightNodeId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct References<'a> {
    pub refs: HashSet<&'a str>,
}

impl<'a> IntoIterator for References<'a> {
    type Item = &'a str;
    type IntoIter = std::collections::hash_set::IntoIter<&'a str>;

    fn into_iter(self) -> Self::IntoIter {
        self.refs.into_iter()
    }
}

impl<'a> References<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_source<S>(mut self, source: &'a S) -> Self
    where
        S: ReferenceSource<'a> + 'a,
    {
        self.refs.extend(source.references());
        self
    }
}

/// A source of SBOM node references for validating.
pub trait ReferenceSource<'a> {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str>;
}

impl<'a> ReferenceSource<'a> for &'a [&'a str] {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.iter().copied()
    }
}

impl<'a, const N: usize> ReferenceSource<'a> for [&'a str; N] {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.iter().copied()
    }
}
