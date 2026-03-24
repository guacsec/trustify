use crate::graph::sbom::common::node::NodeCreator;
use crate::graph::sbom::{Checksum, ReferenceSource};
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{sbom_package, sbom_package_license, sbom_package_license::LicenseCategory};
use uuid::Uuid;

use super::PackageReference;
use super::reference::ReferenceCreator;

// Creator of packages and relationships.
pub struct PackageCreator {
    sbom_id: Uuid,
    pub(crate) nodes: NodeCreator,
    pub(crate) refs: ReferenceCreator,
    pub(crate) packages: Vec<sbom_package::ActiveModel>,
    pub(crate) sbom_package_licenses: Vec<sbom_package_license::ActiveModel>,
}

pub struct NodeInfoParam {
    pub node_id: String,
    pub name: String,
    pub group: Option<String>,
    pub version: Option<String>,
    pub package_license_info: Vec<PackageLicensenInfo>,
}

pub struct PackageLicensenInfo {
    pub license_id: Uuid,
    pub license_type: LicenseCategory,
}

impl PackageCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::new(sbom_id),
            refs: ReferenceCreator::new(sbom_id),
            packages: Vec::new(),
            sbom_package_licenses: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity_packages: usize) -> Self {
        Self {
            sbom_id,
            nodes: NodeCreator::with_capacity(sbom_id, capacity_packages),
            refs: ReferenceCreator::with_capacity(sbom_id, capacity_packages),
            packages: Vec::with_capacity(capacity_packages),
            sbom_package_licenses: Vec::with_capacity(capacity_packages),
        }
    }

    pub fn add<'a, I, C>(
        &mut self,
        node_info: NodeInfoParam,
        refs: impl Iterator<Item = &'a PackageReference>,
        checksums: I,
    ) where
        I: IntoIterator<Item = C>,
        C: Into<Checksum>,
    {
        self.refs.add(&node_info.node_id, refs);
        self.nodes
            .add(node_info.node_id.clone(), node_info.name, checksums);

        self.packages.push(sbom_package::ActiveModel {
            sbom_id: Set(self.sbom_id),
            group: Set(node_info.group),
            node_id: Set(node_info.node_id.clone()),
            version: Set(node_info.version),
        });

        for package_license in node_info.package_license_info {
            self.sbom_package_licenses
                .push(sbom_package_license::ActiveModel {
                    sbom_id: Set(self.sbom_id),
                    node_id: Set(node_info.node_id.clone()),
                    license_id: Set(package_license.license_id),
                    license_type: Set(package_license.license_type),
                });
        }
    }

    #[instrument(
        skip_all,
        fields(
            num_packages=self.packages.len(),
        ),
        err(level=tracing::Level::INFO)
    )]
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        self.nodes.create(db).await?;
        self.refs.create(db).await?;

        for batch in &self.packages.into_iter().chunked() {
            sbom_package::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_package::Column::SbomId,
                        sbom_package::Column::NodeId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        for batch in &self.sbom_package_licenses.into_iter().chunked() {
            sbom_package_license::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_package_license::Column::SbomId,
                        sbom_package_license::Column::NodeId,
                        sbom_package_license::Column::LicenseId,
                        sbom_package_license::Column::LicenseType,
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

impl<'a> ReferenceSource<'a> for PackageCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes.references()
    }
}
