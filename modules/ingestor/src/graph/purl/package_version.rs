//! Support for *versioned* package.

use crate::graph::{
    error::Error,
    purl::{PackageContext, qualified_package::QualifiedPackageContext},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use std::fmt::{Debug, Formatter};
use trustify_common::purl::Purl;
use trustify_entity::{self as entity, qualified_purl::Qualifiers, versioned_purl};

/// Live context for a package version.
#[derive(Clone)]
pub struct PackageVersionContext<'g> {
    pub package: PackageContext<'g>,
    pub package_version: entity::versioned_purl::Model,
}

impl Debug for PackageVersionContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version.fmt(f)
    }
}

impl<'g> PackageVersionContext<'g> {
    pub fn new(package: &PackageContext<'g>, package_version: versioned_purl::Model) -> Self {
        Self {
            package: package.clone(),
            package_version,
        }
    }

    pub async fn ingest_qualified_package<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<QualifiedPackageContext<'g>, Error> {
        if let Some(found) = self.get_qualified_package(purl, connection).await? {
            return Ok(found);
        }
        let cp = purl.clone().into();
        // No appropriate qualified package, create one.
        let qualified_package = entity::qualified_purl::ActiveModel {
            id: Set(purl.qualifier_uuid()),
            versioned_purl_id: Set(self.package_version.id),
            qualifiers: Set(Qualifiers(purl.qualifiers.clone())),
            purl: Set(cp),
        };

        let qualified_package = qualified_package.insert(connection).await?;

        Ok(QualifiedPackageContext::new(self, qualified_package))
    }

    pub async fn get_qualified_package<C: ConnectionTrait>(
        &self,
        purl: &Purl,
        connection: &C,
    ) -> Result<Option<QualifiedPackageContext<'g>>, Error> {
        let found = entity::qualified_purl::Entity::find()
            .filter(entity::qualified_purl::Column::VersionedPurlId.eq(self.package_version.id))
            .filter(
                entity::qualified_purl::Column::Qualifiers.eq(Qualifiers(purl.qualifiers.clone())),
            )
            .one(connection)
            .await?;

        Ok(found.map(|model| QualifiedPackageContext::new(self, model)))
    }
}
