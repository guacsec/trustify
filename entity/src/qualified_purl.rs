use sea_orm::{FromJsonQueryResult, FromQueryResult, entity::prelude::*};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trustify_common::purl::Purl;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "qualified_purl")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub versioned_purl_id: Uuid,
    pub qualifiers: Qualifiers,
    #[sea_orm(column_type = "JsonBinary")]
    pub purl: CanonicalPurl,
}

/// A purl struct for storing in the database.
///
/// The difference between [`Self`] and [`Purl`] is the serialization format. [`Self`] is intended
/// to be serialized into a JSON structure, so that it is possible to use JSON queries on this
/// field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, FromJsonQueryResult, Serialize, Deserialize)]
pub struct CanonicalPurl {
    pub ty: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub qualifiers: BTreeMap<String, String>,
}

impl From<Purl> for CanonicalPurl {
    fn from(purl: Purl) -> Self {
        CanonicalPurl {
            ty: purl.ty,
            namespace: purl.namespace,
            name: purl.name,
            version: purl.version,
            qualifiers: purl.qualifiers,
        }
    }
}
impl From<CanonicalPurl> for Purl {
    fn from(purl: CanonicalPurl) -> Self {
        Purl {
            ty: purl.ty,
            namespace: purl.namespace,
            name: purl.name,
            version: purl.version,
            qualifiers: purl.qualifiers,
        }
    }
}

#[derive(
    Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, FromJsonQueryResult,
)]
pub struct Qualifiers(pub BTreeMap<String, String>);

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::versioned_purl::Entity",
        from = "super::qualified_purl::Column::VersionedPurlId"
        to = "super::versioned_purl::Column::Id"
    )]
    VersionedPurl,
    #[sea_orm(
        belongs_to = "super::sbom_package_purl_ref::Entity",
        from = "Column::Id",
        to = "super::sbom_package_purl_ref::Column::QualifiedPurlId"
    )]
    SbomPackage,
}

impl Related<super::versioned_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionedPurl.def()
    }
}

impl Related<super::sbom_package_purl_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SbomPackage.def()
    }
}

impl Related<super::base_purl::Entity> for Entity {
    fn to() -> RelationDef {
        super::versioned_purl::Relation::BasePurl.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(FromQueryResult, Debug)]
pub struct PackageType {
    pub package_type: String,
}

#[derive(FromQueryResult, Debug)]
pub struct PackageNamespace {
    pub package_namespace: String,
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::{from_str, json, to_string};
    use test_log::test;

    #[test]
    fn test_canonical_purl() {
        let cp = CanonicalPurl {
            ty: "rpm".to_string(),
            namespace: Some("redhat".to_string()),
            name: "".to_string(),
            version: Some("3.8-6.el8".to_string()),
            qualifiers: Default::default(),
        };

        assert_eq!("rpm", cp.ty);
        assert_eq!(Some("redhat".to_string()), cp.namespace);
        assert_eq!(Some("3.8-6.el8".to_string()), cp.version);

        let model = ActiveModel {
            purl: sea_orm::ActiveValue::Set(cp.clone()),
            ..Default::default()
        };
        assert_eq!(model.clone().purl.unwrap(), cp);

        let purl: Purl = serde_json::from_str(
            r#"
            "pkg:rpm/redhat/filesystem@3.8-6.el8?arch=aarch64"
            "#,
        )
        .unwrap();
        let cp = purl.clone().into();
        let model = ActiveModel {
            purl: sea_orm::ActiveValue::Set(purl.into()),
            ..Default::default()
        };
        assert_eq!(model.clone().purl.unwrap(), cp);
        assert_eq!(cp.qualifiers.get("arch"), Some(&"aarch64".to_string()));

        // check we can serialize CanonicalPurl to url string
        assert_eq!(
            Purl::from(model.purl.clone().unwrap()).to_string(),
            "pkg:rpm/redhat/filesystem@3.8-6.el8?arch=aarch64",
        );

        // check we can serialize CanonicalPurl to json value
        let json_value: serde_json::Value = from_str(&to_string(&cp).unwrap()).unwrap();
        assert_eq!(
            json_value,
            json!({"ty": "rpm", "namespace": "redhat", "name": "filesystem", "version": "3.8-6.el8", "qualifiers": {"arch": "aarch64"}})
        );

        // check we can serialize CanonicalPurl to Purl
        let purl: Purl = serde_json::from_str(
            r#"
            "pkg:rpm/redhat/filesystem@3.8-6.el8?arch=aarch64"
            "#,
        )
        .unwrap();
        let cp1: CanonicalPurl = purl.clone().into();
        assert_eq!(purl, Purl::from(cp1));
    }
}
