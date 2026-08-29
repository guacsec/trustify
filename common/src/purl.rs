use deepsize::DeepSizeOf;
use packageurl::PackageUrl;
use sea_orm::FromJsonQueryResult;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error, Visitor},
};
use std::{borrow::Cow, cmp::Ordering};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Display, Formatter},
    hash::Hash,
    str::FromStr,
};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{KnownFormat, ObjectBuilder, RefOr, Schema, SchemaFormat, Type},
};
use uuid::Uuid;

use crate::db::query::Valuable;

#[derive(Debug, thiserror::Error)]
pub enum PurlErr {
    #[error("missing version {0}")]
    MissingVersion(String),
    #[error("packageurl problem {0}")]
    Package(#[from] packageurl::Error),
}

#[derive(Clone, PartialEq, Eq, Hash, DeepSizeOf, FromJsonQueryResult)]
pub struct Purl {
    pub ty: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub qualifiers: BTreeMap<String, String>,
}

impl Valuable for Purl {
    fn like(&self, pat: &str) -> bool {
        match urlencoding::decode(pat) {
            Ok(s) => self.to_string().contains(&s.into_owned()),
            _ => false,
        }
    }
}
impl PartialOrd<String> for Purl {
    fn partial_cmp(&self, other: &String) -> Option<Ordering> {
        match Purl::from_str(other) {
            Ok(purl) if self.eq(&purl) => Some(Ordering::Equal),
            _ => self.to_string().partial_cmp(other),
        }
    }
}
impl PartialEq<String> for Purl {
    fn eq(&self, other: &String) -> bool {
        match Purl::from_str(other) {
            Ok(p) => self.eq(&p),
            _ => self.to_string().eq(other),
        }
    }
}

impl ToSchema for Purl {
    fn name() -> Cow<'static, str> {
        "Purl".into()
    }
}

impl PartialSchema for Purl {
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uri)))
            .into()
    }
}

impl From<&Purl> for serde_json::Value {
    fn from(purl: &Purl) -> Self {
        serde_json::json!({
            "ty": purl.ty,
            "namespace": purl.namespace,
            "name": purl.name,
            "version": purl.version,
            "qualifiers": purl.qualifiers,
        })
    }
}

const NAMESPACE: Uuid = Uuid::from_bytes([
    0x37, 0x38, 0xb4, 0x3d, 0xfd, 0x03, 0x4a, 0x9d, 0x84, 0x9c, 0x48, 0x9b, 0xec, 0x61, 0x0f, 0x06,
]);

impl Purl {
    // clone from self with the passed version
    pub fn with_version<T: ToString>(&self, version: T) -> Self {
        let mut result = self.clone();
        result.version = Some(version.to_string());
        result
    }

    pub fn package_uuid(&self) -> Uuid {
        let mut result = Uuid::new_v5(&NAMESPACE, self.ty.as_bytes());
        if let Some(namespace) = &self.namespace {
            result = Uuid::new_v5(&result, namespace.as_bytes());
        }
        Uuid::new_v5(&result, self.name.as_bytes())
    }

    fn then_version_uuid(&self, package: &Uuid) -> Uuid {
        Uuid::new_v5(
            package,
            self.version
                .as_ref()
                .map(|v| v.as_bytes())
                .unwrap_or_default(),
        )
    }

    pub fn version_uuid(&self) -> Uuid {
        self.then_version_uuid(&self.package_uuid())
    }

    fn then_qualifier_uuid(&self, version: &Uuid) -> Uuid {
        let mut result = *version;
        for (k, v) in &self.qualifiers {
            result = Uuid::new_v5(&result, k.as_bytes());
            result = Uuid::new_v5(&result, v.as_bytes());
        }

        result
    }

    pub fn qualifier_uuid(&self) -> Uuid {
        self.then_qualifier_uuid(&self.version_uuid())
    }

    pub fn uuids(&self) -> (Uuid, Uuid, Uuid) {
        let package = self.package_uuid();
        let version = self.then_version_uuid(&package);
        let qualified = self.then_qualifier_uuid(&version);
        (package, version, qualified)
    }

    /// Create a new instance with only the base information
    pub fn to_base(&self) -> Self {
        Self {
            ty: self.ty.clone(),
            name: self.name.clone(),
            namespace: self.namespace.clone(),
            version: None,
            qualifiers: Default::default(),
        }
    }

    /// Create a new instance with only the version information
    pub fn to_version(&self) -> Self {
        Self {
            ty: self.ty.clone(),
            name: self.name.clone(),
            namespace: self.namespace.clone(),
            version: self.version.clone(),
            qualifiers: Default::default(),
        }
    }

    /// Query translator for purl components
    pub fn translate(op: &str, v: &str) -> Option<String> {
        match (op, Purl::from_str(v)) {
            ("=" | "~", Ok(p)) => {
                let mut q = format!("purl:ty={}&purl:name={}", p.ty, p.name);
                if let Some(ns) = p.namespace {
                    q.push_str(&format!("&purl:namespace{op}{ns}"));
                }
                if let Some(version) = p.version {
                    q.push_str(&format!("&purl:version{op}{version}"));
                }
                for (k, v) in p.qualifiers {
                    q.push_str(&format!("&purl:qualifiers:{k}{op}{v}"));
                }
                Some(q)
            }
            ("~", Err(_)) => Some(v.into()),
            (_, Err(e)) => Some(e.to_string()),
            (_, _) => Some("illegal operation for purl field".into()),
        }
    }
}

impl Serialize for Purl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl FromStr for Purl {
    type Err = PurlErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PackageUrl::from_str(s)
            .map(Purl::from)
            .map_err(PurlErr::Package)
    }
}

impl<'de> Deserialize<'de> for Purl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PurlVisitor)
    }
}

struct PurlVisitor;

impl Visitor<'_> for PurlVisitor {
    type Value = Purl;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str("a pURL")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        v.try_into().map_err(Error::custom)
    }
}

impl Display for Purl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut purl = PackageUrl::new(&self.ty, &self.name).map_err(|_| fmt::Error)?;
        if let Some(ns) = &self.namespace {
            purl.with_namespace(ns).map_err(|_| fmt::Error)?;
        }
        if let Some(version) = &self.version {
            purl.with_version(version).map_err(|_| fmt::Error)?;
        }
        for (key, value) in &self.qualifiers {
            purl.add_qualifier(key, value).map_err(|_| fmt::Error)?;
        }
        Display::fmt(&purl, f)
    }
}

impl Debug for Purl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl TryFrom<&str> for Purl {
    type Error = PurlErr;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match PackageUrl::from_str(value) {
            Ok(s) => Ok(s.into()),
            Err(e) => Err(PurlErr::Package(e)),
        }
    }
}

impl TryFrom<String> for Purl {
    type Error = PurlErr;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl From<PackageUrl<'_>> for Purl {
    fn from(value: PackageUrl) -> Self {
        Self {
            ty: value.ty().to_string(),
            namespace: value.namespace().map(|inner| inner.to_string()),
            name: value.name().to_string(),
            version: value.version().map(|inner| inner.to_string()),
            qualifiers: value
                .qualifiers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::purl::Purl;
    use std::str::FromStr;
    use test_log::test;

    #[test(tokio::test)]
    async fn purl_serde() -> Result<(), anyhow::Error> {
        let purl: Purl = serde_json::from_str(
            r#"
            "pkg:maven/io.quarkus/quarkus-core@1.2.3?foo=bar"
            "#,
        )
        .unwrap();

        assert_eq!("maven", purl.ty);

        assert_eq!(Some("io.quarkus".to_string()), purl.namespace);

        assert_eq!(Some("1.2.3".to_string()), purl.version);

        assert_eq!(purl.qualifiers.get("foo"), Some(&"bar".to_string()));

        let purl: Purl = "pkg:maven/io.quarkus/quarkus-core@1.2.3?foo=bar".try_into()?;
        let json = serde_json::to_string(&purl).unwrap();

        assert_eq!(json, r#""pkg:maven/io.quarkus/quarkus-core@1.2.3?foo=bar""#);
        Ok(())
    }

    #[test(tokio::test)]
    async fn purl_oci() -> Result<(), anyhow::Error> {
        let purl: Purl = serde_json::from_str(
            r#"
            "pkg:oci/ose-cluster-network-operator@sha256:0170ba5eebd557fd9f477d915bb7e0d4c1ad6cd4c1852d4b1ceed7a2817dd5d2?repository_url=registry.redhat.io/openshift4/ose-cluster-network-operator&tag=v4.11.0-202403090037.p0.g33da9fb.assembly.stream.el8"
            "#,
        )
            .unwrap();

        assert_eq!("oci", purl.ty);
        assert_eq!(None, purl.namespace);
        assert_eq!(
            Some(
                "sha256:0170ba5eebd557fd9f477d915bb7e0d4c1ad6cd4c1852d4b1ceed7a2817dd5d2"
                    .to_string()
            ),
            purl.version
        );
        assert_eq!(
            purl.qualifiers.get("repository_url"),
            Some(&"registry.redhat.io/openshift4/ose-cluster-network-operator".to_string())
        );
        assert_eq!(
            purl.qualifiers.get("tag"),
            Some(&"v4.11.0-202403090037.p0.g33da9fb.assembly.stream.el8".to_string())
        );

        let purl: Purl = "pkg:oci/ose-cluster-network-operator@sha256:0170ba5eebd557fd9f477d915bb7e0d4c1ad6cd4c1852d4b1ceed7a2817dd5d2?repository_url=registry.redhat.io/openshift4/ose-cluster-network-operator&tag=v4.11.0-202403090037.p0.g33da9fb.assembly.stream.el8".try_into()?;
        let json = serde_json::to_string(&purl).unwrap();

        assert_eq!(
            json,
            r#""pkg:oci/ose-cluster-network-operator@sha256:0170ba5eebd557fd9f477d915bb7e0d4c1ad6cd4c1852d4b1ceed7a2817dd5d2?repository_url=registry.redhat.io/openshift4/ose-cluster-network-operator&tag=v4.11.0-202403090037.p0.g33da9fb.assembly.stream.el8""#
        );
        Ok(())
    }

    #[test(tokio::test)]
    async fn purl_rpm() -> Result<(), anyhow::Error> {
        let purl: Purl = serde_json::from_str(
            r#"
            "pkg:rpm/redhat/filesystem@3.8-6.el8?arch=aarch64"
            "#,
        )
        .unwrap();

        assert_eq!("rpm", purl.ty);
        assert_eq!(Some("redhat".to_string()), purl.namespace);
        assert_eq!(Some("3.8-6.el8".to_string()), purl.version);
        assert_eq!(purl.qualifiers.get("arch"), Some(&"aarch64".to_string()));

        let purl: Purl = "pkg:rpm/redhat/filesystem@3.8-6.el8?arch=aarch64".try_into()?;
        let json = serde_json::to_string(&purl).unwrap();

        assert_eq!(
            json,
            r#""pkg:rpm/redhat/filesystem@3.8-6.el8?arch=aarch64""#
        );
        Ok(())
    }

    #[test(tokio::test)]
    async fn purl_rpm_deux() -> Result<(), anyhow::Error> {
        let purl: Purl = serde_json::from_str(
            r#"
            "pkg:rpm/redhat/subscription-manager-rhsm-certificates@1.28.29.1-1.el8_6?arch=s390x"
            "#,
        )
        .unwrap();

        assert_eq!("rpm", purl.ty);
        assert_eq!(Some("redhat".to_string()), purl.namespace);
        assert_eq!(Some("1.28.29.1-1.el8_6".to_string()), purl.version);
        assert_eq!(purl.qualifiers.get("arch"), Some(&"s390x".to_string()));

        let otherpurl: Purl = Purl::from_str(
            "pkg:rpm/redhat/subscription-manager-rhsm-certificates@1.28.29.1-1.el8_6?arch=s390x",
        )?;
        assert_eq!("rpm", otherpurl.ty);
        assert_eq!(Some("redhat".to_string()), otherpurl.namespace);
        assert_eq!(Some("1.28.29.1-1.el8_6".to_string()), otherpurl.version);
        assert_eq!(otherpurl.qualifiers.get("arch"), Some(&"s390x".to_string()));

        let purl: Purl =
            "pkg:rpm/redhat/subscription-manager-rhsm-certificates@1.28.29.1-1.el8_6?arch=s390x"
                .try_into()?;
        let json = serde_json::to_string(&purl).unwrap();

        assert_eq!(
            json,
            r#""pkg:rpm/redhat/subscription-manager-rhsm-certificates@1.28.29.1-1.el8_6?arch=s390x""#
        );
        Ok(())
    }

    #[test(tokio::test)]
    async fn purl_cmp() -> Result<(), anyhow::Error> {
        let purl1: Purl = serde_json::from_str(
            r#"
            "pkg:rpm/redhat/filesystem@3.8-6.el8?arch=aarch64&tags=test1"
            "#,
        )
        .unwrap();
        let purl2: Purl = serde_json::from_str(
            r#"
            "pkg:rpm/redhat/filesystem@3.8-6.el8?tags=test1&arch=aarch64"
            "#,
        )
        .unwrap();
        assert_eq!(purl1, purl2);
        Ok(())
    }

    #[test(tokio::test)]
    async fn purl_encoding() -> Result<(), anyhow::Error> {
        let purl = Purl::from_str("pkg:npm/@fastify/this@that@3.8-%236.el8")?;
        assert_eq!(
            purl.to_string().as_str(),
            "pkg:npm/%40fastify/this%40that@3.8-%236.el8"
        );
        let purl = Purl::from_str("pkg:generic/ibm-granite%2Fgranite-docling-258M@1.0")?;
        assert_eq!(
            purl.to_string().as_str(),
            "pkg:generic/ibm-granite%2Fgranite-docling-258M@1.0"
        );

        Ok(())
    }
}
