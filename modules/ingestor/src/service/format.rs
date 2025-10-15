use crate::{
    graph::{Graph, sbom::clearly_defined::Curation},
    model::IngestResult,
    service::{
        Error,
        advisory::{csaf::loader::CsafLoader, cve::loader::CveLoader, osv::loader::OsvLoader},
        sbom::{
            clearly_defined::ClearlyDefinedLoader,
            clearly_defined_curation::ClearlyDefinedCurationLoader, cyclonedx::CyclonedxLoader,
            spdx::SpdxLoader,
        },
        weakness::CweCatalogLoader,
    },
};
use csaf::Csaf;
use cve::Cve;
use jsn::{Format as JsnFormat, TokenReader, mask::*};
use quick_xml::{Reader, events::Event};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::{io::Cursor, str::FromStr};
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_entity::labels::Labels;

#[derive(
    Clone,
    Copy,
    Debug,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::Display,
    strum::VariantNames,
    utoipa::ToSchema,
    PartialEq,
    Eq,
)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
#[schema(rename_all = "lowercase")]
pub enum Format {
    OSV,
    CSAF,
    CVE,
    SPDX,
    CycloneDX,
    ClearlyDefinedCuration,
    ClearlyDefined,
    CweCatalog,
    // These should be resolved to one of the above before loading
    Advisory,
    SBOM,
    Unknown,
}

impl Format {
    #[instrument(skip_all)]
    pub async fn load(
        &self,
        graph: &'_ Graph,
        labels: Labels,
        issuer: Option<String>,
        digests: &Digests,
        buffer: &[u8],
    ) -> Result<IngestResult, Error> {
        match self {
            Format::CSAF => {
                // issuer is internal as publisher of the document.
                let loader = CsafLoader::new(graph);
                let csaf: Csaf = serde_json::from_slice(buffer)?;
                loader.load(labels, csaf, digests).await
            }
            Format::OSV => {
                // issuer is :shrug: sometimes we can tell, sometimes not :shrug:
                let loader = OsvLoader::new(graph);
                let osv = super::advisory::osv::parse(buffer)?;
                loader.load(labels, osv, digests, issuer).await
            }
            Format::CVE => {
                // issuer is always CVE Project
                let loader = CveLoader::new(graph);
                let cve: Cve = serde_json::from_slice(buffer)?;
                loader.load(labels, cve, digests).await
            }
            Format::SPDX => {
                let loader = SpdxLoader::new(graph);
                let v: Value = serde_json::from_slice(buffer)?;
                loader.load(labels, v, digests).await
            }
            Format::CycloneDX => {
                let loader = CyclonedxLoader::new(graph);
                loader.load(labels, buffer, digests).await
            }
            Format::ClearlyDefined => {
                let loader = ClearlyDefinedLoader::new(graph);
                let item: Value = serde_json::from_slice(buffer)?;
                loader.load(labels, item, digests).await
            }
            Format::ClearlyDefinedCuration => {
                let loader = ClearlyDefinedCurationLoader::new(graph);
                let curation: Curation = serde_yml::from_slice(buffer)?;
                loader.load(labels, curation, digests).await
            }
            Format::CweCatalog => {
                let loader = CweCatalogLoader::new(graph);
                loader.load_bytes(labels, buffer, digests).await
            }
            f => Err(Error::UnsupportedFormat(format!(
                "Must resolve {f:?} to an actual format"
            ))),
        }
    }

    #[instrument(skip_all, ret)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match Self::advisory_from_bytes(bytes) {
            Err(Error::UnsupportedFormat(ea)) => match Self::sbom_from_bytes(bytes) {
                Err(Error::UnsupportedFormat(es)) => match Self::is_cwe_catalog(bytes) {
                    Ok(true) => Ok(Self::CweCatalog),
                    _ => Err(Error::UnsupportedFormat(format!("{ea}\n{es}"))),
                },
                x => x,
            },
            x => x,
        }
    }

    #[instrument(skip_all, ret)]
    pub fn advisory_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if Self::is_csaf(bytes)? {
            Ok(Format::CSAF)
        } else if Self::is_cve(bytes)? {
            Ok(Format::CVE)
        } else if Self::is_osv(bytes)? {
            Ok(Format::OSV)
        } else {
            Err(Error::UnsupportedFormat(
                "Unable to detect advisory format; only CSAF, CVE, and OSV are supported".into(),
            ))
        }
    }

    #[instrument(skip_all, ret)]
    pub fn sbom_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if Self::is_spdx(bytes)? {
            Ok(Format::SPDX)
        } else if Self::is_cyclonedx(bytes)? {
            Ok(Format::CycloneDX)
        } else if Self::is_clearly_defined(bytes)? {
            Ok(Format::ClearlyDefinedCuration)
        } else {
            Err(Error::UnsupportedFormat(
                "Unable to detect SBOM format; only SPDX and CycloneDX are supported".into(),
            ))
        }
    }

    pub fn is_csaf(bytes: &[u8]) -> Result<bool, Error> {
        match masked(
            key("document").and(key("csaf_version")).and(depth(2)),
            bytes,
        ) {
            Ok(Some(_)) => Ok(true),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_cve(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("dataType")), bytes) {
            Ok(Some(_)) => Ok(true),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_osv(bytes: &[u8]) -> Result<bool, Error> {
        Ok(Self::is_osv_json(bytes)? || Self::is_osv_yaml(bytes)?)
    }

    pub fn is_osv_json(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("id")), bytes) {
            Ok(Some(_)) => Ok(true),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_osv_yaml(bytes: &[u8]) -> Result<bool, Error> {
        // TODO: find a way to detect format with streaming
        Ok(super::advisory::osv::from_yaml(bytes).is_ok())
    }

    pub fn is_spdx(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("spdxVersion")), bytes) {
            Ok(Some(x)) if matches!(x.as_str(), "SPDX-2.2" | "SPDX-2.3") => Ok(true),
            Ok(Some(x)) => Err(Error::UnsupportedFormat(format!(
                "SPDX version {x} is unsupported; try 2.2 or 2.3"
            ))),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_cyclonedx(bytes: &[u8]) -> Result<bool, Error> {
        match masked(depth(1).and(key("specVersion")), bytes) {
            Ok(Some(x)) if matches!(x.as_str(), "1.3" | "1.4" | "1.5" | "1.6") => Ok(true),
            Ok(Some(x)) => Err(Error::UnsupportedFormat(format!(
                "CycloneDX version {x} is unsupported; try 1.3, 1.4, 1.5, 1.6"
            ))),
            Err(_) | Ok(None) => Ok(false),
        }
    }

    pub fn is_clearly_defined(bytes: &[u8]) -> Result<bool, Error> {
        // first just try to get some YAML.
        if let Ok(candidate) = serde_yml::from_slice::<'_, serde_yml::Value>(bytes) {
            // does it have a root `coordinates`?
            if candidate.get("coordinates").is_some() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn is_cwe_catalog(bytes: &[u8]) -> Result<bool, Error> {
        let xml = Cursor::new(bytes);
        let mut reader = Reader::from_reader(xml);

        let mut buf = Vec::new();
        loop {
            // read events until we find the first tag, or an error
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(event)) => {
                    // first tag will have some attributes, let's see if it matches our
                    // expected schema.
                    let attrs = event.attributes();
                    for attr in attrs.into_iter().flatten() {
                        if attr.key.local_name().into_inner() == b"schemaLocation" {
                            // The attribute value is weird, and possibly wrong with a
                            // strange prefix URL that does not resolve before the actual
                            // xsd url, hence using `ends_with(...)` to match.
                            if attr
                                .value
                                .ends_with(b"http://cwe.mitre.org/data/xsd/cwe_schema_v7.2.xsd")
                            {
                                // It's a CWE catalog, yay.
                                return Ok(true);
                            }
                        }
                    }
                    // First tag was apparently not the droids we were looking for.
                    return Ok(false);
                }
                Err(_) | Ok(Event::Eof) => return Ok(false),
                _ => {
                    // not an error or a start tag, keep on looping
                    buf.clear()
                }
            }
        }
    }

    /// Resolve one of the "vague" formats (like "SBOM") by inspecting the payload.
    ///
    /// If the format is one of the vague formats, it will try to detect the format
    /// (in that context) by inspecting the payload. Any concrete format will be returned without
    /// checking.
    pub fn resolve(self, data: &[u8]) -> Result<Format, Error> {
        match self {
            Self::Unknown => Self::from_bytes(data),
            Self::Advisory => Self::advisory_from_bytes(data),
            Self::SBOM => Self::sbom_from_bytes(data),
            other => Ok(other),
        }
    }
}

fn masked<N: Mask>(mask: N, bytes: &[u8]) -> Result<Option<String>, Error> {
    let mut iter = TokenReader::new(bytes)
        .with_mask(mask)
        .with_format(JsnFormat::Concatenated)
        .into_iter();

    iter.next()
        .map(|x| {
            x.map(|y| y.get::<String>().unwrap_or_default())
                .map_err(|e| Error::Generic(e.into()))
        })
        .transpose()
}

impl<'de> Deserialize<'de> for Format {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Format {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;
    use std::io::Read;
    use strum::VariantNames;
    use test_log::test;
    use trustify_test_context::{document_bytes, document_read};
    use utoipa::{
        PartialSchema,
        openapi::{RefOr, Schema},
    };
    use zip::ZipArchive;

    #[test(tokio::test)]
    async fn detection() -> Result<(), anyhow::Error> {
        let csaf = document_bytes("csaf/CVE-2023-20862.json").await?;
        assert!(matches!(Format::from_bytes(&csaf), Ok(Format::CSAF)));

        let osv = document_bytes("osv/RUSTSEC-2021-0079.json").await?;
        assert!(matches!(Format::from_bytes(&osv), Ok(Format::OSV)));

        let osv = document_bytes("osv/RSEC-2023-6.yaml").await?;
        assert!(matches!(Format::from_bytes(&osv), Ok(Format::OSV)));

        let cve = document_bytes("mitre/CVE-2024-27088.json").await?;
        assert!(matches!(Format::from_bytes(&cve), Ok(Format::CVE)));

        let cyclone = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;
        assert!(matches!(
            Format::from_bytes(&cyclone),
            Ok(Format::CycloneDX)
        ));

        let cyclone = document_bytes("cyclonedx/simple_1dot6.json").await?;
        assert!(matches!(
            Format::from_bytes(&cyclone),
            Ok(Format::CycloneDX)
        ));

        let spdx = document_bytes("ubi9-9.2-755.1697625012.json").await?;
        assert!(matches!(Format::from_bytes(&spdx), Ok(Format::SPDX)));

        let indigestable = document_bytes("indigestable.json").await?;
        assert!(Format::from_bytes(&indigestable).is_err());

        let cwe = document_read("cwec_latest.xml.zip")?;
        let mut cwe = ZipArchive::new(cwe)?;
        let mut cwe = cwe.by_index(0)?;
        let mut xml = Vec::new();
        cwe.read_to_end(&mut xml)?;
        assert!(matches!(Format::from_bytes(&xml), Ok(Format::CweCatalog)));

        Ok(())
    }

    #[test]
    fn from_str() {
        // the new variant value
        assert_eq!(Format::from_str("cyclonedx"), Ok(Format::CycloneDX));
        // the old variant value
        assert_eq!(Format::from_str("cycloneDx"), Ok(Format::CycloneDX));
    }

    #[test]
    fn to_string() {
        assert_eq!(Format::CycloneDX.to_string(), "cyclonedx");
        assert_eq!(Format::OSV.to_string(), "osv");
    }

    /// ensure the variants from strum are the same as the ones in the schema
    #[test]
    fn schema_variants() {
        let RefOr::T(Schema::Object(o)) = Format::schema() else {
            panic!("must be an object")
        };

        let variants = Format::VARIANTS.iter().map(|name| json!(name)).collect();

        assert_eq!(o.enum_values, Some(variants));
    }
}
