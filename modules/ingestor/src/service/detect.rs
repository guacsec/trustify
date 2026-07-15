use crate::{
    graph::{Graph, sbom::clearly_defined::Curation},
    model::IngestResult,
    service::{
        Error, JsonSource,
        advisory::{
            csaf::loader::CsafLoader, cve::loader::CveLoader, nvd::loader::NvdLoader,
            nvd::schema::NvdCve, osv::loader::OsvLoader,
        },
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
use osv::schema::Vulnerability;
use quick_xml::{Reader, events::Event};
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::io::Cursor;
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_entity::labels::Labels;

use super::Format;

/// The wire-level serialization format of a document.
///
/// Wire format constrains which content formats are valid:
/// - **Json**: all formats except `CweCatalog`
/// - **Yaml**: `OSV` and `ClearlyDefinedCuration` only
/// - **Xml**: `CweCatalog` only
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireFormat {
    Json,
    Yaml,
    Xml,
}

/// A fully detected and parsed document, ready for ingestion.
#[derive(Debug)]
pub enum DetectedDocument {
    Csaf(Box<Csaf>),
    Cve(Box<Cve>),
    /// A bare NVD CVE API `cve` object. NVD is never content-detected (it is
    /// indistinguishable from OSV by sniffing), so it is only produced when
    /// `Format::NVD` is passed explicitly as the hint.
    Nvd(Box<NvdCve>),
    Osv(Box<Vulnerability>),
    /// SPDX keeps the raw Value because the loader applies license fixups before ingestion.
    Spdx(serde_json::Value),
    CycloneDx(Box<serde_cyclonedx::cyclonedx::v_1_6::CycloneDx>),
    ClearlyDefined(serde_json::Value),
    ClearlyDefinedCuration(Box<Curation>),
    /// XML kept as raw bytes; the loader parses with roxmltree internally.
    CweCatalog(Vec<u8>),
}

/// Stateful document format detector that parses raw bytes through
/// wire format detection, intermediate representation, content type
/// detection, and domain type parsing, reusing work at each stage.
#[derive(Debug)]
pub struct DocumentDetector {
    wire_format: WireFormat,
    format: Format,
    document: DetectedDocument,
}

impl DocumentDetector {
    /// Detect the document format and parse it, using the given hint to
    /// narrow the search. Pass `Format::Unknown` to try all formats.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub fn detect_as(bytes: &[u8], hint: Format) -> Result<Self, Error> {
        let wire = detect_wire_format(bytes);

        if hint.is_concrete() {
            let document = match wire {
                WireFormat::Json => parse_format(bytes, hint)?,
                WireFormat::Yaml => {
                    let value = parse_to_value(bytes, wire)?;
                    parse_format(value, hint)?
                }
                WireFormat::Xml => {
                    if hint != Format::CweCatalog {
                        return Err(Error::UnsupportedFormat(format!(
                            "XML documents can only be parsed as CweCatalog, not {hint}"
                        )));
                    }
                    DetectedDocument::CweCatalog(bytes.to_vec())
                }
            };
            return Ok(Self {
                wire_format: wire,
                format: hint,
                document,
            });
        }

        match wire {
            WireFormat::Xml => {
                if !Format::CweCatalog.matches_hint(hint) {
                    return Err(Error::UnsupportedFormat(format!(
                        "XML documents not expected for {hint}"
                    )));
                }
                let document = detect_xml_format(bytes)?;
                Ok(Self {
                    wire_format: wire,
                    format: Format::CweCatalog,
                    document,
                })
            }
            _ => {
                let value = parse_to_value(bytes, wire)?;
                let format = detect_format(&value, hint)?;
                let document = parse_format(value, format)?;
                Ok(Self {
                    wire_format: wire,
                    format,
                    document,
                })
            }
        }
    }

    /// Detect the document format and parse it, trying all known formats.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub fn detect(bytes: &[u8]) -> Result<Self, Error> {
        Self::detect_as(bytes, Format::Unknown)
    }

    /// Returns the detected wire format.
    pub fn wire_format(&self) -> WireFormat {
        self.wire_format
    }

    /// Returns the detected content format.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Consumes self and returns the parsed document.
    pub fn into_document(self) -> DetectedDocument {
        self.document
    }

    /// Consumes self and dispatches the parsed document to the appropriate loader.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn load(
        self,
        graph: &Graph,
        labels: Labels,
        issuer: Option<String>,
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        match self.document {
            DetectedDocument::Csaf(csaf) => {
                CsafLoader::new(graph)
                    .load(labels, *csaf, digests, tx)
                    .await
            }
            DetectedDocument::Cve(cve) => {
                CveLoader::new(graph).load(labels, *cve, digests, tx).await
            }
            DetectedDocument::Nvd(cve) => {
                NvdLoader::new(graph).load(labels, *cve, digests, tx).await
            }
            DetectedDocument::Osv(osv) => {
                OsvLoader::new(graph)
                    .load(labels, *osv, digests, issuer, tx)
                    .await
            }
            DetectedDocument::Spdx(value) => {
                SpdxLoader::new(graph)
                    .load(labels, value, digests, tx)
                    .await
            }
            DetectedDocument::CycloneDx(cdx) => {
                CyclonedxLoader::new(graph)
                    .ingest(labels, cdx, digests, tx)
                    .await
            }
            DetectedDocument::ClearlyDefined(value) => {
                ClearlyDefinedLoader::new(graph)
                    .load(labels, value, digests, tx)
                    .await
            }
            DetectedDocument::ClearlyDefinedCuration(curation) => {
                ClearlyDefinedCurationLoader::new(graph)
                    .load(labels, *curation, digests, tx)
                    .await
            }
            DetectedDocument::CweCatalog(bytes) => {
                CweCatalogLoader::new()
                    .load_bytes(labels, &bytes, digests, tx)
                    .await
            }
        }
    }
}

/// Determine the wire format from the first non-whitespace byte.
///
/// Returns `Yaml` as a fallback for anything that isn't clearly JSON or XML.
/// If the content isn't actually valid YAML, `parse_to_value` will produce a
/// clear `UnsupportedFormat` error rather than a raw parse error.
fn detect_wire_format(bytes: &[u8]) -> WireFormat {
    let first = bytes.iter().copied().find(|b| !b.is_ascii_whitespace());
    match first {
        Some(b'{') | Some(b'[') => WireFormat::Json,
        Some(b'<') => WireFormat::Xml,
        _ => WireFormat::Yaml,
    }
}

/// Parse raw bytes into a `serde_json::Value` according to the wire format.
///
/// For YAML, wraps parse errors into `UnsupportedFormat` so that garbage input
/// gets a clear "not recognized" message.
fn parse_to_value(bytes: &[u8], wire: WireFormat) -> Result<serde_json::Value, Error> {
    match wire {
        WireFormat::Json => Ok(serde_json::from_slice(bytes)?),
        WireFormat::Yaml => serde_yml::from_slice(bytes).map_err(|e| {
            Error::UnsupportedFormat(format!(
                "Document not recognized as JSON, XML, or valid YAML: {e}"
            ))
        }),
        WireFormat::Xml => Err(Error::UnsupportedFormat(
            "XML documents cannot be represented as JSON Value".into(),
        )),
    }
}

/// Identify the content format from a parsed JSON/YAML Value.
///
/// Only checks formats that match the given hint, skipping irrelevant ones.
/// For example, with `Format::SBOM` only SPDX/CycloneDX/ClearlyDefined checks run.
fn detect_format(value: &serde_json::Value, hint: Format) -> Result<Format, Error> {
    if Format::CSAF.matches_hint(hint)
        && value
            .get("document")
            .and_then(|d| d.get("csaf_version"))
            .is_some()
    {
        return Ok(Format::CSAF);
    }

    if Format::CVE.matches_hint(hint) && value.get("dataType").is_some() {
        return Ok(Format::CVE);
    }

    if Format::SPDX.matches_hint(hint)
        && let Some(ver) = value.get("spdxVersion").and_then(|v| v.as_str())
    {
        return match ver {
            "SPDX-2.2" | "SPDX-2.3" => Ok(Format::SPDX),
            other => Err(Error::UnsupportedFormat(format!(
                "SPDX version {other} is unsupported; try 2.2 or 2.3"
            ))),
        };
    }

    if Format::CycloneDX.matches_hint(hint)
        && let Some(ver) = value.get("specVersion").and_then(|v| v.as_str())
    {
        return match ver {
            "1.3" | "1.4" | "1.5" | "1.6" => Ok(Format::CycloneDX),
            other => Err(Error::UnsupportedFormat(format!(
                "CycloneDX version {other} is unsupported; try 1.3, 1.4, 1.5, 1.6"
            ))),
        };
    }

    if Format::ClearlyDefinedCuration.matches_hint(hint) && value.get("coordinates").is_some() {
        return Ok(Format::ClearlyDefinedCuration);
    }

    if Format::ClearlyDefined.matches_hint(hint) && value.get("_id").is_some() {
        return Ok(Format::ClearlyDefined);
    }

    // OSV checked last because `id` is a very generic key
    if Format::OSV.matches_hint(hint) && value.get("id").is_some() {
        return Ok(Format::OSV);
    }

    Err(Error::UnsupportedFormat(format!(
        "Unable to detect document format for hint {hint}"
    )))
}

/// Parse a JSON-compatible source into a `DetectedDocument` for a known format.
///
/// Accepts both `&[u8]` (for JSON with known format — direct parse, no Value
/// intermediate) and `serde_json::Value` (for YAML-normalized or auto-detected
/// content) via the `JsonSource` trait.
fn parse_format(source: impl JsonSource, format: Format) -> Result<DetectedDocument, Error> {
    let map_err = |e: serde_json::Error| Error::UnsupportedFormat(format!("Failed to parse: {e}"));

    match format {
        Format::CSAF => Ok(DetectedDocument::Csaf(Box::new(
            source.parse_json().map_err(map_err)?,
        ))),
        Format::CVE => Ok(DetectedDocument::Cve(Box::new(
            source.parse_json().map_err(map_err)?,
        ))),
        Format::NVD => Ok(DetectedDocument::Nvd(Box::new(
            source.parse_json().map_err(map_err)?,
        ))),
        Format::OSV => Ok(DetectedDocument::Osv(Box::new(
            source.parse_json().map_err(map_err)?,
        ))),
        Format::SPDX => Ok(DetectedDocument::Spdx(
            source.parse_json().map_err(map_err)?,
        )),
        Format::CycloneDX => Ok(DetectedDocument::CycloneDx(
            source.parse_json().map_err(map_err)?,
        )),
        Format::ClearlyDefined => Ok(DetectedDocument::ClearlyDefined(
            source.parse_json().map_err(map_err)?,
        )),
        Format::ClearlyDefinedCuration => Ok(DetectedDocument::ClearlyDefinedCuration(Box::new(
            source.parse_json().map_err(map_err)?,
        ))),
        Format::CweCatalog => Err(Error::UnsupportedFormat(
            "CWE catalog requires XML wire format".into(),
        )),
        other => Err(Error::UnsupportedFormat(format!("Cannot parse as {other}"))),
    }
}

/// Detect XML document format by inspecting the first element's attributes.
fn detect_xml_format(bytes: &[u8]) -> Result<DetectedDocument, Error> {
    if is_cwe_catalog_xml(bytes) {
        return Ok(DetectedDocument::CweCatalog(bytes.to_vec()));
    }
    Err(Error::UnsupportedFormat(
        "Unable to detect XML document format".into(),
    ))
}

/// Check whether the given XML bytes represent a CWE catalog by looking for
/// the CWE schema location attribute in the root element.
fn is_cwe_catalog_xml(bytes: &[u8]) -> bool {
    let xml = Cursor::new(bytes);
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(event)) => {
                for attr in event.attributes().flatten() {
                    if attr.key.local_name().into_inner() == b"schemaLocation"
                        && attr
                            .value
                            .ends_with(b"http://cwe.mitre.org/data/xsd/cwe_schema_v7.2.xsd")
                    {
                        return true;
                    }
                }
                return false;
            }
            Err(_) | Ok(Event::Eof) => return false,
            _ => buf.clear(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Read;
    use test_log::test;
    use trustify_test_context::{document_bytes, document_read};
    use zip::ZipArchive;

    #[test(tokio::test)]
    async fn detect_csaf() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("csaf/CVE-2023-20862.json").await?;
        let detector = DocumentDetector::detect(&bytes)?;
        assert_eq!(detector.format(), Format::CSAF);
        assert_eq!(detector.wire_format(), WireFormat::Json);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_osv_json() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("osv/RUSTSEC-2021-0079.json").await?;
        let detector = DocumentDetector::detect(&bytes)?;
        assert_eq!(detector.format(), Format::OSV);
        assert_eq!(detector.wire_format(), WireFormat::Json);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_osv_yaml() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("osv/RSEC-2023-6.yaml").await?;
        let detector = DocumentDetector::detect(&bytes)?;
        assert_eq!(detector.format(), Format::OSV);
        assert_eq!(detector.wire_format(), WireFormat::Yaml);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_cve() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("mitre/CVE-2024-27088.json").await?;
        let detector = DocumentDetector::detect(&bytes)?;
        assert_eq!(detector.format(), Format::CVE);
        assert_eq!(detector.wire_format(), WireFormat::Json);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_cyclonedx() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;
        let detector = DocumentDetector::detect(&bytes)?;
        assert_eq!(detector.format(), Format::CycloneDX);
        assert_eq!(detector.wire_format(), WireFormat::Json);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_cyclonedx_1dot6() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("cyclonedx/simple_1dot6.json").await?;
        let detector = DocumentDetector::detect(&bytes)?;
        assert_eq!(detector.format(), Format::CycloneDX);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_spdx() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("ubi9-9.2-755.1697625012.json").await?;
        let detector = DocumentDetector::detect(&bytes)?;
        assert_eq!(detector.format(), Format::SPDX);
        assert_eq!(detector.wire_format(), WireFormat::Json);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_cwe_catalog() -> Result<(), anyhow::Error> {
        let cwe = document_read("cwec_latest.xml.zip")?;
        let mut archive = ZipArchive::new(cwe)?;
        let mut entry = archive.by_index(0)?;
        let mut xml = Vec::new();
        entry.read_to_end(&mut xml)?;
        let detector = DocumentDetector::detect(&xml)?;
        assert_eq!(detector.format(), Format::CweCatalog);
        assert_eq!(detector.wire_format(), WireFormat::Xml);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_indigestable() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("indigestable.json").await?;
        assert!(DocumentDetector::detect(&bytes).is_err());
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_as_advisory_csaf() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("csaf/CVE-2023-20862.json").await?;
        let detector = DocumentDetector::detect_as(&bytes, Format::Advisory)?;
        assert_eq!(detector.format(), Format::CSAF);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_as_sbom_spdx() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("ubi9-9.2-755.1697625012.json").await?;
        let detector = DocumentDetector::detect_as(&bytes, Format::SBOM)?;
        assert_eq!(detector.format(), Format::SPDX);
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_as_wrong_category() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("csaf/CVE-2023-20862.json").await?;
        assert!(DocumentDetector::detect_as(&bytes, Format::SBOM).is_err());
        Ok(())
    }

    #[test(tokio::test)]
    async fn detect_as_concrete_format() -> Result<(), anyhow::Error> {
        let bytes = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;
        let detector = DocumentDetector::detect_as(&bytes, Format::CycloneDX)?;
        assert_eq!(detector.format(), Format::CycloneDX);
        Ok(())
    }

    #[test]
    fn wire_format_json_object() {
        assert_eq!(detect_wire_format(b"  { }"), WireFormat::Json);
    }

    #[test]
    fn wire_format_json_array() {
        assert_eq!(detect_wire_format(b"[1, 2]"), WireFormat::Json);
    }

    #[test]
    fn wire_format_xml() {
        assert_eq!(detect_wire_format(b"<?xml"), WireFormat::Xml);
    }

    #[test]
    fn wire_format_yaml_fallback() {
        assert_eq!(detect_wire_format(b"---\nid: foo"), WireFormat::Yaml);
    }

    #[test]
    fn wire_format_garbage_is_yaml() {
        assert_eq!(detect_wire_format(b"\x00\x01\x02"), WireFormat::Yaml);
    }

    #[test]
    fn garbage_input_gives_unsupported_format() {
        let err = DocumentDetector::detect(b"\x00\x01\x02binary garbage");
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("not recognized"),
            "expected 'not recognized' in error, got: {msg}"
        );
    }
}
