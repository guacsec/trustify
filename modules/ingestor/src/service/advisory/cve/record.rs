//! A CVE record, with the parts the `cve` crate doesn't model (yet).

use crate::service::advisory::nvd::schema::Configuration;
use cve::Cve;
use serde::{Deserialize, Deserializer, de::Error as _};
use serde_json::Value;

/// A CVE record, and the CPE applicability statements (`cpeApplicability`) of its containers.
#[derive(Clone, Debug)]
pub struct CveRecord {
    pub cve: Cve,
    /// The `cpeApplicability` of the CNA and ADP containers. It uses the CPE Applicability Language,
    /// as NVD configurations do.
    pub applicability: Vec<(Configuration, trustify_api::correlation::ProviderIdentity)>,
    /// What couldn't be parsed and was left out: the `cpeApplicability` of a container which isn't
    /// valid.
    pub warnings: Vec<String>,
}

impl From<Cve> for CveRecord {
    fn from(cve: Cve) -> Self {
        Self {
            cve,
            applicability: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for CveRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let mut warnings = Vec::new();
        let applicability = applicability(&value, &mut warnings);
        let cve = Cve::deserialize(value).map_err(D::Error::custom)?;
        Ok(Self {
            cve,
            applicability,
            warnings,
        })
    }
}

/// The `cpeApplicability` of the containers of a record.
///
/// The `cpeApplicability` of a container which can't be parsed is left out, with a warning, as
/// older versions stored such records, ignoring it.
fn applicability(
    record: &Value,
    warnings: &mut Vec<String>,
) -> Vec<(Configuration, trustify_api::correlation::ProviderIdentity)> {
    let containers = record.get("containers");
    let cna = containers.and_then(|c| c.get("cna"));
    let adp = containers
        .and_then(|c| c.get("adp"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten();

    let mut result = Vec::new();
    for (role, container) in cna.into_iter().map(|c| ("cna".to_string(), c)).chain(
        adp.enumerate()
            .map(|(index, c)| (format!("adp:{index}"), c)),
    ) {
        if let Some(applicability) = container.get("cpeApplicability") {
            let provider = super::loader::source_provider(
                &container
                    .get("providerMetadata")
                    .cloned()
                    .unwrap_or_default(),
                &role,
            );
            match Vec::<Configuration>::deserialize(applicability) {
                Ok(configurations) => result.extend(
                    configurations
                        .into_iter()
                        .map(|configuration| (configuration, provider.clone())),
                ),
                Err(err) => warnings.push(format!(
                    "Ignoring the invalid cpeApplicability of container {role}: {err}"
                )),
            }
        }
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;
    use test_log::test;
    use trustify_test_context::document_bytes;

    const RECORD: &str = "scenarios/S26_cve_cpe_applicability_kernel/cve/CVE-2024-26581.json";

    /// The CPE criteria of the applicability of a record, and its warnings.
    fn summary(record: &CveRecord) -> (Vec<&str>, &[String]) {
        (
            record
                .applicability
                .iter()
                .flat_map(|(configuration, _)| &configuration.nodes)
                .flat_map(|node| &node.cpe_match)
                .map(|cpe_match| cpe_match.criteria.as_str())
                .collect(),
            &record.warnings,
        )
    }

    #[test(tokio::test)]
    async fn applicability() -> anyhow::Result<()> {
        let record: CveRecord = serde_json::from_slice(&document_bytes(RECORD).await?)?;
        assert_eq!(
            summary(&record),
            (
                vec!["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"; 8],
                &[][..]
            )
        );
        Ok(())
    }

    /// Invalid applicability is left out, with a warning, and the rest of the record is kept.
    ///
    /// No published record with invalid applicability is known, so a real record is broken here.
    #[test(tokio::test)]
    async fn invalid_applicability_is_left_out() -> anyhow::Result<()> {
        let mut value: Value = serde_json::from_slice(&document_bytes(RECORD).await?)?;
        value["containers"]["cna"]["cpeApplicability"][0]["nodes"][0]["cpeMatch"][0]["vulnerable"] =
            "yes".into();

        let record: CveRecord = serde_json::from_value(value)?;

        assert_eq!(
            (record.cve.id(), summary(&record)),
            (
                "CVE-2024-26581",
                (
                    vec![],
                    &[
                        "Ignoring the invalid cpeApplicability of container cna: invalid type: \
                       string \"yes\", expected a boolean"
                            .to_string()
                    ][..]
                )
            )
        );
        Ok(())
    }
}
