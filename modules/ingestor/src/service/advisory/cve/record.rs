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
}

impl From<Cve> for CveRecord {
    fn from(cve: Cve) -> Self {
        Self {
            cve,
            applicability: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for CveRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let applicability = applicability(&value).map_err(D::Error::custom)?;
        let cve = Cve::deserialize(value).map_err(D::Error::custom)?;
        Ok(Self { cve, applicability })
    }
}

/// The `cpeApplicability` of the containers of a record.
fn applicability(
    record: &Value,
) -> Result<Vec<(Configuration, trustify_api::correlation::ProviderIdentity)>, serde_json::Error> {
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
            result.extend(
                Vec::<Configuration>::deserialize(applicability)?
                    .into_iter()
                    .map(|configuration| (configuration, provider.clone())),
            );
        }
    }
    Ok(result)
}
