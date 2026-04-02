use crate::purl::model::{BasePurlHead, PurlHead, VersionedPurlHead};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trustify_common::purl::Purl;
use trustify_entity::qualified_purl::{self, CanonicalPurl};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, ToSchema, Hash)]
pub struct PurlSummary {
    #[serde(flatten)]
    pub head: PurlHead,
    #[deprecated]
    pub base: BasePurlHead,
    #[deprecated]
    pub version: VersionedPurlHead,
    #[deprecated]
    pub qualifiers: BTreeMap<String, String>,
}

impl From<Purl> for PurlSummary {
    #[allow(deprecated)]
    fn from(purl: Purl) -> Self {
        let base_purl_id = purl.package_uuid();
        let versioned_purl_id = purl.version_uuid();
        let qualified_purl_id = purl.qualifier_uuid();

        PurlSummary {
            head: PurlHead {
                uuid: qualified_purl_id,
                purl: purl.clone(),
            },
            base: BasePurlHead {
                uuid: base_purl_id,
                purl: purl.to_base(),
            },
            version: VersionedPurlHead {
                uuid: versioned_purl_id,
                purl: purl.to_version(),
                version: purl.version.clone().unwrap_or_default(),
            },
            qualifiers: purl.qualifiers,
        }
    }
}

impl PurlSummary {
    pub fn from_entities(qualified_packages: &[qualified_purl::Model]) -> Vec<Self> {
        qualified_packages.iter().map(Self::from_entity).collect()
    }

    pub fn from_entity(purl: &qualified_purl::Model) -> Self {
        Purl::from(purl.purl.clone()).into()
    }

    pub fn from_values(values: Vec<serde_json::Value>) -> Vec<Self> {
        values
            .into_iter()
            .flat_map(|purl| {
                serde_json::from_value::<CanonicalPurl>(purl)
                    .inspect_err(|err| {
                        log::warn!("Failed to deserialize PURL: {err}");
                    })
                    .ok()
            })
            .map(|purl| Purl::from(purl).into())
            .collect()
    }
}
