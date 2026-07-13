use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

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
    /// Whether this is a concrete (fully-specified) format, not a category or unknown.
    pub fn is_concrete(&self) -> bool {
        !matches!(self, Format::Unknown | Format::Advisory | Format::SBOM)
    }

    /// Check whether this format satisfies a given hint.
    pub fn matches_hint(&self, hint: Format) -> bool {
        match hint {
            Format::Unknown => true,
            Format::Advisory => matches!(self, Format::CSAF | Format::CVE | Format::OSV),
            Format::SBOM => matches!(
                self,
                Format::SPDX
                    | Format::CycloneDX
                    | Format::ClearlyDefined
                    | Format::ClearlyDefinedCuration
            ),
            concrete => *self == concrete,
        }
    }
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
    use strum::VariantNames;
    use test_log::test;
    use utoipa::{
        PartialSchema,
        openapi::{RefOr, Schema},
    };

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

    /// Ensure the variants from strum are the same as the ones in the schema.
    #[test]
    fn schema_variants() {
        let RefOr::T(Schema::Object(o)) = Format::schema() else {
            panic!("must be an object")
        };

        let variants = Format::VARIANTS.iter().map(|name| json!(name)).collect();

        assert_eq!(o.enum_values, Some(variants));
    }
}
