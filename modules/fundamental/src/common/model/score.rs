use serde::{Deserialize, Serialize};
use serde_json::json;
use trustify_cvss::cvss3::severity::Severity;
use trustify_entity::{advisory_vulnerability_score, cvss3};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{
        ObjectBuilder, RefOr, Schema, Type, extensions::ExtensionsBuilder, schema::SchemaType,
    },
};

/// The type of score, indicating the scoring system and version used.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, PartialEq, strum::VariantArray)]
pub enum ScoreType {
    /// CVSS v2.0 score
    #[serde(rename = "2.0")]
    V2,
    /// CVSS v3.0 score
    #[serde(rename = "3.0")]
    V3,
    /// CVSS v3.1 score
    #[serde(rename = "3.1")]
    V3_1,
    /// CVSS v4.0 score
    #[serde(rename = "4.0")]
    V4,
}

impl PartialSchema for ScoreType {
    fn schema() -> RefOr<Schema> {
        Schema::Object(
            ObjectBuilder::new()
                .schema_type(SchemaType::Type(Type::String))
                .description(Some(
                    "The type of score, indicating the scoring system and version used.",
                ))
                .enum_values(Some(["2.0", "3.0", "3.1", "4.0"]))
                .extensions(Some(
                    ExtensionsBuilder::new()
                        .add(
                            "x-enum-descriptions",
                            json!([
                                "CVSS v2.0 score",
                                "CVSS v3.0 score",
                                "CVSS v3.1 score",
                                "CVSS v4.0 score",
                            ]),
                        )
                        .build(),
                ))
                .build(),
        )
        .into()
    }
}

impl ToSchema for ScoreType {}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, ToSchema, PartialEq)]
pub struct Score {
    /// The score type
    pub r#type: ScoreType,
    /// The actual value
    pub value: f64,
    /// The derived severity
    pub severity: Severity,
}

impl TryFrom<cvss3::Model> for Score {
    type Error = ();

    fn try_from(row: cvss3::Model) -> Result<Self, Self::Error> {
        // map to V3* type
        let r#type = match row.minor_version {
            0 => ScoreType::V3,
            1 => ScoreType::V3_1,
            _ => return Err(()),
        };

        Ok(Score {
            r#type,
            value: row.score,
            severity: row.score.into(),
        })
    }
}

impl From<advisory_vulnerability_score::Model> for Score {
    fn from(model: advisory_vulnerability_score::Model) -> Self {
        let r#type = match model.r#type {
            advisory_vulnerability_score::ScoreType::V2_0 => ScoreType::V2,
            advisory_vulnerability_score::ScoreType::V3_0 => ScoreType::V3,
            advisory_vulnerability_score::ScoreType::V3_1 => ScoreType::V3_1,
            advisory_vulnerability_score::ScoreType::V4_0 => ScoreType::V4,
        };

        let severity = match model.severity {
            advisory_vulnerability_score::Severity::None => Severity::None,
            advisory_vulnerability_score::Severity::Low => Severity::Low,
            advisory_vulnerability_score::Severity::Medium => Severity::Medium,
            advisory_vulnerability_score::Severity::High => Severity::High,
            advisory_vulnerability_score::Severity::Critical => Severity::Critical,
        };

        // Round to 1 decimal place to avoid f32->f64 precision artifacts
        // CVSS scores are typically displayed with 1 decimal precision
        let value = (model.score as f64 * 10.0).round() / 10.0;

        Score {
            r#type,
            value,
            severity,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use strum::VariantArray;

    #[test]
    fn ensure_schema_variants() {
        let RefOr::T(Schema::Object(schema)) = ScoreType::schema() else {
            panic!("must but a concrete object");
        };

        // ensure the base type is a string

        assert!(matches!(schema.schema_type, SchemaType::Type(Type::String)));

        // ensure we have as many enum variants as in our Rust type, and that they match

        assert_eq!(
            schema.enum_values,
            Some(
                ScoreType::VARIANTS
                    .iter()
                    .map(|v| json!(v))
                    .collect::<Vec<_>>()
            )
        );

        // ensure that we have the same entries in the extension description

        let ext = &schema.extensions.unwrap()["x-enum-descriptions"];
        let serde_json::Value::Array(items) = ext else {
            panic!("must be an array")
        };

        assert_eq!(
            items,
            &ScoreType::VARIANTS
                .iter()
                .map(|v| {
                    let v = json!(v).to_string();
                    let v = v.trim_matches('\"');
                    format!("CVSS v{v} score")
                })
                .collect::<Vec<_>>()
        );
    }
}
