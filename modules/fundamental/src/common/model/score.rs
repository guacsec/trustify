use serde::{Deserialize, Serialize};
use serde_json::json;
use trustify_entity::{advisory_vulnerability_score as entity_score, advisory_vulnerability_score};
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

impl From<entity_score::ScoreType> for ScoreType {
    fn from(value: entity_score::ScoreType) -> Self {
        match value {
            entity_score::ScoreType::V2_0 => Self::V2,
            entity_score::ScoreType::V3_0 => Self::V3,
            entity_score::ScoreType::V3_1 => Self::V3_1,
            entity_score::ScoreType::V4_0 => Self::V4,
        }
    }
}

impl From<ScoreType> for entity_score::ScoreType {
    fn from(value: ScoreType) -> Self {
        match value {
            ScoreType::V2 => Self::V2_0,
            ScoreType::V3 => Self::V3_0,
            ScoreType::V3_1 => Self::V3_1,
            ScoreType::V4 => Self::V4_0,
        }
    }
}

/// Severity rating derived from a CVSS score value.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, PartialEq, strum::VariantArray)]
pub enum Severity {
    /// No impact (score = 0.0)
    #[serde(rename = "none")]
    None,
    /// Low severity (score 0.1–3.9)
    #[serde(rename = "low")]
    Low,
    /// Medium severity (score 4.0–6.9)
    #[serde(rename = "medium")]
    Medium,
    /// High severity (score 7.0–8.9)
    #[serde(rename = "high")]
    High,
    /// Critical severity (score 9.0–10.0)
    #[serde(rename = "critical")]
    Critical,
}

impl From<(ScoreType, f64)> for Severity {
    /// Converts a (ScoreType, numeric score) pair to a Severity rating.
    ///
    /// Uses version-specific thresholds per CVSS specifications:
    /// - v2.0: Low (0.0–3.9), Medium (4.0–6.9), High (7.0–10.0)
    /// - v3.x/v4.0: None (0.0), Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9), Critical (9.0–10.0)
    fn from((r#type, score): (ScoreType, f64)) -> Self {
        match r#type {
            ScoreType::V2 => match score {
                s if s < 4.0 => Self::Low,
                s if s < 7.0 => Self::Medium,
                _ => Self::High,
            },
            ScoreType::V3 | ScoreType::V3_1 | ScoreType::V4 => match score {
                s if s <= 0.0 => Self::None,
                s if s < 4.0 => Self::Low,
                s if s < 7.0 => Self::Medium,
                s if s < 9.0 => Self::High,
                _ => Self::Critical,
            },
        }
    }
}

impl PartialSchema for Severity {
    fn schema() -> RefOr<Schema> {
        Schema::Object(
            ObjectBuilder::new()
                .schema_type(SchemaType::Type(Type::String))
                .description(Some("Severity rating derived from a CVSS score value."))
                .enum_values(Some(["none", "low", "medium", "high", "critical"]))
                .extensions(Some(
                    ExtensionsBuilder::new()
                        .add(
                            "x-enum-descriptions",
                            json!([
                                "No impact (score = 0.0)",
                                "Low severity (score 0.1–3.9)",
                                "Medium severity (score 4.0–6.9)",
                                "High severity (score 7.0–8.9)",
                                "Critical severity (score 9.0–10.0)",
                            ]),
                        )
                        .build(),
                ))
                .build(),
        )
        .into()
    }
}

impl ToSchema for Severity {}

impl From<advisory_vulnerability_score::Severity> for Severity {
    fn from(value: entity_score::Severity) -> Self {
        match value {
            advisory_vulnerability_score::Severity::None => Self::None,
            advisory_vulnerability_score::Severity::Low => Self::Low,
            advisory_vulnerability_score::Severity::Medium => Self::Medium,
            advisory_vulnerability_score::Severity::High => Self::High,
            advisory_vulnerability_score::Severity::Critical => Self::Critical,
        }
    }
}

impl From<Severity> for advisory_vulnerability_score::Severity {
    fn from(value: Severity) -> Self {
        match value {
            Severity::None => Self::None,
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, ToSchema, PartialEq)]
pub struct Score {
    /// The score type
    pub r#type: ScoreType,
    /// The actual value
    pub value: f64,
    /// The derived severity
    pub severity: Severity,
}

/// A CVSS score combined with its raw vector string, for contexts where clients need both
/// the pre-parsed numeric values and the original vector for display or re-parsing.
#[derive(Clone, Serialize, Deserialize, Debug, ToSchema, PartialEq)]
pub struct ScoredVector {
    /// The score type, value, and derived severity.
    #[serde(flatten)]
    pub score: Score,
    /// The raw CVSS vector string (e.g. `CVSS:3.1/AV:N/AC:L/...`).
    pub vector: String,
}

impl From<entity_score::Model> for ScoredVector {
    /// Converts a DB score model into a `ScoredVector`, preserving both the parsed score
    /// fields and the original vector string.
    fn from(model: entity_score::Model) -> Self {
        Self {
            vector: model.vector.clone(),
            score: Score::from(model),
        }
    }
}

impl From<entity_score::Model> for Score {
    /// Converts a DB score model into a `Score`, mapping entity types to API types and
    /// rounding the value to one decimal place to avoid f32→f64 precision artifacts.
    fn from(model: entity_score::Model) -> Self {
        let value = (model.score as f64 * 10.0).round() / 10.0;
        Score {
            r#type: ScoreType::from(model.r#type),
            value,
            severity: Severity::from(model.severity),
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
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

    #[rstest]
    // v2.0: negative and zero map to Low (no None in v2.0)
    #[case::v2_negative(ScoreType::V2, -1.0, Severity::Low)]
    #[case::v2_zero(ScoreType::V2, 0.0, Severity::Low)]
    #[case::v2_low(ScoreType::V2, 3.9, Severity::Low)]
    #[case::v2_medium_boundary(ScoreType::V2, 4.0, Severity::Medium)]
    #[case::v2_medium(ScoreType::V2, 6.9, Severity::Medium)]
    #[case::v2_high_boundary(ScoreType::V2, 7.0, Severity::High)]
    #[case::v2_high(ScoreType::V2, 10.0, Severity::High)]
    // v3.0
    #[case::v3_0_negative(ScoreType::V3, -1.0, Severity::None)]
    #[case::v3_0_zero(ScoreType::V3, 0.0, Severity::None)]
    #[case::v3_0_low(ScoreType::V3, 3.9, Severity::Low)]
    #[case::v3_0_medium_boundary(ScoreType::V3, 4.0, Severity::Medium)]
    #[case::v3_0_medium(ScoreType::V3, 6.9, Severity::Medium)]
    #[case::v3_0_high_boundary(ScoreType::V3, 7.0, Severity::High)]
    #[case::v3_0_high(ScoreType::V3, 8.9, Severity::High)]
    #[case::v3_0_critical_boundary(ScoreType::V3, 9.0, Severity::Critical)]
    #[case::v3_0_critical(ScoreType::V3, 10.0, Severity::Critical)]
    // v3.1
    #[case::v3_1_negative(ScoreType::V3_1, -1.0, Severity::None)]
    #[case::v3_1_zero(ScoreType::V3_1, 0.0, Severity::None)]
    #[case::v3_1_low(ScoreType::V3_1, 0.1, Severity::Low)]
    #[case::v3_1_critical(ScoreType::V3_1, 9.0, Severity::Critical)]
    // v4.0
    #[case::v4_negative(ScoreType::V4, -1.0, Severity::None)]
    #[case::v4_zero(ScoreType::V4, 0.0, Severity::None)]
    #[case::v4_low(ScoreType::V4, 0.1, Severity::Low)]
    #[case::v4_critical(ScoreType::V4, 9.0, Severity::Critical)]
    fn severity_from_score(
        #[case] score_type: ScoreType,
        #[case] score: f64,
        #[case] expected: Severity,
    ) {
        assert_eq!(Severity::from((score_type, score)), expected);
    }
}
