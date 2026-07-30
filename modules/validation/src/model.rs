use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// Severity level of a validation result.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ValidationLevel {
    Ok,
    Information,
    Warning,
    Error,
}

impl ValidationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Information => "information",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Parses a level string into a ValidationLevel.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ok" => Some(Self::Ok),
            "information" => Some(Self::Information),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Request body for upserting a validation result.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ValidationRequest {
    pub level: ValidationLevel,
    pub message: String,
    pub source: String,
    pub key: String,
}

/// A validation result as returned by the API.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ValidationResult {
    pub id: Uuid,
    pub level: ValidationLevel,
    pub message: String,
    pub source: String,
    pub key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
}

impl From<trustify_entity::document_validation::Model> for ValidationResult {
    fn from(m: trustify_entity::document_validation::Model) -> Self {
        Self {
            id: m.id,
            level: ValidationLevel::parse(&m.level).unwrap_or(ValidationLevel::Information),
            message: m.message,
            source: m.source,
            key: m.key,
            timestamp: m.timestamp,
        }
    }
}
