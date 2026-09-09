use std::borrow::Cow;
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ErrorInformation {
    /// A machine-readable error type
    pub error: Cow<'static, str>,
    /// A human-readable error message
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    /// Human-readable error details
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorInformation {
    pub fn new(error: impl Into<Cow<'static, str>>, message: impl Display) -> Self {
        Self {
            error: error.into(),
            message: message.to_string(),
            details: None,
        }
    }
}
