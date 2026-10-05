pub mod correlation;
pub mod ingest;

/// Frontend configuration exposed via `/.well-known/trustify`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FrontendInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc: Option<FrontendOidcInfo>,
}

/// OIDC configuration for frontend clients.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FrontendOidcInfo {
    pub issuer_url: String,
    pub client_id: String,
    pub scope: String,
}
