use super::*;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::collections::HashSet;

/// How OSV documents are retrieved. Defaults to Git when omitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(transform = default_git_transport)]
#[serde(
    tag = "transport",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum OsvTransport {
    Git {
        /// An optional branch. Will use the default branch otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        branch: Option<String>,
        /// An optional path to start searching for documents. Defaults to the repository root.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    Http {
        /// Base URL for REST records (`<id>.json`). Defaults to the index directory.
        #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none")]
        base_url: Option<Url>,
    },
}

// Serde cannot express a default for an internally tagged enum. Keep the
// schema in sync with the legacy-Git fallback in our custom deserializer.
fn default_git_transport(schema: &mut schemars::Schema) {
    if let Some(required) = schema
        .get_mut("oneOf")
        .and_then(|variants| variants.get_mut(0))
        .and_then(|git| git.get_mut("required"))
        .and_then(serde_json::Value::as_array_mut)
    {
        required.retain(|field| field != "transport");
    }
}

impl ToSchema for OsvTransport {}

impl utoipa::PartialSchema for OsvTransport {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use utoipa::openapi::schema::{
            KnownFormat, ObjectBuilder, OneOfBuilder, SchemaFormat, SchemaType, Type,
        };

        let discriminator = |value| {
            ObjectBuilder::new()
                .schema_type(Type::String)
                .enum_values(Some([value]))
        };
        let optional_string =
            || ObjectBuilder::new().schema_type(SchemaType::from_iter([Type::String, Type::Null]));
        OneOfBuilder::new()
            .description(Some("How OSV documents are retrieved. Defaults to Git when omitted."))
            .item(
                ObjectBuilder::new()
                    .property("transport", discriminator("git"))
                    .property(
                        "branch",
                        optional_string()
                            .description(Some("An optional branch. Will use the default branch otherwise.")),
                    )
                    .property(
                        "path",
                        optional_string()
                            .description(Some("An optional path to start searching for documents. Defaults to the repository root.")),
                    ),
            )
            .item(
                ObjectBuilder::new()
                    .property("transport", discriminator("http"))
                    .required("transport")
                    .property(
                        "baseUrl",
                        optional_string().format(Some(SchemaFormat::KnownFormat(KnownFormat::Uri)))
                            .description(Some("Base URL for REST records (`<id>.json`). Defaults to the index directory.")),
                    ),
            )
            .into()
    }
}

impl<'de> Deserialize<'de> for OsvTransport {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Kind {
            Git,
            Http,
        }

        // Legacy configurations have no discriminator. Decode the flat options
        // first to preserve those Git configurations, but reject mixed options.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Options {
            transport: Option<Kind>,
            branch: Option<String>,
            path: Option<String>,
            base_url: Option<Url>,
        }

        let options = Options::deserialize(deserializer)?;
        match options.transport.unwrap_or(Kind::Git) {
            Kind::Git => {
                if options.base_url.is_some() {
                    return Err(D::Error::custom("OSV baseUrl requires HTTP transport"));
                }
                Ok(Self::Git {
                    branch: options.branch,
                    path: options.path,
                })
            }
            Kind::Http => {
                if options.branch.is_some() || options.path.is_some() {
                    return Err(D::Error::custom(
                        "OSV branch and path require Git transport",
                    ));
                }
                Ok(Self::Http {
                    base_url: options.base_url,
                })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OsvImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    /// A Git repository URL or an OSV REST index URL.
    pub source: String,

    #[serde(flatten)]
    pub transport: OsvTransport,

    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub years: HashSet<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_year: Option<u16>,
}

impl Deref for OsvImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for OsvImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::{Value, from_value, json, to_value};
    use utoipa::PartialSchema;

    #[rstest]
    #[case::https_git("https://example.com/repo.git")]
    #[case::http_index_name("https://example.com/all.json")]
    #[case::local("/local/repo")]
    fn legacy_git_configuration(#[case] source: &str) {
        let config: OsvImporter = from_value(json!({
            "source": source, "period": "1h", "branch": "osv", "path": "advisories",
            "years": [2026], "startYear": 2025,
        }))
        .unwrap();
        assert_eq!(
            config.transport,
            OsvTransport::Git {
                branch: Some("osv".into()),
                path: Some("advisories".into()),
            }
        );
        assert!(config.years.contains(&2026));
        assert_eq!(config.start_year, Some(2025));
        let serialized = to_value(&config).unwrap();
        assert_eq!(serialized["transport"], "git");
        assert_eq!(from_value::<OsvImporter>(serialized).unwrap(), config);
    }

    #[rstest]
    #[case::git(json!({"transport": "git"}))]
    #[case::git_options(json!({"transport": "git", "branch": "main", "path": "vulns"}))]
    #[case::http(json!({"transport": "http"}))]
    #[case::http_base_url(json!({"transport": "http", "baseUrl": "https://example.com/records/"}))]
    fn transport_configuration_roundtrip(#[case] mut value: Value) {
        value["source"] = json!("https://example.com/feed.json");
        value["period"] = json!("1h");
        value["disabled"] = json!(false);
        let config: OsvImporter = from_value(value.clone()).unwrap();
        let serialized = to_value(&config).unwrap();
        assert_eq!(serialized, value);
        assert_eq!(from_value::<OsvImporter>(serialized).unwrap(), config);
    }

    #[rstest]
    #[case::legacy_base_url(json!({"baseUrl": "https://example.com/records/"}))]
    #[case::git_base_url(json!({"transport": "git", "baseUrl": "https://example.com/records/"}))]
    #[case::http_branch(json!({"transport": "http", "branch": "main"}))]
    #[case::http_path(json!({"transport": "http", "path": "vulns"}))]
    #[case::unknown_transport(json!({"transport": "unsupported"}))]
    fn mixed_transport_options_are_rejected(#[case] mut value: Value) {
        value["source"] = json!("https://example.com/feed.json");
        value["period"] = json!("1h");
        assert!(from_value::<OsvImporter>(value).is_err());
    }

    #[test]
    fn nested_importer_configuration() {
        let config: ImporterConfiguration = from_value(json!({
            "osv": {"source": "https://example.com/index.json", "period": "1h",
            "transport": "http", "baseUrl": "https://example.com/records/",
            }
        }))
        .unwrap();
        let serialized: Value = to_value(&config).unwrap();
        assert_eq!(serialized["osv"]["transport"], "http");
        assert_eq!(serialized["osv"]["baseUrl"], "https://example.com/records/");
        assert_eq!(
            from_value::<ImporterConfiguration>(serialized).unwrap(),
            config
        );
    }

    #[rstest]
    #[case::legacy(json!({}))]
    #[case::legacy_options(json!({"branch": "main", "path": "advisories"}))]
    #[case::git(json!({"transport": "git"}))]
    #[case::git_options(json!({"transport": "git", "branch": "main", "path": "advisories"}))]
    #[case::http(json!({"transport": "http"}))]
    #[case::http_options(json!({"transport": "http", "baseUrl": "https://example.com/records/"}))]
    fn schemas_accept_legacy_and_explicit_transports(#[case] mut config: Value) {
        config["source"] = json!("https://example.com/source");
        config["period"] = json!("1h");
        let importer: OsvImporter = from_value(config.clone()).unwrap();
        let json_schema = to_value(schemars::schema_for!(OsvImporter)).unwrap();
        let openapi = json!({
            "components": {"schemas": {"CommonImporter": CommonImporter::schema(), "OsvTransport": OsvTransport::schema(), "Labels": Labels::schema()}},
            "allOf": [OsvImporter::schema()],
        });
        for schema in [json_schema, openapi] {
            let validator = jsonschema::validator_for(&schema).unwrap();
            validator.validate(&config).unwrap();
            validator.validate(&to_value(&importer).unwrap()).unwrap();
        }
    }

    #[rstest]
    #[case::unknown(json!("unsupported"))]
    #[case::wrong_type(json!(false))]
    fn schemas_reject_invalid_transports(#[case] transport: Value) {
        let config = json!({"transport": transport});
        for schema in [
            to_value(schemars::schema_for!(OsvTransport)).unwrap(),
            to_value(OsvTransport::schema()).unwrap(),
        ] {
            let validator = jsonschema::validator_for(&schema).unwrap();
            assert!(!validator.is_valid(&config));
        }
    }

    #[test]
    fn schemas_default_only_the_git_variant() {
        for schema in [
            to_value(schemars::schema_for!(OsvTransport)).unwrap(),
            to_value(OsvTransport::schema()).unwrap(),
        ] {
            let variants = schema["oneOf"].as_array().unwrap();
            assert_eq!(variants.len(), 2);
            assert!(
                !variants[0]["required"]
                    .as_array()
                    .is_some_and(|required| required.contains(&json!("transport")))
            );
            assert_eq!(variants[1]["required"], json!(["transport"]));
            let git = jsonschema::validator_for(&variants[0]).unwrap();
            let http = jsonschema::validator_for(&variants[1]).unwrap();
            assert!(git.is_valid(&json!({})));
            assert!(git.is_valid(&json!({"transport": "git"})));
            assert!(!git.is_valid(&json!({"transport": "http"})));
            assert!(!http.is_valid(&json!({})));
            assert!(http.is_valid(&json!({"transport": "http"})));
            assert!(!http.is_valid(&json!({"transport": "git"})));
        }
    }

    #[test]
    fn openapi_uses_transport_specific_fields() {
        let schema = to_value(OsvTransport::schema()).unwrap();
        let variants = schema["oneOf"].as_array().unwrap();
        let git = &variants[0]["properties"];
        assert!(git.get("branch").is_some());
        assert!(git.get("path").is_some());
        assert!(git.get("baseUrl").is_none());
        let http = &variants[1]["properties"];
        assert!(http.get("baseUrl").is_some());
        assert!(http.get("base_url").is_none());
        assert!(http.get("branch").is_none());
        assert!(http.get("path").is_none());
    }
}
