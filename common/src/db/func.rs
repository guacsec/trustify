use sea_orm::Iden;
use sea_orm::{ConnectionTrait, DbErr, ExecResult};
use sea_query::{Func, SelectStatement};

/// PostgreSQL's `array_agg` function.
///
/// See: <https://www.postgresql.org/docs/current/functions-aggregate.html>
pub struct ArrayAgg;

impl Iden for ArrayAgg {
    fn unquoted(&self) -> &str {
        "array_agg"
    }
}

/// PostgreSQL's `json_build_object` function.
///
/// See: <https://www.postgresql.org/docs/current/functions-json.html>
pub struct JsonBuildObject;

impl Iden for JsonBuildObject {
    fn unquoted(&self) -> &str {
        "json_build_object"
    }
}

/// PostgreSQL's `json_build_object` function.
///
/// See: <https://www.postgresql.org/docs/current/functions-json.html>
pub struct ToJson;

impl Iden for ToJson {
    fn unquoted(&self) -> &str {
        "to_json"
    }
}

pub struct Cvss3Score;

impl Iden for Cvss3Score {
    fn unquoted(&self) -> &str {
        "cvss3_score"
    }
}

pub struct VersionMatches;

impl Iden for VersionMatches {
    fn unquoted(&self) -> &str {
        "version_matches"
    }
}

/// The function updating the deprecated state of a consistent set of advisories.
pub struct UpdateDeprecatedAdvisory;

impl Iden for UpdateDeprecatedAdvisory {
    fn unquoted(&self) -> &str {
        "update_deprecated_advisory"
    }
}

impl UpdateDeprecatedAdvisory {
    pub async fn execute(db: &impl ConnectionTrait, identifier: &str) -> Result<ExecResult, DbErr> {
        let stmt = db
            .get_database_backend()
            .build(SelectStatement::new().expr(Func::cust(Self).arg(identifier)));

        db.execute_raw(stmt).await
    }
}

// NOTE: This enum is currently unused. The `expand_license_expression_with_mappings`
// PostgreSQL function is invoked via raw SQL in `populate_expanded_license()` due to
// its use of complex PostgreSQL features (composite types, array aggregation over
// `license_mapping`, and complex CTEs). This enum is preserved for potential future
// refactoring to SeaQuery/SeaORM query builders, though such migration may not be
// feasible given the function's complexity and the performance benefits of raw SQL.
#[derive(Iden)]
pub enum CustomFunc {
    #[iden = "expand_license_expression_with_mappings"]
    ExpandLicenseExpressionWithMappings,
}
