use sea_orm::Iden;
use sea_orm::{ConnectionTrait, DbErr, ExecResult};
use sea_query::{Func, SelectStatement};
use std::fmt::Write;

/// PostgreSQL's `array_agg` function.
///
/// See: <https://www.postgresql.org/docs/current/functions-aggregate.html>
pub struct ArrayAgg;

impl Iden for ArrayAgg {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        s.write_str("array_agg").unwrap();
    }
}

/// PostgreSQL's `json_build_object` function.
///
/// See: <https://www.postgresql.org/docs/current/functions-json.html>
pub struct JsonBuildObject;

impl Iden for JsonBuildObject {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        s.write_str("json_build_object").unwrap();
    }
}

/// PostgreSQL's `json_build_object` function.
///
/// See: <https://www.postgresql.org/docs/current/functions-json.html>
pub struct ToJson;

impl Iden for ToJson {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        s.write_str("to_json").unwrap();
    }
}

pub struct Cvss3Score;

impl Iden for Cvss3Score {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "cvss3_score").unwrap()
    }
}

pub struct VersionMatches;

impl Iden for VersionMatches {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "version_matches").unwrap()
    }
}

/// The function updating the deprecated state of a consistent set of advisories.
pub struct UpdateDeprecatedAdvisory;

impl Iden for UpdateDeprecatedAdvisory {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "update_deprecated_advisory").unwrap()
    }
}

impl UpdateDeprecatedAdvisory {
    pub async fn execute(db: &impl ConnectionTrait, identifier: &str) -> Result<ExecResult, DbErr> {
        let stmt = db
            .get_database_backend()
            .build(SelectStatement::new().expr(Func::cust(Self).arg(identifier)));

        db.execute(stmt).await
    }
}

/// The function expanding the license replacing all 'LicenseRef-' instances
/// with the actual license they refer to.
pub struct ExpandLicenseExpression;

impl Iden for ExpandLicenseExpression {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "expand_license_expression").unwrap()
    }
}
