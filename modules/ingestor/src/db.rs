use sea_query::Iden;

pub struct QualifiedPackageTransitive;

impl Iden for QualifiedPackageTransitive {
    fn unquoted(&self) -> &str {
        "qualified_package_transitive"
    }
}

pub struct LeftPackageId;
impl Iden for LeftPackageId {
    fn unquoted(&self) -> &str {
        "left_package_id"
    }
}
