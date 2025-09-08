use sea_query::Iden;
use std::fmt::Write;

pub struct QualifiedPackageTransitive;

impl Iden for QualifiedPackageTransitive {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "qualified_package_transitive").unwrap();
    }
}

pub struct LeftPackageId;
impl Iden for LeftPackageId {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "left_package_id").unwrap();
    }
}
