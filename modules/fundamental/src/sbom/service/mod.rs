pub mod assertion;
pub mod label;
pub mod sbom;

#[cfg(test)]
mod test;

use trustify_common::db::Database;

#[derive(Clone)]
pub struct SbomService {
    db: Database,
}

impl SbomService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}
