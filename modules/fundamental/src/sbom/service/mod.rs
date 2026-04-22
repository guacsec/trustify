pub mod assertion;
pub mod label;
pub mod sbom;

#[cfg(test)]
mod test;

use trustify_common::db::{Database, pagination_cache::PaginationCache};

pub struct SbomService {
    db: Database,
    pub(crate) cache: PaginationCache,
}

impl SbomService {
    pub fn new(db: Database, cache: PaginationCache) -> Self {
        Self { db, cache }
    }
}
