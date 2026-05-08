pub mod assertion;
pub mod label;
pub mod sbom;

#[cfg(test)]
mod test;

use trustify_common::db::pagination_cache::PaginationCache;

pub struct SbomService {
    pub(crate) cache: PaginationCache,
}

impl SbomService {
    /// Creates a new SBOM service.
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }
}
