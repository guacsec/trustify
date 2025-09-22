use crate::data::Document;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::num::{NonZeroU64, NonZeroUsize};
use trustify_entity::sbom;

#[derive(Debug, Copy, Clone)]
pub struct Partition {
    pub current: u64,
    pub total: NonZeroU64,
}

pub trait Partitionable {
    fn hashed_id(&self) -> u64;
}

impl Partitionable for sbom::Model {
    fn hashed_id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.sbom_id.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for Partition {
    fn default() -> Self {
        Self::new_one()
    }
}

impl Partition {
    pub const fn new_one() -> Self {
        Self {
            current: 0,
            total: unsafe { NonZeroU64::new_unchecked(1) },
        }
    }

    pub fn is_selected<D>(&self, document: &D::Model) -> bool
    where
        D: Document,
        D::Model: Partitionable,
    {
        document.hashed_id() % self.total == self.current
    }
}
