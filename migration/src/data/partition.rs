use crate::data::Document;
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    num::NonZeroU64,
};

/// Information required for partitioning data
#[derive(Debug, Copy, Clone)]
pub struct Partition {
    pub current: u64,
    pub total: NonZeroU64,
}

/// A thing which can be distributed over different partitions via a hashed id.
///
/// The idea is that the thing returns a hash ID, which can then be distributed over partitions
/// by using a "X of Y" approach. Where the thing is processed when "ID modulo Y == X".
pub trait Partitionable {
    /// Get the hashed ID for the thing.
    fn hashed_id(&self) -> u64;
}

impl<H: Hash> Partitionable for H {
    fn hashed_id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for Partition {
    fn default() -> Self {
        Self::new_one()
    }
}

impl Partition {
    /// Create a new partition of one.
    ///
    /// This will be one processor processing everything.
    pub const fn new_one() -> Self {
        Self {
            current: 0,
            total: unsafe { NonZeroU64::new_unchecked(1) },
        }
    }

    pub fn is_selected<D>(&self, id: &D::Id) -> bool
    where
        D: Document,
        D::Id: Partitionable,
    {
        id.hashed_id() % self.total == self.current
    }
}
