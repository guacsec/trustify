//! Format-independent vulnerability correlation from raw documents to verdicts.

pub mod collector;
pub mod engine;
pub mod evidence;
pub mod extract;
pub(crate) mod matching;
pub mod memory;
pub mod options;
pub(crate) mod resolution;
pub mod types;
pub mod verdict;
pub mod version;

#[cfg(test)]
mod test;
