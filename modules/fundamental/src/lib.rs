#![recursion_limit = "256"]

pub mod advisory;
pub mod common;
pub mod db;
pub mod endpoints;
pub mod error;
pub mod license;
pub mod organization;
pub mod product;
pub mod purl;
pub mod sbom;
pub mod source_document;
#[allow(deprecated)]
pub mod vulnerability;
pub mod weakness;

pub use endpoints::{Config, configure};
pub use error::Error;

#[cfg(test)]
pub mod test;
