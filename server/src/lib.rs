#![recursion_limit = "256"]

#[cfg(feature = "garage-door")]
mod embedded_oidc;
mod endpoints;
mod sample_data;

pub use sample_data::sample_data;

pub mod openapi;
pub mod profile;
