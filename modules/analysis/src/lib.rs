extern crate core;

pub mod config;
pub mod endpoints;
pub mod error;
pub mod service;

use actix_http::StatusCode;
pub use error::Error;
use uuid::Uuid;
pub mod model;

#[cfg(test)]
pub mod test;

fn parse_sbom_id(id: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(id).map_err(|err| Error::BadRequest {
        msg: format!("Unable to parse SBOM ID {id}: {err}"),
        status: StatusCode::BAD_REQUEST,
    })
}
