use std::str::FromStr;

use crate::graph::error::Error;
use trustify_entity::status::Status;

/// Parses a status slug string into a `Status` enum value.
pub fn parse_status(status: &str) -> Result<Status, Error> {
    Status::from_str(status).map_err(|_| Error::InvalidStatus(status.to_string()))
}
