#![cfg_attr(test, recursion_limit = "256")]

pub mod config;
pub mod endpoints;
pub(crate) mod inject_token;

#[cfg(test)]
mod test;
