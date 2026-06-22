#![recursion_limit = "256"]

pub mod advisory;
pub mod endpoints;
pub mod organization;
pub mod sbom;
pub mod sbomstatus;
pub mod vulnerability;

use async_graphql::MergedObject;

#[cfg(test)]
pub mod test;

#[derive(MergedObject, Default)]
pub struct RootQuery(
    advisory::AdvisoryQuery,
    organization::OrganizationQuery,
    sbom::SbomQuery,
    vulnerability::VulnerabilityQuery,
    sbomstatus::SbomStatusQuery,
);
