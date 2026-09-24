use super::{
    util::branch_purl,
    value::{self, OnInvalidData},
};
use crate::graph::advisory::{
    vers::parse_vers,
    version::{Version, VersionInfo, VersionSpec},
};
use crate::service::Error;
use cpe::cpe::Cpe;
use csaf::schema::csaf2_0::schema::{Branch, CategoryOfTheBranch, FullProductNameT};
use sbom_walker::report::ReportSink;
use trustify_common::purl::Purl;
use trustify_entity::version_scheme::VersionScheme;

#[derive(Clone, Default, Debug, Eq, Hash, PartialEq)]
pub struct ProductStatus {
    pub vendor: Option<String>,
    pub product: String,
    pub version: Option<VersionInfo>,
    pub cpe: Option<trustify_common::cpe::Cpe>,
    pub status: &'static str,
    pub purls: Vec<Purl>,
    pub packages: Vec<String>,
    pub vers_specs: Vec<VersionInfo>,
}

impl ProductStatus {
    pub fn update_from_branch(
        &mut self,
        branch: &Branch,
        on_invalid: OnInvalidData,
        report: &dyn ReportSink,
    ) -> Result<(), Error> {
        match branch.category {
            CategoryOfTheBranch::ProductName => {
                self.product = branch.name.to_string();
                self.set_version(branch.product.clone(), on_invalid, report)?;
            }
            CategoryOfTheBranch::Vendor => {
                self.vendor = Some(branch.name.to_string());
            }
            CategoryOfTheBranch::ProductVersion => {
                match branch.product.clone() {
                    Some(full_name) => match full_name.product_identification_helper {
                        Some(id_helper) => {
                            // Only treat the branch as a package when it carries no purl at
                            // all. An invalid one is left to the policy.
                            let purl = match id_helper.purl.as_deref() {
                                Some(purl) => on_invalid.validate(value::purl(purl), report)?,
                                None => None,
                            };
                            match purl {
                                Some(purl) => self.purls.push(purl.into()),
                                None => self.packages.push(branch.name.to_string()),
                            }
                        }
                        None => self.packages.push(full_name.product_id.to_string()),
                    },
                    None => self.packages.push(branch.name.to_string()),
                };
            }
            CategoryOfTheBranch::ProductVersionRange => {
                let version_infos =
                    parse_vers(&branch.name).map_err(|err| Error::Generic(err.into()))?;
                self.vers_specs.extend(version_infos);
                if let Some(purl) = branch_purl(branch, on_invalid, report)? {
                    self.purls.push(Purl::from(purl));
                }
            }
            _ => {
                if let Some(purl) = branch_purl(branch, on_invalid, report)? {
                    self.purls.push(Purl::from(purl));
                }
            }
        }
        Ok(())
    }

    /// Parse cpe or purl from product identifier helper
    pub fn set_version(
        &mut self,
        full_name: Option<FullProductNameT>,
        on_invalid: OnInvalidData,
        report: &dyn ReportSink,
    ) -> Result<(), Error> {
        let Some(helper) = full_name.and_then(|full_name| full_name.product_identification_helper)
        else {
            self.version = None;
            return Ok(());
        };

        // We prefer the CPE, which carries a version we can widen into a product stream.
        let cpe = match helper.cpe.as_deref() {
            Some(cpe) => on_invalid.validate(value::cpe(cpe), report)?,
            None => None,
        };

        if let Some(cpe) = cpe {
            self.cpe = Some(cpe.clone().into());
            self.version = Some(version_from_cpe(&cpe));
            return Ok(());
        }

        // Otherwise fall back to the purl, which gives us an exact version.
        let purl = match helper.purl.as_deref() {
            Some(purl) => on_invalid.validate(value::purl(purl), report)?,
            None => None,
        };

        self.version = purl.and_then(|purl| {
            purl.version().map(|version| VersionInfo {
                spec: VersionSpec::Exact(version.to_string()),
                scheme: VersionScheme::Semver,
            })
        });

        Ok(())
    }
}

/// Derive the version information from a CPE.
fn version_from_cpe(cpe: &cpe::uri::OwnedUri) -> VersionInfo {
    let version = cpe.version().to_string();

    if version == "*" {
        // Treat * value as unbounded version
        return VersionInfo {
            spec: VersionSpec::Range(Version::Unbounded, Version::Unbounded),
            scheme: VersionScheme::Semver,
        };
    }

    // Lenient semver parsing so we can get "product streams", e.g.
    // 2 is > 2.0.0
    // 2.13 is > 2.13.0
    match lenient_semver::parse(version.as_str()).map_err(|e| e.owned()) {
        Ok(semver) => {
            let mut upper = semver.clone();
            upper.major += 1;
            upper.minor = 0;
            upper.patch = 0;
            VersionInfo {
                spec: VersionSpec::Range(
                    Version::Inclusive(semver.to_string()),
                    Version::Exclusive(upper.to_string()),
                ),
                scheme: VersionScheme::Rpm,
            }
        }
        Err(_) => VersionInfo {
            spec: VersionSpec::Exact(version),
            scheme: VersionScheme::Generic,
        },
    }
}
