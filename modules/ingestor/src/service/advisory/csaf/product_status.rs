use std::str::FromStr;

use super::util::branch_purl;
use crate::graph::advisory::{
    vers::parse_vers,
    version::{Version, VersionInfo, VersionSpec},
};
use csaf_rs::schema::csaf2_0::schema::{
    Branch, CategoryOfTheBranch as BranchCategory, FullProductNameT as FullProductName,
};
use packageurl::PackageUrl;
use trustify_common::{cpe::Cpe, purl::Purl};
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
    pub fn update_from_branch(&mut self, branch: &Branch) -> Result<(), anyhow::Error> {
        match branch.category {
            BranchCategory::ProductName => {
                self.product = branch.name.to_string();
                self.set_version(branch.product.clone())?;
            }
            BranchCategory::Vendor => {
                self.vendor = Some(branch.name.to_string());
            }
            BranchCategory::ProductVersion => {
                match branch.product.clone() {
                    Some(full_name) => match full_name.product_identification_helper {
                        Some(id_helper) => match id_helper.purl {
                            Some(purl) => self.purls.push(Purl::from_str(purl.as_str())?),
                            None => self.packages.push(branch.name.to_string()),
                        },
                        None => self.packages.push(full_name.product_id.to_string()),
                    },
                    None => self.packages.push(branch.name.to_string()),
                };
            }
            BranchCategory::ProductVersionRange => {
                let version_infos = parse_vers(&branch.name)?;
                self.vers_specs.extend(version_infos);
                if let Some(purl) = branch_purl(branch)? {
                    self.purls.push(Purl::from(purl.clone()));
                }
            }
            _ => {
                if let Some(purl) = branch_purl(branch)? {
                    let purl = Purl::from(purl.clone());
                    self.purls.push(purl);
                }
            }
        }
        Ok(())
    }

    /// Parse cpe or purl from product identifier helper
    pub fn set_version(&mut self, full_name: Option<FullProductName>) -> anyhow::Result<()> {
        let version = 'version: {
            let Some(id) = full_name.and_then(|full_name| full_name.product_identification_helper)
            else {
                break 'version None;
            };
            if let Some(cpe) = id.cpe {
                let cpe = Cpe::from_str(cpe.as_str())?;
                // We have a CPE in product identifier helper
                self.cpe = Some(cpe.clone());
                let version = cpe.version().to_string();
                let version_info = if version != "*" {
                    // Lenient semver parsing so we can get "product streams", e.g.
                    // 2 is > 2.0.0
                    // 2.13 is > 2.13.0
                    match lenient_semver::parse(version.as_str()).map_err(|e| e.owned()) {
                        Ok(semver) => {
                            // let upper = semver.clone().set_major(semver.major + 1).build();
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
                } else {
                    // Treat * value as unbounded version
                    VersionInfo {
                        spec: VersionSpec::Range(Version::Unbounded, Version::Unbounded),
                        scheme: VersionScheme::Semver,
                    }
                };

                Some(version_info)
            } else {
                let Some(purl) = id.purl else {
                    break 'version None;
                };
                let purl = PackageUrl::from_str(purl.as_str())?;

                // If we have purl, use an exact version
                purl.version().map(|version| VersionInfo {
                    spec: VersionSpec::Exact(version.to_string()),
                    scheme: VersionScheme::Semver,
                })
            }
        };
        self.version = version;
        Ok(())
    }
}
