use super::util::{branch_purl, parse_cpe, parse_purl};
use crate::graph::advisory::{
    vers::parse_vers,
    version::{Version, VersionInfo, VersionSpec},
};
use cpe::cpe::Cpe;
use csaf::schema::csaf2_0::schema::{Branch, CategoryOfTheBranch, FullProductNameT};
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
    pub fn update_from_branch(&mut self, branch: &Branch) -> Result<(), anyhow::Error> {
        match branch.category {
            CategoryOfTheBranch::ProductName => {
                self.product = branch.name.to_string();
                self.set_version(branch.product.clone());
            }
            CategoryOfTheBranch::Vendor => {
                self.vendor = Some(branch.name.to_string());
            }
            CategoryOfTheBranch::ProductVersion => {
                match branch.product.clone() {
                    Some(full_name) => match full_name.product_identification_helper {
                        Some(id_helper) => {
                            match id_helper.purl.as_deref().and_then(|purl| parse_purl(purl)) {
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
                let version_infos = parse_vers(&branch.name)?;
                self.vers_specs.extend(version_infos);
                if let Some(purl) = branch_purl(branch) {
                    self.purls.push(Purl::from(purl));
                }
            }
            _ => {
                if let Some(purl) = branch_purl(branch) {
                    self.purls.push(Purl::from(purl));
                }
            }
        }
        Ok(())
    }

    /// Parse cpe or purl from product identifier helper
    pub fn set_version(&mut self, full_name: Option<FullProductNameT>) {
        self.version = full_name.and_then(|full_name| {
            full_name.product_identification_helper.and_then(|id| {
                id.cpe
                    .as_deref()
                    .and_then(|cpe| parse_cpe(cpe))
                    .map(|cpe| {
                        // We have a CPE in product identifier helper
                        self.cpe = Some(cpe.clone().into());
                        let version = cpe.version().to_string();
                        if version != "*" {
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
                        }
                    })
                    .or_else(|| {
                        id.purl
                            .as_deref()
                            .and_then(|purl| parse_purl(purl))
                            .and_then(|purl| {
                                // If we have purl, use an exact version
                                purl.version().map(|version| VersionInfo {
                                    spec: VersionSpec::Exact(version.to_string()),
                                    scheme: VersionScheme::Semver,
                                })
                            })
                    })
            })
        });
    }
}
