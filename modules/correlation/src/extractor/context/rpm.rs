//! The product of an RPM, from its own PURL.
//!
//! An RPM names the product it was built for: the SBOM producer may state it as the `distro=`
//! qualifier (`rhel-8.10`, `sles-15.6`), and its release carries it (Red Hat `el8` of
//! `1.1.1k-9.el8_7`, the SUSE codestream `150600` of `3.1.4-150600.5.39.1`). Mapping that to the
//! product CPE vendors use in their advisories is vendor specific, so it is done per PURL
//! namespace:
//!
//! * Red Hat: `cpe:/*:redhat:enterprise_linux:<major>`. The part is ANY, as Red Hat states RHEL
//!   products as both `o` (BaseOS) and `a` (AppStream).
//! * SUSE: `cpe:/o:suse:*:<major>:sp<minor>`. The product is ANY, as one package ships in several
//!   products (SLES, SLED, modules) of a service pack. Only SLE 12 and 15 use that scheme. Note
//!   that a GA product's CPE has no service pack (`sles:15`), so it matches any service pack of
//!   its major version.

use crate::extractor::purl::stream::suse_codestream;
use trustify_common::{purl::Purl, rpm::Evr};
use trustify_entity::{correlation_evidence_context::ContextSource, cpe};
use uuid::Uuid;

/// Namespace of the IDs of the derived (not stored) CPEs.
const NAMESPACE: Uuid = Uuid::from_bytes([
    0x6a, 0x0f, 0x2d, 0x91, 0x7e, 0x34, 0x4b, 0xc8, 0x85, 0x1a, 0xd3, 0x60, 0x4f, 0x92, 0xe7, 0x1c,
]);

/// The product of an RPM, from its `distro=` qualifier, or else its release.
pub fn rpm_context(purl: &Purl) -> Option<(cpe::Model, ContextSource)> {
    if purl.ty != "rpm" {
        return None;
    }
    let vendor = Vendor::of(purl.namespace.as_deref()?)?;

    if let Some(product) = purl
        .qualifiers
        .get("distro")
        .and_then(|distro| vendor.product_of_distro(distro))
    {
        return Some((product.cpe(vendor), ContextSource::PurlQualifier));
    }

    let release = Evr::parse(purl.version.as_deref()?).release?;
    let product = vendor.product_of_release(release)?;
    Some((product.cpe(vendor), ContextSource::PurlRelease))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Vendor {
    RedHat,
    Suse,
}

/// A product version: the major version, and the minor version (SUSE service pack).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Product {
    major: u32,
    minor: Option<u32>,
}

impl Vendor {
    fn of(namespace: &str) -> Option<Self> {
        match namespace {
            "redhat" => Some(Self::RedHat),
            "suse" => Some(Self::Suse),
            _ => None,
        }
    }

    /// `rhel-8.10`, `sles-15.6`.
    fn product_of_distro(self, distro: &str) -> Option<Product> {
        let prefix = match self {
            Self::RedHat => "rhel-",
            Self::Suse => "sles-",
        };
        let version = distro.strip_prefix(prefix)?;
        let (major, minor) = match version.split_once('.') {
            Some((major, minor)) => (major, Some(minor.parse().ok()?)),
            None => (version, None),
        };
        self.product(major.parse().ok()?, minor)
    }

    /// Red Hat `el8` (also in `module+el8.8.0+…`), SUSE codestream `150600`.
    fn product_of_release(self, release: &str) -> Option<Product> {
        match self {
            Self::RedHat => release
                .split(['.', '+', '_'])
                .find_map(|token| token.strip_prefix("el")?.parse().ok())
                .and_then(|major| self.product(major, None)),
            Self::Suse => {
                let codestream = suse_codestream(release)?;
                if codestream.len() != 6 || !codestream.ends_with("00") {
                    return None;
                }
                let major = codestream[..2].parse().ok()?;
                let minor = codestream[2..4].parse().ok()?;
                self.product(major, Some(minor))
            }
        }
    }

    /// A product, if the vendor's CPEs of that version are known.
    fn product(self, major: u32, minor: Option<u32>) -> Option<Product> {
        match self {
            Self::RedHat => Some(Product { major, minor: None }),
            // SLE 16 and later don't name service packs in their CPEs
            Self::Suse => matches!(major, 12 | 15).then_some(Product { major, minor }),
        }
    }
}

impl Product {
    fn cpe(self, vendor: Vendor) -> cpe::Model {
        let any = || Some("*".to_string());
        let (part, vendor_name, product, update) = match vendor {
            Vendor::RedHat => (any(), "redhat", Some("enterprise_linux".into()), any()),
            Vendor::Suse => (
                Some("o".into()),
                "suse",
                any(),
                match self.minor {
                    Some(minor) if minor > 0 => Some(format!("sp{minor}")),
                    _ => any(),
                },
            ),
        };
        let mut model = cpe::Model {
            id: Uuid::nil(),
            part,
            vendor: Some(vendor_name.into()),
            product,
            version: Some(self.major.to_string()),
            update,
            edition: any(),
            language: any(),
            sw_edition: any(),
            target_sw: any(),
            target_hw: any(),
            other: any(),
        };
        model.id = Uuid::new_v5(&NAMESPACE, super::format_cpe(&model).as_bytes());
        model
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest]
    #[case::rh_qualifier(
        "pkg:rpm/redhat/openssl@1.1.1k-9.el8_7?distro=rhel-8.10",
        Some(("cpe:2.3:*:redhat:enterprise_linux:8:*:*:*:*:*:*:*", ContextSource::PurlQualifier))
    )]
    #[case::rh_release(
        "pkg:rpm/redhat/openssl@1.1.1k-9.el8_7",
        Some(("cpe:2.3:*:redhat:enterprise_linux:8:*:*:*:*:*:*:*", ContextSource::PurlRelease))
    )]
    #[case::rh_module(
        "pkg:rpm/redhat/golang@1.19.13-1.module%2Bel8.8.0%2B20373%2Bd9cd605c",
        Some(("cpe:2.3:*:redhat:enterprise_linux:8:*:*:*:*:*:*:*", ContextSource::PurlRelease))
    )]
    // the qualifier wins over the release
    #[case::rh_qualifier_first(
        "pkg:rpm/redhat/openssl@1.1.1k-9.el8_7?distro=rhel-9.4",
        Some(("cpe:2.3:*:redhat:enterprise_linux:9:*:*:*:*:*:*:*", ContextSource::PurlQualifier))
    )]
    #[case::suse_qualifier(
        "pkg:rpm/suse/libopenssl3@3.1.4-150600.5.39.1?distro=sles-15.6",
        Some(("cpe:2.3:o:suse:*:15:sp6:*:*:*:*:*:*", ContextSource::PurlQualifier))
    )]
    #[case::suse_release(
        "pkg:rpm/suse/libopenssl3@3.1.4-150600.5.39.1",
        Some(("cpe:2.3:o:suse:*:15:sp6:*:*:*:*:*:*", ContextSource::PurlRelease))
    )]
    #[case::suse_ga(
        "pkg:rpm/suse/openssl@1.1.0-150000.3.23.1",
        Some(("cpe:2.3:o:suse:*:15:*:*:*:*:*:*:*", ContextSource::PurlRelease))
    )]
    #[case::suse_12(
        "pkg:rpm/suse/openssl@1.0.2p-120200.3.1",
        Some(("cpe:2.3:o:suse:*:12:sp2:*:*:*:*:*:*", ContextSource::PurlRelease))
    )]
    #[case::suse_16("pkg:rpm/suse/openssl@3.5.0-160000.3.2", None)]
    #[case::suse_micro("pkg:rpm/suse/openssl@3.1.4-slfo.1.1_3.10", None)]
    #[case::tumbleweed("pkg:rpm/suse/openssl@3.1.4-13.1", None)]
    #[case::fedora("pkg:rpm/fedora/openssl@3.1.1-4.fc39?distro=fedora-39", None)]
    #[case::not_rpm("pkg:maven/io.netty/netty-codec@4.1.45.Final-redhat-00001", None)]
    fn context(#[case] purl: &str, #[case] expected: Option<(&str, ContextSource)>) {
        let purl = Purl::from_str(purl).expect("valid PURL");
        assert_eq!(
            rpm_context(&purl).map(|(cpe, source)| (super::super::format_cpe(&cpe), source)),
            expected.map(|(cpe, source)| (cpe.to_string(), source))
        );
    }
}
