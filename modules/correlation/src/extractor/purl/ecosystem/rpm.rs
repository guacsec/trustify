//! RPM: qualifiers, and scoping by the stream of the release (e.g. `el8_6` of `1.1.1k-9.el8_6`).
//!
//! SUSE doesn't use a dist tag, but encodes the codestream at the start of the release instead
//! (e.g. `150600` of `3.1.4-150600.5.39.1`), see [`suse_codestream`].

use super::StreamMatch;
use std::collections::BTreeMap;
use trustify_common::rpm::{Evr, stream_major};

/// Qualifier of a module stream (e.g. `firefox:flatpak`).
const MODULE: &str = "rpmmod";
/// Qualifier of the architecture (e.g. `x86_64`, or `src` for a source package).
const ARCH: &str = "arch";

/// A module named by the advisory must be present on the SBOM package. An omitted module is
/// unspecified.
///
/// A binary package only matches the advisory's packages of its own architecture, or of its
/// source package. An omitted architecture is unspecified, on either side.
pub fn qualifiers_match(
    sbom: &BTreeMap<String, String>,
    stated: &BTreeMap<String, String>,
) -> bool {
    let module = stated
        .get(MODULE)
        .is_none_or(|module| sbom.get(MODULE) == Some(module));
    let arch = match (sbom.get(ARCH), stated.get(ARCH)) {
        (Some(sbom), Some(stated)) if is_binary(sbom) && is_binary(stated) => sbom == stated,
        _ => true,
    };
    module && arch
}

/// If an architecture is one of a binary package, not of a source package.
fn is_binary(arch: &str) -> bool {
    !matches!(arch, "src" | "nosrc")
}

/// Compare the dist tag streams of an SBOM version and a range version.
pub fn stream_match(sbom: &str, range: Option<&str>) -> Option<StreamMatch> {
    streams_match(
        Evr::parse(sbom).stream(),
        range.map(Evr::parse).and_then(|range| range.stream()),
    )
}

/// Compare two streams, `None` if they belong to different streams.
fn streams_match(sbom: Option<&str>, range: Option<&str>) -> Option<StreamMatch> {
    let (Some(sbom), Some(range)) = (sbom, range) else {
        return Some(StreamMatch::Unscoped);
    };

    if sbom == range {
        return Some(StreamMatch::Exact);
    }

    let (sbom_major, range_major) = (stream_major(sbom), stream_major(range));
    if sbom_major != range_major {
        None
    } else if sbom == sbom_major || range == range_major {
        Some(StreamMatch::Major)
    } else {
        Some(StreamMatch::Minor)
    }
}

/// SUSE codestream of an RPM release, `None` if it has none.
///
/// It is either the leading build number, of at least six digits, which encodes the product
/// version (e.g. `150600` of `150600.5.39.1` for SLE 15 SP6, or `160000` for SLE 16.0), or the
/// SUSE Linux Framework One release (e.g. `slfo.1.1` of `slfo.1.1_7.1`). Releases of e.g.
/// Tumbleweed (`13.1`) carry none.
pub(crate) fn suse_codestream(release: &str) -> Option<&str> {
    if release.starts_with("slfo.") {
        return Some(
            release
                .split_once('_')
                .map_or(release, |(stream, _)| stream),
        );
    }

    let first = release.split('.').next()?;
    (first.len() >= 6 && first.bytes().all(|b| b.is_ascii_digit())).then_some(first)
}

/// Compare the SUSE codestreams of an SBOM version and a range version. A range without a version
/// is unscoped.
pub fn suse_stream_match(sbom: &str, range: Option<&str>) -> Option<StreamMatch> {
    let Some(range) = range else {
        return Some(StreamMatch::Unscoped);
    };
    codestreams_match(
        Evr::parse(sbom).release.and_then(suse_codestream),
        Evr::parse(range).release.and_then(suse_codestream),
    )
}

/// Compare two SUSE codestreams, `None` if they differ.
///
/// Unlike [`streams_match`], there is no relation between codestreams, and a codestream on only
/// one side is a mismatch too: SUSE advisories list the fixes of many codestreams side by side,
/// and a release without one (e.g. Tumbleweed's `13.1`) isn't comparable to one with
/// (`150600.5.7.1` is "newer" than `13.1`).
fn codestreams_match(sbom: Option<&str>, range: Option<&str>) -> Option<StreamMatch> {
    match (sbom, range) {
        (None, None) => Some(StreamMatch::Unscoped),
        (Some(sbom), Some(range)) if sbom == range => Some(StreamMatch::Exact),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    fn qualifiers(purl: &str) -> BTreeMap<String, String> {
        purl.split_once('?')
            .map(|(_, query)| {
                query
                    .split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[rstest]
    #[case::same_arch("?arch=x86_64", "?arch=x86_64", true)]
    #[case::other_arch("?arch=x86_64", "?arch=aarch64", false)]
    #[case::noarch("?arch=noarch", "?arch=x86_64", false)]
    #[case::source_package("?arch=x86_64", "?arch=src", true)]
    #[case::nosrc_package("?arch=x86_64", "?arch=nosrc", true)]
    #[case::sbom_source("?arch=src", "?arch=x86_64", true)]
    #[case::sbom_unspecified("", "?arch=x86_64", true)]
    #[case::stated_unspecified("?arch=x86_64", "", true)]
    #[case::same_module("?rpmmod=firefox:flatpak", "?rpmmod=firefox:flatpak", true)]
    #[case::other_module("?rpmmod=firefox:other", "?rpmmod=firefox:flatpak", false)]
    #[case::missing_module("", "?rpmmod=firefox:flatpak", false)]
    #[case::module_unspecified("?rpmmod=firefox:flatpak", "", true)]
    #[case::module_and_other_arch(
        "?arch=x86_64&rpmmod=firefox:flatpak",
        "?arch=aarch64&rpmmod=firefox:flatpak",
        false
    )]
    fn qualifiers_matching(#[case] sbom: &str, #[case] stated: &str, #[case] expected: bool) {
        assert_eq!(
            qualifiers_match(&qualifiers(sbom), &qualifiers(stated)),
            expected
        );
    }

    #[rstest]
    #[case(Some("el8_6"), Some("el8_6"), Some(StreamMatch::Exact))]
    #[case(Some("fc39"), Some("fc39"), Some(StreamMatch::Exact))]
    #[case(Some("el8"), Some("el8_6"), Some(StreamMatch::Major))]
    #[case(Some("el8_6"), Some("el8"), Some(StreamMatch::Major))]
    #[case(Some("el8_6"), Some("el8_7"), Some(StreamMatch::Minor))]
    #[case(Some("el10_2"), Some("el10_1"), Some(StreamMatch::Minor))]
    #[case(Some("el8"), Some("el9"), None)]
    #[case(Some("el8"), Some("fc8"), None)]
    #[case(Some("el8"), None, Some(StreamMatch::Unscoped))]
    #[case(None, Some("el8"), Some(StreamMatch::Unscoped))]
    #[case(None, None, Some(StreamMatch::Unscoped))]
    #[test_log::test]
    fn stream_matching(
        #[case] sbom: Option<&str>,
        #[case] range: Option<&str>,
        #[case] expected: Option<StreamMatch>,
    ) {
        assert_eq!(streams_match(sbom, range), expected);
    }

    #[rstest]
    #[case("1:1.1.1k-9.el8_6", Some("1:1.1.1k-9.el8_6"), Some(StreamMatch::Exact))]
    #[case("1:1.1.1k-7.el8", Some("1:1.1.1k-9.el8_6"), Some(StreamMatch::Major))]
    #[case("1:1.1.1k-7.el8", Some("3.0.7-1.el9"), None)]
    #[case("1:1.1.1k-7.el8", None, Some(StreamMatch::Unscoped))]
    #[test_log::test]
    fn version_stream_matching(
        #[case] sbom: &str,
        #[case] range: Option<&str>,
        #[case] expected: Option<StreamMatch>,
    ) {
        assert_eq!(stream_match(sbom, range), expected);
    }

    #[rstest]
    #[case("150600.5.39.1", Some("150600"))]
    #[case("150000.3.23.1", Some("150000"))]
    #[case("160000.4.1", Some("160000"))]
    #[case("slfo.1.1_7.1", Some("slfo.1.1"))]
    #[case("slfo.1.1", Some("slfo.1.1"))]
    #[case("13.1", None)]
    #[case("6.1", None)]
    #[case("1.22", None)]
    #[case("28.el9_4", None)]
    #[test_log::test]
    fn suse_codestreams(#[case] release: &str, #[case] expected: Option<&str>) {
        assert_eq!(suse_codestream(release), expected);
    }

    #[rstest]
    #[case(Some("150600"), Some("150600"), Some(StreamMatch::Exact))]
    #[case(Some("slfo.1.1"), Some("slfo.1.1"), Some(StreamMatch::Exact))]
    #[case(Some("150600"), Some("150700"), None)]
    #[case(Some("150600"), Some("160000"), None)]
    #[case(Some("150600"), None, None)]
    #[case(None, Some("150600"), None)]
    #[case(None, None, Some(StreamMatch::Unscoped))]
    #[test_log::test]
    fn suse_stream_matching(
        #[case] sbom: Option<&str>,
        #[case] range: Option<&str>,
        #[case] expected: Option<StreamMatch>,
    ) {
        assert_eq!(codestreams_match(sbom, range), expected);
    }

    #[rstest]
    #[case(
        "3.1.4-150600.5.39.1",
        Some("3.1.4-150600.5.40.1"),
        Some(StreamMatch::Exact)
    )]
    #[case("3.1.4-150600.5.39.1", Some("3.1.4-150700.5.40.1"), None)]
    #[case("3.1.4-150600.5.39.1", None, Some(StreamMatch::Unscoped))]
    #[test_log::test]
    fn suse_version_stream_matching(
        #[case] sbom: &str,
        #[case] range: Option<&str>,
        #[case] expected: Option<StreamMatch>,
    ) {
        assert_eq!(suse_stream_match(sbom, range), expected);
    }
}
