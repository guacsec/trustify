//! Scoping of RPM matches by the stream of the release (e.g. `el8_6` of `1.1.1k-9.el8_6`).
//!
//! SUSE doesn't use a dist tag, but encodes the codestream at the start of the release instead
//! (e.g. `150600` of `3.1.4-150600.5.39.1`), see [`suse_codestream`].

use super::{CONFIDENCE, PLAIN, STREAM};
use trustify_common::rpm::stream_major;

/// How the RPM stream of an SBOM version relates to the stream of a matched range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMatch {
    /// Both streams are equal (e.g. `el8_6` and `el8_6`).
    Exact,
    /// Both share the major, and one of them is just the major (e.g. `el8` and `el8_6`).
    Major,
    /// At least one side has no stream, so it can't be scoped.
    Unscoped,
}

impl StreamMatch {
    /// Confidence of a match, depending on how the streams relate.
    pub fn confidence(self) -> f64 {
        match self {
            Self::Exact | Self::Unscoped => CONFIDENCE,
            Self::Major => 0.8,
        }
    }

    /// Type of the evidence of a stated range: only scoped matches are stream evidence.
    pub fn extractor(self) -> &'static str {
        match self {
            Self::Exact | Self::Major => STREAM,
            Self::Unscoped => PLAIN,
        }
    }
}

/// Compare the streams of an SBOM version and a range, `None` if they belong to different streams.
pub fn stream_match(sbom: Option<&str>, range: Option<&str>) -> Option<StreamMatch> {
    let (Some(sbom), Some(range)) = (sbom, range) else {
        return Some(StreamMatch::Unscoped);
    };

    if sbom == range {
        return Some(StreamMatch::Exact);
    }

    let (sbom_major, range_major) = (stream_major(sbom), stream_major(range));
    if sbom_major == range_major && (sbom == sbom_major || range == range_major) {
        Some(StreamMatch::Major)
    } else {
        None
    }
}

/// SUSE codestream of an RPM release, `None` if it has none.
///
/// It is either the leading build number, of at least six digits, which encodes the product
/// version (e.g. `150600` of `150600.5.39.1` for SLE 15 SP6, or `160000` for SLE 16.0), or the
/// SUSE Linux Framework One release (e.g. `slfo.1.1` of `slfo.1.1_7.1`). Releases of e.g.
/// Tumbleweed (`13.1`) carry none.
pub fn suse_codestream(release: &str) -> Option<&str> {
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

/// Compare the SUSE codestreams of an SBOM version and a range, `None` if they differ.
///
/// Unlike [`stream_match`], there is no relation between codestreams, and a codestream on only
/// one side is a mismatch too: SUSE advisories list the fixes of many codestreams side by side,
/// and a release without one (e.g. Tumbleweed's `13.1`) isn't comparable to one with
/// (`150600.5.7.1` is "newer" than `13.1`).
pub fn suse_stream_match(sbom: Option<&str>, range: Option<&str>) -> Option<StreamMatch> {
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

    #[rstest]
    #[case(Some("el8_6"), Some("el8_6"), Some(StreamMatch::Exact))]
    #[case(Some("fc39"), Some("fc39"), Some(StreamMatch::Exact))]
    #[case(Some("el8"), Some("el8_6"), Some(StreamMatch::Major))]
    #[case(Some("el8_6"), Some("el8"), Some(StreamMatch::Major))]
    #[case(Some("el8_6"), Some("el8_7"), None)]
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
        assert_eq!(suse_stream_match(sbom, range), expected);
    }
}
