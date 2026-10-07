//! Scoping of RPM matches by the stream of the release (e.g. `el8_6` of `1.1.1k-9.el8_6`).

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
}
