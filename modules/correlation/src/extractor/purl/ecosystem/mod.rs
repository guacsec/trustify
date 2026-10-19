//! Matching semantics specific to the PURL type (and namespace) of a package.
//!
//! An advisory PURL may carry qualifiers which scope it to only some of the packages of the same
//! name and version (e.g. an RPM's architecture). A version may also belong to a stream of
//! releases (e.g. the `el8_6` of an RPM), which scopes the ranges it matches. Their meaning depends
//! on the ecosystem, so does their comparison with the SBOM's package.

pub(crate) mod rpm;

use super::{CONFIDENCE, PLAIN, STREAM};
use crate::model::{ConfidenceFactor, ConfidenceReason, StreamRelation};
use std::collections::BTreeMap;

/// PURL namespace of SUSE packages, scoped by their codestream.
const SUSE: &str = "suse";

/// A family of packages with its own matching semantics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ecosystem {
    /// `pkg:rpm/…`, with a stream in the dist tag of the release (e.g. `el8_6`, `fc39`).
    Rpm,
    /// `pkg:rpm/suse/…`, with a codestream at the start of the release (e.g. `150600`).
    SuseRpm,
    /// Any other type, without qualifiers or streams scoping a match.
    Other,
}

impl Ecosystem {
    /// The ecosystem of a PURL type and namespace.
    pub fn of(ty: &str, namespace: Option<&str>) -> Self {
        match (ty, namespace) {
            ("rpm", Some(SUSE)) => Self::SuseRpm,
            ("rpm", _) => Self::Rpm,
            _ => Self::Other,
        }
    }

    /// If the qualifiers of an SBOM package are compatible with the ones stated by an advisory.
    ///
    /// Qualifiers without a defined meaning are ignored.
    pub fn qualifiers_match(
        self,
        sbom: &BTreeMap<String, String>,
        stated: &BTreeMap<String, String>,
    ) -> bool {
        match self {
            Self::Rpm | Self::SuseRpm => rpm::qualifiers_match(sbom, stated),
            Self::Other => true,
        }
    }

    /// Relation of the streams of the SBOM version and a matched range, `None` if they belong to
    /// different streams.
    ///
    /// The range's stream is taken from its upper bound, falling back to the lower one.
    pub fn stream_match(
        self,
        sbom_version: &str,
        range_low: Option<&str>,
        range_high: Option<&str>,
    ) -> Option<StreamMatch> {
        let range = range_high.or(range_low);
        match self {
            Self::Rpm => rpm::stream_match(sbom_version, range),
            Self::SuseRpm => rpm::suse_stream_match(sbom_version, range),
            Self::Other => Some(StreamMatch::Unscoped),
        }
    }
}

/// How the stream of an SBOM version relates to the stream of a matched range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMatch {
    /// Both streams are equal (e.g. `el8_6` and `el8_6`).
    Exact,
    /// Both share the major, and one of them is just the major (e.g. `el8` and `el8_6`).
    Major,
    /// Different minors of the same major (e.g. `el9_0` and `el9_1`). In the mainline of a
    /// product, the minors are one line (9.0 is followed by 9.1, which rebuilds its packages),
    /// while extended support (EUS, …) of a minor is a separate product. So such a match only
    /// applies to a node in the statement's product, and only if nothing is stated for the node's
    /// own stream.
    Minor,
    /// At least one side has no stream, so it can't be scoped.
    Unscoped,
}

impl StreamMatch {
    /// Confidence of a match, depending on how the streams relate.
    pub fn confidence(self) -> f64 {
        match self {
            Self::Exact | Self::Unscoped => CONFIDENCE,
            Self::Major | Self::Minor => 0.8,
        }
    }

    /// The confidence as a factor, with its reason.
    pub fn factor(self) -> ConfidenceFactor {
        let reason = match self {
            Self::Exact => ConfidenceReason::RpmStream {
                stream: StreamRelation::Exact,
            },
            Self::Major => ConfidenceReason::RpmStream {
                stream: StreamRelation::Major,
            },
            Self::Minor => ConfidenceReason::RpmStream {
                stream: StreamRelation::Minor,
            },
            Self::Unscoped => ConfidenceReason::Purl,
        };
        ConfidenceFactor::new(reason, self.confidence())
    }

    /// Type of the evidence of a stated range: only scoped matches are stream evidence.
    pub fn extractor(self) -> &'static str {
        match self {
            Self::Exact | Self::Major | Self::Minor => STREAM,
            Self::Unscoped => PLAIN,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::redhat("rpm", Some("redhat"), Ecosystem::Rpm)]
    #[case::no_namespace("rpm", None, Ecosystem::Rpm)]
    #[case::suse("rpm", Some("suse"), Ecosystem::SuseRpm)]
    #[case::deb("deb", Some("debian"), Ecosystem::Other)]
    #[case::npm("npm", None, Ecosystem::Other)]
    fn of(#[case] ty: &str, #[case] namespace: Option<&str>, #[case] expected: Ecosystem) {
        assert_eq!(Ecosystem::of(ty, namespace), expected);
    }

    #[test]
    fn other_ignores_qualifiers() {
        let qualifiers = |arch: &str| BTreeMap::from([("arch".to_string(), arch.to_string())]);
        assert!(Ecosystem::Other.qualifiers_match(&qualifiers("amd64"), &qualifiers("arm64")));
    }

    #[test]
    fn other_is_unscoped() {
        assert_eq!(
            Ecosystem::Other.stream_match("1.0-1.el8", None, Some("1.1-1.el9")),
            Some(StreamMatch::Unscoped)
        );
    }
}
