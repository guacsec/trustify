use osv::schema::Ecosystem;
use serde::{
    Deserialize,
    de::value::{self, StrDeserializer},
};
use std::borrow::Cow;

/// Resolve the native ecosystem used for package naming and version ordering.
///
/// Lightwell's suffix is another OSV ecosystem, not a release or repository qualifier.
/// Keep the source ecosystem intact and reuse OSV's parser for the complete suffix,
/// including any Maven repository URL. Missing, unknown or nested Lightwell suffixes
/// have no native interpretation.
pub(super) fn native_ecosystem(ecosystem: &Ecosystem) -> Option<Cow<'_, Ecosystem>> {
    let suffix = match ecosystem {
        Ecosystem::RedHatLightwell(Some(suffix)) => suffix,
        Ecosystem::RedHatLightwell(None) => return None,
        _ => return Some(Cow::Borrowed(ecosystem)),
    };

    let native = Ecosystem::deserialize(StrDeserializer::<value::Error>::new(suffix)).ok()?;
    match native {
        Ecosystem::RedHatLightwell(_) => None,
        _ => Some(Cow::Owned(native)),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("Maven", Some("Maven"))]
    #[case("PyPI", Some("PyPI"))]
    #[case(
        "Maven:https://maven.google.com",
        Some("Maven:https://maven.google.com")
    )]
    #[case(
        "Red Hat:rhel_aus:8.4::appstream",
        Some("Red Hat:rhel_aus:8.4::appstream")
    )]
    #[case("Red Hat Lightwell:Maven", Some("Maven"))]
    #[case("Red Hat Lightwell:PyPI", Some("PyPI"))]
    #[case("Red Hat Lightwell:npm", Some("npm"))]
    #[case(
        "Red Hat Lightwell:Maven:https://maven.google.com",
        Some("Maven:https://maven.google.com")
    )]
    #[case("Red Hat Lightwell", None)]
    #[case("Red Hat Lightwell:", None)]
    #[case("Red Hat Lightwell:unknown", None)]
    #[case("Red Hat Lightwell:Red Hat Lightwell:Maven", None)]
    fn resolve_native_ecosystem(
        #[case] source: &str,
        #[case] expected: Option<&str>,
    ) -> anyhow::Result<()> {
        let ecosystem: Ecosystem = serde_json::from_value(source.into())?;
        let original = serde_json::to_value(&ecosystem)?;
        let native = native_ecosystem(&ecosystem);
        let expected = expected
            .map(|value| serde_json::from_value::<Ecosystem>(value.into()))
            .transpose()?;

        assert_eq!(native.as_deref(), expected.as_ref());
        assert_eq!(serde_json::to_value(&ecosystem)?, original);
        if !matches!(ecosystem, Ecosystem::RedHatLightwell(_)) {
            assert!(matches!(native, Some(Cow::Borrowed(_))));
        }
        Ok(())
    }
}
