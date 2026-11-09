use osv::schema::Ecosystem;

/// Borrow the native ecosystem used for package naming and version ordering.
///
/// OSV validates and parses Lightwell's required native suffix, including any Maven
/// repository URL. Keep the source ecosystem intact; no second parser is needed.
pub(super) fn native_ecosystem(ecosystem: &Ecosystem) -> &Ecosystem {
    match ecosystem {
        Ecosystem::RedHatLightwell(native) => native,
        _ => ecosystem,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    use std::ptr;

    #[rstest]
    #[case("Maven", "Maven")]
    #[case("PyPI", "PyPI")]
    #[case("Maven:https://maven.google.com", "Maven:https://maven.google.com")]
    #[case("Red Hat:rhel_aus:8.4::appstream", "Red Hat:rhel_aus:8.4::appstream")]
    #[case("Red Hat Lightwell:Maven", "Maven")]
    #[case("Red Hat Lightwell:PyPI", "PyPI")]
    #[case("Red Hat Lightwell:npm", "npm")]
    #[case(
        "Red Hat Lightwell:Maven:https://maven.google.com",
        "Maven:https://maven.google.com"
    )]
    fn resolve_native_ecosystem(
        #[case] source: &str,
        #[case] expected: &str,
    ) -> anyhow::Result<()> {
        let ecosystem: Ecosystem = serde_json::from_value(source.into())?;
        let original = serde_json::to_value(&ecosystem)?;
        let expected: Ecosystem = serde_json::from_value(expected.into())?;
        let native = native_ecosystem(&ecosystem);

        assert_eq!(native, &expected);
        assert_eq!(serde_json::to_value(&ecosystem)?, original);
        let borrowed = match &ecosystem {
            Ecosystem::RedHatLightwell(inner) => inner.as_ref(),
            _ => &ecosystem,
        };
        assert!(ptr::eq(native, borrowed));
        Ok(())
    }

    #[rstest]
    #[case("Red Hat Lightwell")]
    #[case("Red Hat Lightwell:")]
    #[case("Red Hat Lightwell:unknown")]
    #[case("Red Hat Lightwell:Red Hat Lightwell:Maven")]
    fn invalid_lightwell_ecosystems_are_rejected(#[case] source: &str) -> anyhow::Result<()> {
        assert!(serde_json::from_value::<Ecosystem>(source.into()).is_err());
        let yaml = serde_saphyr::to_string(&source)?;
        assert!(serde_saphyr::from_str::<Ecosystem>(&yaml).is_err());
        Ok(())
    }
}
