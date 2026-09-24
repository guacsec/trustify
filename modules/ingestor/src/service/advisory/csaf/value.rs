//! Parsing of CSAF scalar values, and the policy applied when one is invalid.
//!
//! CSAF carries purls, CPEs, timestamps and URLs as plain strings, so trustify parses them
//! itself. [`OnInvalidData`] decides what happens when such a value cannot be parsed.

use crate::service::Error;
use anyhow::anyhow;
use cpe::{error::CpeError, uri::OwnedUri};
use packageurl::PackageUrl;
use sbom_walker::report::ReportSink;
use std::{fmt::Display, str::FromStr};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::{ParseError, Url};

/// What to do when a CSAF document carries a value trustify cannot parse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OnInvalidData {
    /// Reject the document.
    #[default]
    Reject,
    /// Record a warning and skip the value.
    Warn,
}

impl OnInvalidData {
    /// Apply this policy to an attempted conversion.
    ///
    /// This is the single decision point: every invalid value in a CSAF document passes
    /// through here, and is either fatal or reported and skipped.
    ///
    /// Returns the parsed value, or `None` when the value was invalid and the policy is
    /// [`OnInvalidData::Warn`]. Returns [`Error::InvalidContent`] when the value was
    /// invalid and the policy is [`OnInvalidData::Reject`].
    pub fn validate<T, E>(
        self,
        operation: Operation<'_, T, E>,
        report: &dyn ReportSink,
    ) -> Result<Option<T>, Error>
    where
        E: Display,
    {
        let Operation {
            kind,
            value,
            result,
        } = operation;

        let err = match result {
            Ok(value) => return Ok(Some(value)),
            Err(err) => err,
        };

        let msg = format!("invalid {kind} '{value}': {err}");

        match self {
            Self::Reject => Err(Error::InvalidContent(anyhow!(msg))),
            Self::Warn => {
                tracing::warn!("{msg}");
                report.error(msg);
                Ok(None)
            }
        }
    }
}

/// An attempted conversion of a CSAF value, retaining the input for diagnostics.
pub struct Operation<'a, T, E> {
    /// What kind of value this is, used in the error message.
    kind: &'static str,
    /// The value as it appears in the document.
    value: &'a str,
    /// The outcome of parsing it.
    result: Result<T, E>,
}

/// Parse a purl held in a CSAF document.
pub fn purl(value: &str) -> Operation<'_, PackageUrl<'static>, packageurl::Error> {
    Operation {
        kind: "purl",
        value,
        result: PackageUrl::from_str(value),
    }
}

/// Parse a CPE held in a CSAF document.
pub fn cpe(value: &str) -> Operation<'_, OwnedUri, CpeError> {
    Operation {
        kind: "cpe",
        value,
        result: cpe::uri::Uri::parse(value).map(|cpe| cpe.to_owned()),
    }
}

/// Parse a timestamp held in a CSAF document.
pub fn date(value: &str) -> Operation<'_, OffsetDateTime, time::error::Parse> {
    Operation {
        kind: "date",
        value,
        result: OffsetDateTime::parse(value, &Rfc3339),
    }
}

/// Parse a URL held in a CSAF document.
pub fn url(value: &str) -> Operation<'_, Url, ParseError> {
    Operation {
        kind: "url",
        value,
        result: Url::parse(value),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::Warnings;
    use rstest::rstest;

    /// Runs one of the [`Operation`] constructors, reporting only whether a value was
    /// produced. This erases the operation's result type so the cases can be tabulated.
    type Check = fn(OnInvalidData, &str, &dyn ReportSink) -> Result<bool, Error>;

    fn check_purl(
        mode: OnInvalidData,
        value: &str,
        report: &dyn ReportSink,
    ) -> Result<bool, Error> {
        Ok(mode.validate(purl(value), report)?.is_some())
    }

    fn check_cpe(mode: OnInvalidData, value: &str, report: &dyn ReportSink) -> Result<bool, Error> {
        Ok(mode.validate(cpe(value), report)?.is_some())
    }

    fn check_date(
        mode: OnInvalidData,
        value: &str,
        report: &dyn ReportSink,
    ) -> Result<bool, Error> {
        Ok(mode.validate(date(value), report)?.is_some())
    }

    fn check_url(mode: OnInvalidData, value: &str, report: &dyn ReportSink) -> Result<bool, Error> {
        Ok(mode.validate(url(value), report)?.is_some())
    }

    /// For every kind of value: a valid one passes under either policy, an invalid one is
    /// fatal under [`OnInvalidData::Reject`], and is reported and skipped under
    /// [`OnInvalidData::Warn`].
    ///
    /// Nothing selects `Warn` in production yet, so this is the only thing keeping that
    /// arm working.
    #[rstest]
    #[case::purl(check_purl as Check, "pkg:cargo/hyper@0.14.10", "not-a-purl", "invalid purl")]
    #[case::cpe(check_cpe as Check, "cpe:/a:redhat:openshift:4", "not-a-cpe", "invalid cpe")]
    #[case::date(check_date as Check, "2023-04-18T00:00:00Z", "not-a-date", "invalid date")]
    #[case::url(check_url as Check, "https://www.redhat.com", "not a url", "invalid url")]
    fn policy(
        #[case] check: Check,
        #[case] valid: &str,
        #[case] invalid: &str,
        #[case] expected: &str,
    ) {
        // a valid value is returned, whichever policy is in effect, and reports nothing
        for mode in [OnInvalidData::Reject, OnInvalidData::Warn] {
            let warnings = Warnings::new();
            assert!(check(mode, valid, &warnings).expect("a valid value must pass"));
            assert!(Vec::<String>::from(warnings).is_empty());
        }

        // rejecting turns an invalid value into `InvalidContent`, and reports nothing
        let warnings = Warnings::new();
        let err = check(OnInvalidData::Reject, invalid, &warnings)
            .expect_err("an invalid value must be rejected");
        assert!(
            matches!(&err, Error::InvalidContent(_)),
            "expected InvalidContent, got {err:?}"
        );
        assert!(err.to_string().contains(expected), "got {err}");
        assert!(Vec::<String>::from(warnings).is_empty());

        // warning skips the value and records exactly one warning naming it
        let warnings = Warnings::new();
        assert!(
            !check(OnInvalidData::Warn, invalid, &warnings).expect("warning must not fail"),
            "an invalid value must be skipped"
        );
        let warnings = Vec::<String>::from(warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with(expected), "got {warnings:?}");
    }
}
