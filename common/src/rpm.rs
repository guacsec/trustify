//! RPM version handling.

/// An RPM version, split into epoch, version and release (`[epoch:]version[-release]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evr<'a> {
    pub epoch: Option<u32>,
    pub version: &'a str,
    pub release: Option<&'a str>,
}

impl<'a> Evr<'a> {
    /// Split an RPM version string.
    ///
    /// The epoch is a leading number followed by `:`, the release is the part after the last `-`.
    /// Any string is a version, so this never fails.
    pub fn parse(value: &'a str) -> Self {
        let (epoch, rest) = match value.split_once(':') {
            Some((epoch, rest)) => match epoch.parse() {
                Ok(epoch) => (Some(epoch), rest),
                Err(_) => (None, value),
            },
            None => (None, value),
        };

        let (version, release) = match rest.rsplit_once('-') {
            Some((version, release)) => (version, Some(release)),
            None => (rest, None),
        };

        Self {
            epoch,
            version,
            release,
        }
    }

    /// Stream of the release: the first `.` separated token of the release, which starts with
    /// letters directly followed by a digit (e.g. `el8_6` of `9.el8_6`, or `fc39` of `1.fc39`).
    pub fn stream(&self) -> Option<&'a str> {
        self.release?.split('.').find(|token| {
            let letters = token.bytes().take_while(u8::is_ascii_alphabetic).count();
            letters > 0
                && token
                    .as_bytes()
                    .get(letters)
                    .is_some_and(u8::is_ascii_digit)
        })
    }
}

/// The major part of a stream: its leading letters and digits (e.g. `el8` of `el8_6`).
pub fn stream_major(stream: &str) -> &str {
    let letters = stream.bytes().take_while(u8::is_ascii_alphabetic).count();
    let digits = stream[letters..]
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    &stream[..letters + digits]
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("1:1.1.1k-9.el8_6", Evr { epoch: Some(1), version: "1.1.1k", release: Some("9.el8_6") })]
    #[case("1.1.1k-9.el8_6", Evr { epoch: None, version: "1.1.1k", release: Some("9.el8_6") })]
    #[case("1.1.1k", Evr { epoch: None, version: "1.1.1k", release: None })]
    #[case("1.0-1.module+el8.4.0+123+abc", Evr { epoch: None, version: "1.0", release: Some("1.module+el8.4.0+123+abc") })]
    #[case("2.4-1.fc39.1", Evr { epoch: None, version: "2.4", release: Some("1.fc39.1") })]
    #[case("1.0-rc1-2.el9", Evr { epoch: None, version: "1.0-rc1", release: Some("2.el9") })]
    #[case("x:1.0-1", Evr { epoch: None, version: "x:1.0", release: Some("1") })]
    fn parse(#[case] value: &str, #[case] expected: Evr) {
        assert_eq!(Evr::parse(value), expected);
    }

    #[rstest]
    #[case("1:1.1.1k-9.el8_6", Some("el8_6"))]
    #[case("1.1.1k-7.el8", Some("el8"))]
    #[case("2.4-1.fc39", Some("fc39"))]
    #[case("2.4-1.fc39.1", Some("fc39"))]
    #[case("1.0-2.amzn2", Some("amzn2"))]
    #[case("1.0-1.module+el8.4.0+123+abc", None)]
    #[case("1.0-1", None)]
    #[case("1.0", None)]
    fn stream(#[case] value: &str, #[case] expected: Option<&str>) {
        assert_eq!(Evr::parse(value).stream(), expected);
    }

    #[rstest]
    #[case("el8_6", "el8")]
    #[case("el8", "el8")]
    #[case("fc39", "fc39")]
    #[case("amzn2", "amzn2")]
    fn major(#[case] stream: &str, #[case] expected: &str) {
        assert_eq!(stream_major(stream), expected);
    }
}
