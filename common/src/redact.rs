use std::fmt;

pub struct HideString<'a, T: fmt::Debug>(pub &'a T, pub &'a str);

impl<T: fmt::Debug> fmt::Debug for HideString<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.1.is_empty() {
            return self.0.fmt(f);
        }
        let debug_output = format!("{:?}", self.0);
        write!(f, "{}", debug_output.replace(self.1, "***"))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[derive(Debug)]
    struct Config {
        #[allow(dead_code)]
        url: reqwest::Url,
        #[allow(dead_code)]
        password: String,
    }

    #[rstest]
    #[case::string_url(
        "postgres://user:secret@host/db",
        "secret",
        r#""postgres://user:***@host/db""#
    )]
    #[case::no_match("no sensitive data here", "secret", r#""no sensitive data here""#)]
    #[case::empty_hide_string("hello", "", r#""hello""#)]
    fn redacts_from_string(#[case] value: &str, #[case] hide: &str, #[case] expected: &str) {
        assert_eq!(format!("{:?}", HideString(&value, hide)), expected);
    }

    #[test]
    fn redacts_password_from_parsed_url() {
        let config = Config {
            url: reqwest::Url::parse("postgres://user:secret@host/db").unwrap(),
            password: "secret".into(),
        };
        let output = format!("{:?}", HideString(&config, &config.password));
        assert_eq!(
            output,
            r#"Config { url: Url { scheme: "postgres", cannot_be_a_base: false, username: "user", password: Some("***"), host: Some(Domain("host")), port: None, path: "/db", query: None, fragment: None }, password: "***" }"#
        );
    }
}
