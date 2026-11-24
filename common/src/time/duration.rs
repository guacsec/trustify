use jiff::fmt::friendly::{Designator, SpanParser, SpanPrinter};
use std::{fmt, ops::Deref, str::FromStr, time::Duration};

/// A nonnegative duration with human-readable CLI input and display.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HumanDuration(Duration);

impl FromStr for HumanDuration {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "0" {
            return Ok(Self(Duration::ZERO));
        }
        // Legacy configuration uses uppercase M for a fixed-length month.
        let value = value.replace('M', "month");
        let span = SpanParser::new()
            .parse_span(&value)
            .map_err(|e| e.to_string())?;
        if span.is_negative() {
            return Err("duration must not be negative".into());
        }
        // Preserve the fixed units used by existing configuration values:
        // a day is 24 hours, a year 365.25 days, and a month 30.44 days.
        let seconds = i128::from(span.get_years()) * 31_557_600
            + i128::from(span.get_months()) * 2_630_016
            + i128::from(span.get_weeks()) * 604_800
            + i128::from(span.get_days()) * 86_400
            + i128::from(span.get_hours()) * 3_600
            + i128::from(span.get_minutes()) * 60
            + i128::from(span.get_seconds());
        let nanos = seconds * 1_000_000_000
            + i128::from(span.get_milliseconds()) * 1_000_000
            + i128::from(span.get_microseconds()) * 1_000
            + i128::from(span.get_nanoseconds());
        let seconds = u64::try_from(nanos / 1_000_000_000)
            .map_err(|_| "duration is out of range".to_string())?;
        Ok(Self(Duration::new(seconds, (nanos % 1_000_000_000) as u32)))
    }
}

impl From<Duration> for HumanDuration {
    fn from(value: Duration) -> Self {
        Self(value)
    }
}

impl From<HumanDuration> for Duration {
    fn from(value: HumanDuration) -> Self {
        value.0
    }
}

impl Deref for HumanDuration {
    type Target = Duration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_duration(self.0))
    }
}

pub fn format_duration(value: Duration) -> String {
    SpanPrinter::new()
        .designator(Designator::HumanTime)
        .unsigned_duration_to_string(&value)
}

/// String serialization for importer periods, preserving the existing API shape.
pub mod duration_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format_duration(*value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        String::deserialize(deserializer)?
            .parse::<HumanDuration>()
            .map(Into::into)
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_existing_configuration_units() {
        for (input, expected) in [
            ("0", Duration::ZERO),
            ("0s", Duration::ZERO),
            ("1h 30m", Duration::from_secs(5_400)),
            ("7d", Duration::from_secs(604_800)),
            ("1week", Duration::from_secs(604_800)),
            ("1month", Duration::from_secs(2_630_016)),
            ("1M", Duration::from_secs(2_630_016)),
            ("1year", Duration::from_secs(31_557_600)),
            ("123ms 456us 789ns", Duration::from_nanos(123_456_789)),
        ] {
            assert_eq!(
                *input.parse::<HumanDuration>().unwrap(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_invalid_or_negative_durations() {
        for input in ["", "-1s", "forever", "18446744073709551616s"] {
            assert!(input.parse::<HumanDuration>().is_err(), "{input}");
        }
    }

    #[test]
    fn importer_period_round_trips_without_losing_precision() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Period(#[serde(with = "duration_serde")] Duration);

        let value = Period(Duration::new(604_800, 123_456_789));
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(encoded.starts_with('"'));
        let decoded: Period = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.0, value.0);
    }
}
