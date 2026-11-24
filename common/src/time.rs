use std::time::SystemTime;
use time::OffsetDateTime;

mod duration;
pub use duration::{HumanDuration, duration_serde, format_duration};

/// Convert timestamps from upstream models through their `SystemTime` interop.
pub trait TimestampExt {
    /// Turn into a [`time::OffsetDateTime`].
    fn into_time(self) -> OffsetDateTime;
}

impl<T: Into<SystemTime>> TimestampExt for T {
    fn into_time(self) -> OffsetDateTime {
        OffsetDateTime::from(self.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use time::macros::datetime;

    #[test_log::test(rstest::rstest)]
    #[case(SystemTime::from(datetime!(2024-12-24 15:16:17 UTC)), datetime!(2024-12-24 15:16:17 UTC))]
    fn test(#[case] input: SystemTime, #[case] output: OffsetDateTime) {
        assert_eq!(input.into_time(), output)
    }
}
