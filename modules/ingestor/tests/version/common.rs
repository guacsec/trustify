#![allow(unused)]
// clippy complains about this module being imported multiple times. However, that seems to be some
// artifact from the way the group integration tests.
#![allow(clippy::duplicate_mod)]

use sea_orm::{ConnectionTrait, Statement};
use std::fmt::{Debug, Display};
use std::ops::{Bound, Range, RangeBounds};
use test_context::test_context;
use tracing::instrument;
use trustify_common::db::Database;
use trustify_test_context::TrustifyContext;

#[derive(Debug)]
pub enum VersionRange {
    Exact(&'static str),
    Range(Version, Version),
}

impl VersionRange {
    pub fn range(range: impl RangeBounds<&'static str>) -> Self {
        let start = range.start_bound().map(|s| *s).into();
        let end = range.end_bound().map(|s| *s).into();
        Self::Range(start, end)
    }
}

impl From<Bound<&'static str>> for Version {
    fn from(value: Bound<&'static str>) -> Self {
        match value {
            Bound::Unbounded => Version::Unbounded,
            Bound::Included(version) => Version::Inclusive(version),
            Bound::Excluded(version) => Version::Exclusive(version),
        }
    }
}

#[derive(Debug)]
pub enum Version {
    Inclusive(&'static str),
    Exclusive(&'static str),
    Unbounded,
}

#[instrument(skip(db), ret)]
pub async fn version_matches(
    db: &Database,
    candidate: &str,
    range: VersionRange,
    version_scheme: impl Display + Debug,
) -> Result<bool, anyhow::Error> {
    let (low, low_inclusive, high, high_inclusive) = match range {
        VersionRange::Exact(version) => (
            Some(version.to_string()),
            true,
            Some(version.to_string()),
            true,
        ),
        VersionRange::Range(low, high) => {
            let (low, low_inclusive) = match low {
                Version::Inclusive(version) => (Some(version.to_string()), true),
                Version::Exclusive(version) => (Some(version.to_string()), false),
                Version::Unbounded => (None, false),
            };

            let (high, high_inclusive) = match high {
                Version::Inclusive(version) => (Some(version.to_string()), true),
                Version::Exclusive(version) => (Some(version.to_string()), false),
                Version::Unbounded => (None, false),
            };

            (low, low_inclusive, high, high_inclusive)
        }
    };

    let low = low.map(|v| format!("'{v}'")).unwrap_or("null".to_string());
    let high = high.map(|v| format!("'{v}'")).unwrap_or("null".to_string());

    if let Some(result) = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
        SELECT * FROM version_matches('{candidate}',
            (null, '{version_scheme}', {low}, {low_inclusive}, {high}, {high_inclusive})::version_range
        );
                "#,
            ),
        ))
        .await?
    {
        Ok(result.try_get_by_index::<bool>(0)?)
    } else {
        Ok(false)
    }
}
