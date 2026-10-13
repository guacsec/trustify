//! The statements of an `affected` entry of a CVE record, as the CVE record format defines them.
//!
//! An entry lists versions, each a single version or a range (`version <= V < lessThan`, or
//! `<= lessThanOrEqual`), with a status, and the status of all other versions (`defaultStatus`). A
//! range may change its status at some versions (`changes`), which splits it into consecutive
//! ranges. A status `unknown` states nothing.
//!
//! See: <https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json>

use crate::{
    graph::advisory::version::{Version, VersionInfo, VersionSpec},
    service::Warnings,
};
use cve::common::{self, Product, Status, VersionRange};
use sea_orm::{
    ConnectionTrait, DbBackend, DbErr, FromQueryResult, Statement as SqlStatement, TransactionTrait,
};
use std::str::FromStr;
use trustify_common::purl::Purl;
use trustify_entity::version_scheme::VersionScheme;

use super::divination::divine_purl;

/// A status of a range of versions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// The status slug: `affected` or `not_affected`.
    pub status: &'static str,
    pub version_info: VersionInfo,
    /// Whether it is the default status: of all versions no other statement lists.
    pub default: bool,
}

/// The status slug of a CVE status, `None` for `unknown`, which states nothing.
pub fn status_slug(status: &Status) -> Option<&'static str> {
    match status {
        Status::Affected => Some("affected"),
        Status::Unaffected => Some("not_affected"),
        Status::Unknown => None,
    }
}

/// The package an entry is about: its `packageURL`, or the one divined from its `collectionURL`
/// and `packageName`.
///
/// The `packageURL` "MUST NOT include a version". A version is ignored, with a warning.
pub fn package_purl(product: &Product, warnings: &Warnings) -> Option<Purl> {
    let Some(stated) = &product.package_url else {
        return divine_purl(product);
    };
    let mut purl = Purl::from_str(stated)
        .inspect_err(|err| warnings.add(format!("Invalid packageURL '{stated}': {err}")))
        .ok()?;
    if purl.version.take().is_some() {
        warnings.add(format!(
            "The packageURL must not include a version, ignoring it: {stated}"
        ));
    }
    Some(purl)
}

/// The version scheme of a range's `versionType`.
fn range_scheme(version_type: &str) -> VersionScheme {
    VersionScheme::from(version_type)
}

/// The version scheme of a single version. Equality doesn't need a known scheme, so an unspecified
/// (`custom`) one is compared as generic.
fn single_scheme(version_type: Option<&str>) -> VersionScheme {
    match version_type.map(VersionScheme::from) {
        None | Some(VersionScheme::Custom) => VersionScheme::Generic,
        Some(scheme) => scheme,
    }
}

/// The statements of the listed versions of an entry.
///
/// The `changes` of a range are sorted with the database's comparison of its version type, see
/// [`sort_versions`].
pub async fn listed_statements<C: ConnectionTrait + TransactionTrait>(
    product: &Product,
    warnings: &Warnings,
    connection: &C,
) -> Result<Vec<Statement>, DbErr> {
    let mut result = Vec::new();

    for version in &product.versions {
        match version {
            common::Version::Single(single) => {
                result.extend(status_slug(&single.status).map(|status| Statement {
                    status,
                    version_info: VersionInfo {
                        scheme: single_scheme(single.version_type.as_deref()),
                        spec: VersionSpec::Exact(single.version.clone()),
                    },
                    default: false,
                }));
            }
            common::Version::Range(range) => {
                let scheme = range_scheme(&range.version_type);
                let changes = sorted_changes(range, scheme, warnings, connection).await?;
                result.extend(split(range, &changes).into_iter().filter_map(
                    |(low, high, status)| {
                        Some(Statement {
                            status: status_slug(status)?,
                            version_info: VersionInfo {
                                scheme,
                                spec: VersionSpec::Range(low, high),
                            },
                            default: false,
                        })
                    },
                ));
            }
        }
    }

    Ok(result)
}

/// The default status of an entry (`defaultStatus`): the status of all versions it doesn't list,
/// as an unbounded range. `None` for `unknown`, the default if missing, which states nothing.
pub fn default_statement(product: &Product) -> Option<Statement> {
    Some(Statement {
        status: status_slug(product.default_status.as_ref()?)?,
        version_info: VersionInfo {
            scheme: VersionScheme::Generic,
            spec: VersionSpec::Range(Version::Unbounded, Version::Unbounded),
        },
        default: true,
    })
}

/// The changes of a range, sorted by their version (`at`).
///
/// The spec requires clients to sort them. If they can't be sorted (an unknown version type, or
/// versions the type can't compare), they are taken in the listed order, with a warning.
async fn sorted_changes<'a, C: ConnectionTrait + TransactionTrait>(
    range: &'a common::Range,
    scheme: VersionScheme,
    warnings: &Warnings,
    connection: &C,
) -> Result<Vec<&'a common::Change>, DbErr> {
    let mut changes = range.changes.iter().collect::<Vec<_>>();
    if changes.len() < 2 {
        return Ok(changes);
    }

    let versions = changes
        .iter()
        .map(|change| change.at.clone())
        .collect::<Vec<_>>();
    match sort_versions(&versions, scheme, connection).await? {
        Some(sorted) => {
            changes.sort_by_key(|change| sorted.iter().position(|v| *v == change.at));
        }
        None => warnings.add(format!(
            "Unable to sort the changes of the range starting at '{}' by their version type \
             '{}', using the listed order",
            range.version, range.version_type
        )),
    }

    Ok(changes)
}

/// Split a range at its (sorted) changes into consecutive ranges with their status.
fn split<'a>(
    range: &'a common::Range,
    changes: &[&'a common::Change],
) -> Vec<(Version, Version, &'a Status)> {
    let mut result = Vec::with_capacity(changes.len() + 1);
    let mut low = Version::Inclusive(range.version.clone());
    let mut status = &range.status;

    for change in changes {
        result.push((low, Version::Exclusive(change.at.clone()), status));
        low = Version::Inclusive(change.at.clone());
        status = &change.status;
    }

    let high = match &range.range {
        VersionRange::LessThan(high) => Version::Exclusive(high.clone()),
        VersionRange::LessThanOrEqual(high) => Version::Inclusive(high.clone()),
    };
    result.push((low, high, status));

    result
}

#[derive(FromQueryResult)]
struct Ranked {
    version: String,
    rank: i64,
}

/// Sort versions with the database's comparison of the scheme (`version_matches`), `None` if they
/// can't be sorted: the scheme can't compare them, or they are equal.
///
/// The comparison runs in a nested transaction, so that a version the scheme fails to parse doesn't
/// abort the caller's transaction.
pub async fn sort_versions<C: ConnectionTrait + TransactionTrait>(
    versions: &[String],
    scheme: VersionScheme,
    connection: &C,
) -> Result<Option<Vec<String>>, DbErr> {
    // the rank of a version: the number of versions lower than it
    const SQL: &str = r#"
SELECT v AS version, (
    SELECT count(*) FROM unnest($1::text[]) AS o
    WHERE version_matches(o, ROW(NULL, $2, NULL, false, v, false)::version_range)
) AS rank
FROM unnest($1::text[]) AS v
"#;
    let statement = SqlStatement::from_sql_and_values(
        DbBackend::Postgres,
        SQL,
        [versions.to_vec().into(), scheme.to_string().into()],
    );

    let ranked = connection
        .transaction::<_, _, DbErr>(|tx| {
            Box::pin(async move { Ranked::find_by_statement(statement).all(tx).await })
        })
        .await;
    let mut ranked = match ranked {
        Ok(ranked) => ranked,
        Err(err) => {
            tracing::debug!("Unable to compare versions as '{scheme}': {err}");
            return Ok(None);
        }
    };

    ranked.sort_by_key(|r| r.rank);
    // a total order: ranks 0, 1, 2, …
    let total = ranked
        .iter()
        .enumerate()
        .all(|(n, r)| usize::try_from(r.rank).is_ok_and(|rank| rank == n));

    Ok(total.then(|| ranked.into_iter().map(|r| r.version).collect()))
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    fn range(json: &str) -> common::Range {
        match serde_json::from_str::<common::Version>(json) {
            Ok(common::Version::Range(range)) => range,
            other => panic!("not a range: {other:?}"),
        }
    }

    /// A range of pretix-newsletter (CVE-2026-2452) with a change.
    #[test]
    fn split_at_changes() {
        let range = range(
            r#"{"changes": [{"at": "1.6.3", "status": "unaffected"}], "lessThan": "2.0.0", "status": "affected", "version": "1.0.0", "versionType": "python"}"#,
        );
        let changes = range.changes.iter().collect::<Vec<_>>();
        assert_eq!(
            split(&range, &changes),
            [
                (
                    Version::Inclusive("1.0.0".into()),
                    Version::Exclusive("1.6.3".into()),
                    &Status::Affected
                ),
                (
                    Version::Inclusive("1.6.3".into()),
                    Version::Exclusive("2.0.0".into()),
                    &Status::Unaffected
                ),
            ]
        );
    }

    #[rstest]
    #[case(None, VersionScheme::Generic)]
    #[case(Some("custom"), VersionScheme::Generic)]
    #[case(Some("semver"), VersionScheme::Semver)]
    #[test]
    fn scheme_of_single(#[case] version_type: Option<&str>, #[case] scheme: VersionScheme) {
        assert_eq!(single_scheme(version_type), scheme);
    }
}
