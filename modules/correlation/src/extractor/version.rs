//! Checking the version of an SBOM node against the version range of an assertion.
//!
//! Some identifiers name a product, but not its version, e.g. the model number of a firmware. An
//! advisory then states the versions of that product separately (e.g. `vers:semver/<4.1.0`), and
//! the node only matches if its own version is in that range.

use super::{Assertion, NodeRef};
use crate::{compute::on_worker, error::Error};
use sea_orm::{ConnectionTrait, DbBackend, FromQueryResult, Statement};
use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashSet},
};
use tracing::{Instrument, info_span};
use uuid::Uuid;

#[derive(FromQueryResult)]
struct InRangeRow {
    sbom_id: Uuid,
    node_id: String,
    range_id: Uuid,
}

/// Keep the matches without a version range, and the ones whose node has a version in the range of
/// its assertion. A node without a version is in no range.
///
/// The matches can be owned or shared, as only their node and version range are read. Collecting
/// and filtering them runs on a worker thread (see [`on_worker`]), the check here.
pub async fn retain_in_range<N, A, C>(
    matches: Vec<(N, A)>,
    connection: &C,
) -> Result<Vec<(N, A)>, Error>
where
    N: Borrow<NodeRef> + Send + 'static,
    A: Borrow<Assertion> + Send + 'static,
    C: ConnectionTrait,
{
    let (matches, sboms, nodes, ranges) = on_worker(move || {
        let candidates = matches
            .iter()
            .filter_map(|(node, assertion)| {
                let node = node.borrow();
                assertion
                    .borrow()
                    .version_range_id
                    .map(|range| (node.sbom_id, node.node_id.clone(), range))
            })
            .collect::<BTreeSet<_>>();
        let mut sboms = Vec::with_capacity(candidates.len());
        let mut nodes = Vec::with_capacity(candidates.len());
        let mut ranges = Vec::with_capacity(candidates.len());
        for (sbom_id, node_id, range_id) in candidates {
            sboms.push(sbom_id);
            nodes.push(node_id);
            ranges.push(range_id);
        }
        Ok((matches, sboms, nodes, ranges))
    })
    .await?;
    if sboms.is_empty() {
        return Ok(matches);
    }

    let rows = InRangeRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        r#"
SELECT c.sbom_id, c.node_id, c.range_id
FROM unnest($1::uuid[], $2::text[], $3::uuid[]) AS c(sbom_id, node_id, range_id)
JOIN sbom_package p ON p.sbom_id = c.sbom_id AND p.node_id = c.node_id
JOIN version_range vr ON vr.id = c.range_id
WHERE p.version IS NOT NULL AND version_matches(p.version, vr)
"#,
        [sboms.into(), nodes.into(), ranges.into()],
    ))
    .all(connection)
    .instrument(info_span!("checking node versions"))
    .await?;

    on_worker(move || {
        let in_range = rows
            .into_iter()
            .map(|row| (row.sbom_id, row.node_id, row.range_id))
            .collect::<HashSet<_>>();
        Ok(matches
            .into_iter()
            .filter(
                |(node, assertion)| match assertion.borrow().version_range_id {
                    None => true,
                    Some(range) => {
                        let node = node.borrow();
                        in_range.contains(&(node.sbom_id, node.node_id.clone(), range))
                    }
                },
            )
            .collect())
    })
    .await
}
