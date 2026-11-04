//! Reading evidence and verdicts of node classes (see [`crate::extractor::class`]).
//!
//! They are stored for the representative node of a class only, and apply to every member of it.
//! A node of an SBOM without classes is its own representative.

use crate::{error::Error, model::VerdictSummary};
use sea_orm::{
    ConnectionTrait, FromQueryResult, Value,
    sea_query::{Expr, SimpleExpr},
};
use std::collections::{BTreeSet, HashMap};
use tracing::{Instrument, info_span};
use trustify_common::db::sql;
use uuid::Uuid;

/// SQL expression: the representative node of a node.
pub(super) fn representative(sbom_id: Uuid, node_id: &str) -> SimpleExpr {
    Expr::cust_with_values(
        "coalesce((SELECT representative_node_id FROM correlation_node_class \
         WHERE sbom_id = $1 AND node_id = $2), $3)",
        [
            Value::from(sbom_id),
            Value::from(node_id),
            Value::from(node_id),
        ],
    )
}

#[derive(FromQueryResult)]
struct MemberRow {
    node_id: String,
    representative_node_id: String,
}

#[derive(FromQueryResult)]
struct NameRow {
    node_id: String,
    name: String,
}

/// The members of the classes of the given representative nodes, including the representatives.
pub(super) async fn members(
    sbom_id: Uuid,
    representatives: BTreeSet<String>,
    connection: &impl ConnectionTrait,
) -> Result<HashMap<String, Vec<String>>, Error> {
    let mut result = HashMap::<String, Vec<String>>::with_capacity(representatives.len());
    for row in MemberRow::find_by_statement(sql(
        "SELECT node_id, representative_node_id FROM correlation_node_class \
         WHERE sbom_id = $1 AND representative_node_id = ANY($2) ORDER BY node_id",
        vec![
            sbom_id.into(),
            representatives.iter().cloned().collect::<Vec<_>>().into(),
        ],
    ))
    .all(connection)
    .instrument(info_span!("loading class members"))
    .await?
    {
        result
            .entry(row.representative_node_id)
            .or_default()
            .push(row.node_id);
    }
    // without classes, a node represents itself
    for representative in representatives {
        result
            .entry(representative.clone())
            .or_insert_with(|| vec![representative]);
    }
    Ok(result)
}

/// The names of the given nodes.
pub(super) async fn names(
    sbom_id: Uuid,
    nodes: Vec<String>,
    connection: &impl ConnectionTrait,
) -> Result<HashMap<String, String>, Error> {
    Ok(NameRow::find_by_statement(sql(
        "SELECT node_id, name FROM sbom_node WHERE sbom_id = $1 AND node_id = ANY($2)",
        vec![sbom_id.into(), nodes.into()],
    ))
    .all(connection)
    .instrument(info_span!("loading node names"))
    .await?
    .into_iter()
    .map(|row| (row.node_id, row.name))
    .collect())
}

/// Turn a verdict of a representative into the one of a member.
pub(super) fn for_member(
    mut verdict: VerdictSummary,
    node_id: &str,
    names: &HashMap<String, String>,
) -> VerdictSummary {
    if verdict.component.node_id != node_id {
        verdict.component.node_id = node_id.to_string();
        verdict.component.name = names
            .get(node_id)
            .cloned()
            .unwrap_or_else(|| node_id.to_string());
    }
    verdict
}

/// The verdicts of the representatives, for each member of their classes, ordered by node and
/// vulnerability. With a node, only for that node.
pub(super) async fn expand(
    sbom_id: Uuid,
    verdicts: Vec<VerdictSummary>,
    node_id: Option<&str>,
    connection: &impl ConnectionTrait,
) -> Result<Vec<VerdictSummary>, Error> {
    let representatives = verdicts
        .iter()
        .map(|verdict| verdict.component.node_id.clone())
        .collect();
    let members = members(sbom_id, representatives, connection).await?;
    let mut nodes = members.values().flatten().cloned().collect::<Vec<_>>();
    if let Some(node_id) = node_id {
        nodes.retain(|node| node == node_id);
    }
    let names = names(sbom_id, nodes, connection).await?;

    let mut result = Vec::with_capacity(verdicts.len());
    for verdict in verdicts {
        let Some(members) = members.get(&verdict.component.node_id) else {
            continue;
        };
        for member in members {
            if node_id.is_none_or(|node_id| node_id == member) {
                result.push(for_member(verdict.clone(), member, &names));
            }
        }
    }
    result.sort_by(|a, b| {
        (&a.component.node_id, &a.vulnerability.id)
            .cmp(&(&b.component.node_id, &b.vulnerability.id))
    });
    Ok(result)
}

#[cfg(test)]
mod tests;
