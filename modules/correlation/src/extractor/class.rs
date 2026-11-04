//! Node classes: the nodes of an SBOM with the same evidence.
//!
//! The evidence of a node only depends on its identifiers, the version and supplier of its
//! package, and the CPEs, checksums and product identifiers of the node and of its ancestors in
//! the SBOM, with their distance (see [`super::context`]). What else an extraction reads, e.g. the
//! describing CPEs and the ancestor SBOMs, is the same for all nodes of an SBOM. So nodes sharing
//! all of these inputs form a class, which is matched once: through its representative, the
//! member with the smallest node ID. Evidence and verdicts are stored for the representative, and
//! readers map each node to it.
//!
//! The key uses the stored values as they are (e.g. a checksum before normalizing its algorithm),
//! so it may keep nodes apart which match the same, but never joins nodes which don't. It only
//! reads the SBOM's own content, which doesn't change after ingestion.

use super::{
    NodeRef,
    context::{MAX_DEPTH, PARENT_RELATIONSHIPS},
};
use crate::error::Error;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, QueryFilter,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, hash_map::Entry};
use tracing::{Instrument, Span, field, info_span, instrument};
use trustify_common::db::{chunk::EntityChunkedIter, sql};
use trustify_entity::correlation_node_class;
use uuid::Uuid;

/// Number of nodes per query.
const CHUNK: usize = 5000;

/// Namespace of the class keys. Change it when the key changes, to not mix classes of both.
const KEY_NAMESPACE: Uuid = Uuid::from_bytes([
    0x5c, 0x1a, 0x7e, 0x02, 0x9b, 0x4d, 0x4f, 0x61, 0x8a, 0x3e, 0x0d, 0x6b, 0x2f, 0xc4, 0x91, 0x57,
]);

/// The parent relationships of the SBOM's nodes, as in the ancestor walk of the contexts.
fn edges_sql() -> String {
    format!(
        "SELECT left_node_id AS parent, right_node_id AS child FROM package_relates_to_package \
         WHERE sbom_id = $1 AND relationship IN ({PARENT_RELATIONSHIPS})"
    )
}

/// The inputs of a node only it contributes: its PURLs, and the version and supplier of its
/// package.
const OWN_SQL: &str = r#"
SELECT node_id, 'purl:' || qualified_purl_id::text AS item
FROM sbom_node_purl_ref WHERE sbom_id = $1
UNION ALL
SELECT node_id, 'package:' || jsonb_build_array(version, supplier)::text
FROM sbom_package WHERE sbom_id = $1
"#;

/// The inputs a node passes on to its descendants: its CPEs, checksums and product identifiers.
const SCOPING_SQL: &str = r#"
SELECT node_id, 'cpe:' || cpe_id::text AS item
FROM sbom_node_cpe_ref WHERE sbom_id = $1
UNION ALL
SELECT node_id, 'checksum:' || jsonb_build_array(type, value)::text
FROM sbom_node_checksum WHERE sbom_id = $1
UNION ALL
SELECT node_id, 'product:' || jsonb_build_array(identifier_type::text, value)::text
FROM sbom_node_product_identifier WHERE sbom_id = $1
"#;

#[derive(FromQueryResult)]
struct NodeRow {
    node_id: String,
}

#[derive(FromQueryResult)]
struct EdgeRow {
    parent: String,
    child: String,
}

#[derive(FromQueryResult)]
struct ItemRow {
    node_id: String,
    item: String,
}

/// The nodes of an SBOM, indexed, with their inputs.
#[derive(Default)]
struct Graph {
    index: HashMap<String, usize>,
    parents: Vec<Vec<usize>>,
    own: Vec<Vec<String>>,
    scoping: Vec<Vec<String>>,
}

impl Graph {
    /// The index of a node, adding it if it's new.
    fn node(&mut self, node_id: String) -> usize {
        match self.index.entry(node_id) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let index = self.parents.len();
                entry.insert(index);
                self.parents.push(Vec::new());
                self.own.push(Vec::new());
                self.scoping.push(Vec::new());
                index
            }
        }
    }

    /// The scoping inputs of a node and its ancestors, at their shortest distance.
    ///
    /// Like the ancestor walk of the contexts, the ones of the node itself are kept apart from
    /// the same ones of an ancestor, and the walk stops at [`MAX_DEPTH`].
    fn scoping_of(&self, node: usize) -> Vec<String> {
        let mut found = BTreeMap::<(&str, bool), i32>::new();
        let mut seen = HashSet::from([node]);
        let mut frontier = vec![node];
        let mut distance = 0;
        while !frontier.is_empty() {
            let mut next = Vec::new();
            for current in frontier {
                for item in &self.scoping[current] {
                    found
                        .entry((item.as_str(), distance == 0))
                        .or_insert(distance);
                }
                if distance < MAX_DEPTH {
                    for &parent in &self.parents[current] {
                        if seen.insert(parent) {
                            next.push(parent);
                        }
                    }
                }
            }
            frontier = next;
            distance += 1;
        }
        found
            .into_iter()
            .map(|((item, _), distance)| format!("{distance}:{item}"))
            .collect()
    }

    /// The class key of a node.
    fn key(&self, node: usize, with_scoping: bool) -> Uuid {
        let mut items = self.own[node]
            .iter()
            .map(|item| format!("own:{item}"))
            .collect::<Vec<_>>();
        if with_scoping {
            items.extend(self.scoping_of(node));
        }
        items.sort_unstable();
        // length prefixed, so items can't run into each other
        let mut bytes = Vec::new();
        for item in items {
            bytes.extend_from_slice(&(item.len() as u64).to_le_bytes());
            bytes.extend_from_slice(item.as_bytes());
        }
        Uuid::new_v5(&KEY_NAMESPACE, &bytes)
    }
}

/// Load the inputs of all nodes of an SBOM.
async fn load_graph(
    sbom_id: Uuid,
    tx: &impl ConnectionTrait,
) -> Result<(Graph, Vec<usize>), Error> {
    let mut graph = Graph::default();
    let nodes = NodeRow::find_by_statement(sql(
        "SELECT node_id FROM sbom_node WHERE sbom_id = $1",
        vec![sbom_id.into()],
    ))
    .all(tx)
    .instrument(info_span!("loading nodes"))
    .await?
    .into_iter()
    .map(|row| graph.node(row.node_id))
    .collect::<Vec<_>>();

    for row in EdgeRow::find_by_statement(sql(&edges_sql(), vec![sbom_id.into()]))
        .all(tx)
        .instrument(info_span!("loading parent relationships"))
        .await?
    {
        let parent = graph.node(row.parent);
        let child = graph.node(row.child);
        graph.parents[child].push(parent);
    }
    for row in ItemRow::find_by_statement(sql(OWN_SQL, vec![sbom_id.into()]))
        .all(tx)
        .instrument(info_span!("loading node identifiers"))
        .await?
    {
        let node = graph.node(row.node_id);
        graph.own[node].push(row.item);
    }
    for row in ItemRow::find_by_statement(sql(SCOPING_SQL, vec![sbom_id.into()]))
        .all(tx)
        .instrument(info_span!("loading node scoping identifiers"))
        .await?
    {
        let node = graph.node(row.node_id);
        graph.scoping[node].push(row.item);
    }
    Ok((graph, nodes))
}

/// Compute the classes of the nodes of an SBOM, and store them, replacing the previous ones.
///
/// Returns the representative nodes.
#[instrument(skip(tx), fields(nodes, classes = field::Empty), err(level = tracing::Level::INFO))]
pub async fn classify(sbom_id: Uuid, tx: &impl ConnectionTrait) -> Result<HashSet<String>, Error> {
    let (graph, nodes) = load_graph(sbom_id, tx).await?;
    let span = Span::current();
    span.record("nodes", nodes.len());

    let names = graph
        .index
        .iter()
        .map(|(node_id, index)| (*index, node_id.as_str()))
        .collect::<HashMap<_, _>>();
    // without any scoping identifiers, there is no need to walk the ancestors
    let with_scoping = graph.scoping.iter().any(|items| !items.is_empty());
    let mut classes = HashMap::<Uuid, Vec<&str>>::new();
    for node in nodes {
        let Some(name) = names.get(&node) else {
            continue;
        };
        classes
            .entry(graph.key(node, with_scoping))
            .or_default()
            .push(name);
    }
    span.record("classes", classes.len());

    correlation_node_class::Entity::delete_many()
        .filter(correlation_node_class::Column::SbomId.eq(sbom_id))
        .exec(tx)
        .await?;

    let mut representatives = HashSet::with_capacity(classes.len());
    let mut rows = Vec::with_capacity(names.len());
    for members in classes.into_values() {
        let Some(representative) = members.iter().min().copied() else {
            continue;
        };
        for member in members {
            rows.push(correlation_node_class::ActiveModel {
                sbom_id: Set(sbom_id),
                node_id: Set(member.to_string()),
                representative_node_id: Set(representative.to_string()),
            });
        }
        representatives.insert(representative.to_string());
    }
    for batch in rows.chunked() {
        correlation_node_class::Entity::insert_many(batch)
            .exec(tx)
            .instrument(info_span!("inserting node classes"))
            .await?;
    }
    Ok(representatives)
}

#[derive(FromQueryResult)]
struct MemberRow {
    sbom_id: Uuid,
    node_id: String,
}

/// The nodes of the given ones that aren't the representative of their class.
///
/// Their evidence is the one of their representative. Nodes of SBOMs without classes (not
/// extracted since classes were introduced) represent themselves.
#[instrument(skip_all, fields(nodes = field::Empty, members = field::Empty), err(level = tracing::Level::INFO))]
pub async fn members(
    nodes: BTreeSet<NodeRef>,
    tx: &impl ConnectionTrait,
) -> Result<HashSet<NodeRef>, Error> {
    Span::current().record("nodes", nodes.len());
    let nodes = nodes.into_iter().collect::<Vec<_>>();
    let mut result = HashSet::new();
    for chunk in nodes.chunks(CHUNK) {
        let (sboms, ids): (Vec<_>, Vec<_>) = chunk
            .iter()
            .map(|node| (node.sbom_id, node.node_id.clone()))
            .unzip();
        result.extend(
            MemberRow::find_by_statement(sql(
                "SELECT c.sbom_id, c.node_id FROM unnest($1::uuid[], $2::text[]) AS n(sbom_id, node_id) \
                 JOIN correlation_node_class c ON c.sbom_id = n.sbom_id AND c.node_id = n.node_id \
                 WHERE c.representative_node_id <> c.node_id",
                vec![sboms.into(), ids.into()],
            ))
            .all(tx)
            .await?
            .into_iter()
            .map(|row| NodeRef {
                sbom_id: row.sbom_id,
                node_id: row.node_id,
            }),
        );
    }
    Span::current().record("members", result.len());
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    /// A graph from `(node, own, scoping)` entries and `(parent, child)` edges.
    fn graph(nodes: &[(&str, &[&str], &[&str])], edges: &[(&str, &str)]) -> Graph {
        let mut graph = Graph::default();
        for (node, own, scoping) in nodes {
            let index = graph.node(node.to_string());
            graph.own[index] = own.iter().map(ToString::to_string).collect();
            graph.scoping[index] = scoping.iter().map(ToString::to_string).collect();
        }
        for (parent, child) in edges {
            let parent = graph.node(parent.to_string());
            let child = graph.node(child.to_string());
            graph.parents[child].push(parent);
        }
        graph
    }

    fn key(graph: &Graph, node: &str) -> Uuid {
        graph.key(graph.index[node], true)
    }

    #[test]
    fn classes() {
        let graph = graph(
            &[
                ("product", &[], &["cpe:a"]),
                ("other", &[], &["cpe:b"]),
                ("lib", &["purl:x", "package:1"], &[]),
                ("lib-copy", &["purl:x", "package:1"], &[]),
                ("lib-other-product", &["purl:x", "package:1"], &[]),
                ("lib-deeper", &["purl:x", "package:1"], &[]),
                ("lib-other-version", &["purl:x", "package:2"], &[]),
                ("lib-own-cpe", &["purl:x", "package:1"], &["cpe:a"]),
                ("middle", &["purl:y"], &[]),
            ],
            &[
                ("product", "lib"),
                ("product", "lib-copy"),
                ("other", "lib-other-product"),
                ("product", "middle"),
                ("middle", "lib-deeper"),
                ("product", "lib-other-version"),
                ("product", "lib-own-cpe"),
            ],
        );

        assert_eq!(key(&graph, "lib"), key(&graph, "lib-copy"));
        for other in [
            "lib-other-product",
            "lib-deeper",
            "lib-other-version",
            "lib-own-cpe",
        ] {
            assert_ne!(key(&graph, "lib"), key(&graph, other), "{other}");
        }
    }

    #[test]
    fn scoping_keeps_the_shortest_distance() {
        let graph = graph(
            &[
                ("top", &[], &["cpe:a"]),
                ("parent", &[], &["cpe:a"]),
                ("node", &[], &["cpe:a"]),
            ],
            &[("top", "parent"), ("parent", "node"), ("top", "node")],
        );

        assert_eq!(
            graph.scoping_of(graph.index["node"]),
            // the ancestors' first
            vec!["1:cpe:a".to_string(), "0:cpe:a".to_string()]
        );
    }

    #[test]
    fn scoping_stops_at_the_depth_limit() {
        let chain = (0..=MAX_DEPTH + 1)
            .map(|n| format!("n{n}"))
            .collect::<Vec<_>>();
        let nodes = chain
            .iter()
            .enumerate()
            .map(|(n, node)| {
                let scoping: &[&str] = if n == 0 { &["cpe:a"] } else { &[] };
                (node.as_str(), &[][..], scoping)
            })
            .collect::<Vec<_>>();
        let edges = chain
            .windows(2)
            .map(|pair| (pair[0].as_str(), pair[1].as_str()))
            .collect::<Vec<_>>();
        let graph = graph(&nodes, &edges);

        let limit = format!("n{MAX_DEPTH}");
        let beyond = format!("n{}", MAX_DEPTH + 1);
        assert_eq!(
            graph.scoping_of(graph.index[limit.as_str()]),
            vec![format!("{MAX_DEPTH}:cpe:a")]
        );
        assert_eq!(
            graph.scoping_of(graph.index[beyond.as_str()]),
            Vec::<String>::new()
        );
    }
}
