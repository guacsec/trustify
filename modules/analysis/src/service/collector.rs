use super::*;
use futures::stream::{self, StreamExt};
use parking_lot::Mutex;
use std::{collections::HashMap, sync::Arc};

/// Tracker for visited nodes, across graphs.
#[derive(Default, Clone)]
pub struct DiscoveredTracker {
    cache: Arc<Mutex<HashMap<*const NodeGraph, FixedBitSet>>>,
}

impl DiscoveredTracker {
    pub fn visit(&self, graph: &NodeGraph, node: NodeIndex) -> bool {
        let mut maps = self.cache.lock();
        let map = maps
            .entry(graph as *const Graph<_, _>)
            .or_insert_with(|| graph.visit_map());

        map.visit(node)
    }
}

/// Collector, helping on collector nodes from a graph.
///
/// Keeping track of all relevant information.
#[derive(Clone)]
pub struct Collector<'a, C: ConnectionTrait> {
    graph_cache: &'a Arc<GraphMap>,
    graphs: &'a [(String, Arc<PackageGraph>)],
    graph: &'a NodeGraph,
    node: NodeIndex,
    direction: Direction,
    depth: u64,
    discovered: DiscoveredTracker,
    relationships: &'a HashSet<Relationship>,
    connection: &'a C,
    concurrency: usize,
}

impl<'a, C: ConnectionTrait> Collector<'a, C> {
    fn clone(&self) -> Self {
        Collector {
            graph_cache: self.graph_cache,
            graphs: self.graphs,
            graph: self.graph,
            node: self.node,
            direction: self.direction,
            depth: self.depth,
            discovered: self.discovered.clone(),
            relationships: self.relationships,
            connection: self.connection,
            concurrency: self.concurrency,
        }
    }

    /// Create a new collector, with a new visited set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        graph_cache: &'a Arc<GraphMap>,
        graphs: &'a [(String, Arc<PackageGraph>)],
        graph: &'a NodeGraph,
        node: NodeIndex,
        direction: Direction,
        depth: u64,
        relationships: &'a HashSet<Relationship>,
        connection: &'a C,
        concurrency: usize,
    ) -> Self {
        Self {
            graph_cache,
            graphs,
            graph,
            node,
            direction,
            depth,
            discovered: Default::default(),
            relationships,
            connection,
            concurrency,
        }
    }

    /// Continue with another graph and node as an entry point.
    ///
    /// Shares the visited set.
    pub fn with(self, graph: &'a NodeGraph, node: NodeIndex) -> Self {
        Self {
            graph,
            node,
            ..self
        }
    }

    /// Continue with a new node, but the same graph.
    ///
    /// Decreases depth by one and keeps the visited set.
    pub fn continue_node(&self, node: NodeIndex) -> Self {
        Self {
            graph_cache: self.graph_cache,
            graphs: self.graphs,
            graph: self.graph,
            node,
            direction: self.direction,
            depth: self.depth - 1,
            discovered: self.discovered.clone(),
            relationships: self.relationships,
            connection: self.connection,
            concurrency: self.concurrency,
        }
    }

    /// Collect related nodes in the provided direction.
    ///
    /// If the depth is zero, or the node was already processed, it will return [`None`], indicating
    /// that the request was not processed.
    pub async fn collect(self) -> Option<Vec<Node>> {
        tracing::debug!(direction = ?self.direction, "collecting for {:?}", self.node);

        if self.depth == 0 {
            log::debug!("depth is zero");
            // we ran out of depth
            return None;
        }

        if !self.discovered.visit(self.graph, self.node) {
            log::debug!("node got visited already");
            // we've already seen this
            return None;
        }

        match self.graph.node_weight(self.node) {
            Some(graph::Node::External(external_node)) => {
                // we know this is an external node, so retrieve external sbom descendant nodes
                let ResolvedSbom {
                    sbom_id: external_sbom_id,
                    node_id: external_node_id,
                } = resolve_external_sbom(&external_node.node_id, self.connection).await?;

                // retrieve external sbom graph from graph_cache
                let Some(external_graph) = self.graph_cache.get(&external_sbom_id.to_string())
                else {
                    log::warn!(
                        "external sbom graph {:?} for {:?} not found during collection.",
                        &external_sbom_id.to_string(),
                        &external_node_id.to_string()
                    );
                    return None;
                };
                // find the node in retrieved external graph
                let Some(external_node_index) = external_graph
                    .node_indices()
                    .find(|&node| external_graph[node].node_id.eq(&external_node_id))
                else {
                    log::warn!("Node with ID {external_node_id} not found in external sbom");
                    return None;
                };
                // recurse into those descendent nodes
                Some(
                    self.with(external_graph.as_ref(), external_node_index)
                        .collect_graph()
                        .await,
                )
            }
            Some(graph::Node::Package(current_node)) => {
                // collect external sbom ancestor nodes
                let current_sbom_id = &current_node.sbom_id;
                let current_sbom_uuid = *current_sbom_id;
                let current_node_id = &current_node.node_id;

                let find_sbom_externals = resolve_rh_external_sbom_ancestors(
                    current_sbom_uuid,
                    current_node.node_id.clone().to_string(),
                    self.connection,
                )
                .await;

                let resolved_external_nodes: Vec<Node> = stream::iter(find_sbom_externals)
                    .map(|sbom_external_node| {
                        let collector = self.clone();
                        async move {
                            if &sbom_external_node.sbom_id == current_sbom_id {
                                return None;
                            }
                            // check this is a valid external relationship
                            match sbom_external_node::Entity::find()
                                .filter(
                                    sbom_external_node::Column::SbomId
                                        .eq(sbom_external_node.clone().sbom_id),
                                )
                                .filter(
                                    sbom_external_node::Column::ExternalNodeRef
                                        .eq(sbom_external_node.clone().node_id),
                                )
                                .one(collector.connection)
                                .await
                            {
                                Ok(Some(matched)) => {
                                    // get the external sbom graph
                                    let Some(external_graph) =
                                        collector.graph_cache.clone().get(&matched.sbom_id.to_string())
                                    else {
                                        log::warn!(
                                            "external sbom graph {:?} not found in graph cache",
                                            &matched.sbom_id.to_string()
                                        );
                                        return None;
                                    };
                                    // find the node in retrieved external graph
                                    let Some(external_node_index) = external_graph
                                        .node_indices()
                                        .find(|&node| {
                                            external_graph[node].node_id.eq(&matched.node_id)
                                        })
                                    else {
                                        log::warn!(
                                            "Node with ID {current_node_id} not found in external sbom"
                                        );
                                        return None;
                                    };
                                    // recurse into those external sbom nodes and save
                                    Some(
                                        collector
                                            .with(external_graph.as_ref(), external_node_index)
                                            .collect_graph()
                                            .await,
                                    )
                                }
                                Err(_) => {
                                    log::warn!("Problem looking up sbom external node");
                                    None
                                }
                                _ => {
                                    log::debug!(
                                        "not external sbom sbom_external_node {sbom_external_node:?}"
                                    );
                                    None
                                }
                            }
                        }
                    })
                    .buffer_unordered(self.concurrency)
                    .filter_map(|nodes| async move { nodes })
                    .flat_map(stream::iter)
                    .collect::<Vec<_>>()
                    .await;

                let mut result = self.collect_graph().await;
                if !resolved_external_nodes.is_empty() {
                    result.extend(resolved_external_nodes);
                }
                Some(result)
            }
            _ => Some(self.collect_graph().await),
        }
    }

    pub async fn collect_graph(&self) -> Vec<Node> {
        log::debug!("Collecting graph for {:?}", self.node);

        stream::iter(self.graph.edges_directed(self.node, self.direction))
            .map(|edge| async move {
                log::debug!("edge {edge:?}");

                // we only recurse in one direction
                // Depending on the direction, we collect ancestors or descendants
                let (ancestor, descendent, package_node) = match self.direction {
                    // If the direction is incoming, we are collecting ancestors.
                    // We recursively call `collect` for the source of the edge.
                    Direction::Incoming => (
                        self.continue_node(edge.source()).collect().await,
                        None,
                        self.graph.node_weight(edge.source()),
                    ),
                    // If the direction is outgoing, we are collecting descendants.
                    // We recursively call `collect` for the target of the edge.
                    Direction::Outgoing => (
                        None,
                        self.continue_node(edge.target()).collect().await,
                        self.graph.node_weight(edge.target()),
                    ),
                };

                let relationship = edge.weight();

                if !self.relationships.is_empty() && !self.relationships.contains(relationship) {
                    // if we have entries, and no match, continue with the next
                    return None;
                }

                // Create a new `Node` and add it to the result
                Some(Node {
                    base: BaseSummary::from(package_node?),
                    relationship: Some(*relationship),
                    ancestors: ancestor,
                    descendants: descendent,
                })
            })
            .buffer_unordered(self.concurrency)
            .filter_map(|node| async move { node })
            .collect::<Vec<_>>()
            .await
    }
}
