use super::*;
use crate::model::graph::{ExternalNode, PackageNode};
use futures::stream::{self, StreamExt};
use parking_lot::Mutex;
use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};

/// Tracker for visited nodes, across graphs.
#[derive(Default, Clone)]
pub struct DiscoveredTracker {
    cache: Arc<Mutex<HashMap<Uuid, FixedBitSet>>>,
}

impl DiscoveredTracker {
    /// Check if a node was already visited, marking it as visited if not.
    pub fn visit(&self, sbom_id: Uuid, graph: &NodeGraph, node: NodeIndex) -> bool {
        let mut maps = self.cache.lock();
        let map = maps.entry(sbom_id).or_insert_with(|| graph.visit_map());

        map.visit(node)
    }
}

/// Collector, helping on collector nodes from a graph.
///
/// Keeping track of all relevant information.
#[derive(Clone)]
pub struct Collector<'a, C: ConnectionTrait> {
    graph_cache: &'a Arc<GraphMap>,
    graphs: &'a [(Uuid, Arc<PackageGraph>)],
    sbom_id: Uuid,
    graph: &'a NodeGraph,
    node: NodeIndex,
    direction: Direction,
    depth: u64,
    discovered: DiscoveredTracker,
    loaded_graphs: Arc<Mutex<HashMap<Uuid, Arc<PackageGraph>>>>,
    relationships: &'a HashSet<Relationship>,
    connection: &'a C,
    concurrency: usize,
    loader: &'a GraphLoader,
}

impl<'a, C: ConnectionTrait> Collector<'a, C> {
    fn clone(&self) -> Self {
        Collector {
            graph_cache: self.graph_cache,
            graphs: self.graphs,
            sbom_id: self.sbom_id,
            graph: self.graph,
            node: self.node,
            direction: self.direction,
            depth: self.depth,
            discovered: self.discovered.clone(),
            loaded_graphs: self.loaded_graphs.clone(),
            relationships: self.relationships,
            connection: self.connection,
            concurrency: self.concurrency,
            loader: self.loader,
        }
    }

    /// Create a new collector, with a new visited set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        graph_cache: &'a Arc<GraphMap>,
        graphs: &'a [(Uuid, Arc<PackageGraph>)],
        sbom_id: Uuid,
        graph: &'a NodeGraph,
        node: NodeIndex,
        direction: Direction,
        depth: u64,
        relationships: &'a HashSet<Relationship>,
        connection: &'a C,
        concurrency: usize,
        loader: &'a GraphLoader,
    ) -> Self {
        Self {
            graph_cache,
            graphs,
            sbom_id,
            graph,
            node,
            direction,
            depth,
            discovered: Default::default(),
            loaded_graphs: Default::default(),
            relationships,
            connection,
            concurrency,
            loader,
        }
    }

    /// Continue with another graph and node as an entry point.
    ///
    /// Shares the visited set.
    pub fn with(self, sbom_id: Uuid, graph: &'a NodeGraph, node: NodeIndex) -> Self {
        Self {
            sbom_id,
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
            sbom_id: self.sbom_id,
            graph: self.graph,
            node,
            direction: self.direction,
            depth: self.depth - 1,
            discovered: self.discovered.clone(),
            loaded_graphs: self.loaded_graphs.clone(),
            relationships: self.relationships,
            connection: self.connection,
            concurrency: self.concurrency,
            loader: self.loader,
        }
    }

    /// Load an external SBOM graph, checking the local cache first.
    async fn load_external_graph(&self, sbom_id: Uuid) -> Result<Option<Arc<PackageGraph>>, Error> {
        if let Some(graph) = self.loaded_graphs.lock().get(&sbom_id).cloned() {
            return Ok(Some(graph));
        }

        let Some(graph) = self.loader.load(self.connection, sbom_id).await? else {
            return Ok(None);
        };

        let mut map = self.loaded_graphs.lock();
        match map.entry(sbom_id) {
            Entry::Occupied(e) => {
                log::debug!("concurrent load of external SBOM {sbom_id}, reusing existing handle");
                self.loader.redundant_loads.add(1, &[]);
                Ok(Some(e.get().clone()))
            }
            Entry::Vacant(e) => Ok(Some(e.insert(graph).clone())),
        }
    }

    /// Collect related nodes in the provided direction.
    ///
    /// If the depth is zero, or the node was already processed, it will return [`None`], indicating
    /// that the request was not processed.
    pub async fn collect(self) -> Result<(Option<Vec<Node>>, Vec<String>), Error> {
        tracing::trace!(direction = ?self.direction, "collecting for {:?}", self.node);

        if self.depth == 0 {
            log::trace!("depth is zero");
            // we ran out of depth
            return Ok((None, vec![]));
        }

        let node = self.graph.node_weight(self.node);

        if !self.discovered.visit(self.sbom_id, self.graph, self.node) {
            log::trace!("node got visited already");
            return Ok((None, vec!["This node was already visited. Possible relationship loop. Skipping further processing.".into()]));
        }

        match node {
            Some(graph::Node::External(external_node)) => {
                self.collect_external(external_node).await
            }
            Some(graph::Node::Package(current_node)) => self.collect_package(current_node).await,
            _ => Ok((Some(self.collect_graph().await?), vec![])),
        }
    }

    async fn collect_external(
        self,
        external_node: &ExternalNode,
    ) -> Result<(Option<Vec<Node>>, Vec<String>), Error> {
        log::debug!(
            "Collecting external node {}/{}",
            external_node.sbom_id,
            external_node.node_id
        );

        // we know this is an external node, so retrieve external sbom descendant nodes
        let Some(ResolvedSbom {
            sbom_id: external_sbom_id,
            node_id: external_node_id,
        }) = resolve_external_sbom(&external_node.node_id, self.connection).await?
        else {
            return Ok((
                None,
                vec![format!(
                    "Unable to resolve external node: {}",
                    external_node.node_id
                )],
            ));
        };

        // retrieve external sbom graph, checking local cache first
        let Some(external_graph) = self.load_external_graph(external_sbom_id).await? else {
            return Ok((
                None,
                vec![format!(
                    "external sbom graph {external_sbom_id} for {external_node_id} not found during collection."
                )],
            ));
        };

        // find the node in retrieved external graph
        let Some(external_node_index) = external_graph
            .node_indices()
            .find(|&node| external_graph[node].node_id.eq(&external_node_id))
        else {
            return Ok((
                None,
                vec![format!(
                    "Node with ID {external_node_id} not found in external sbom"
                )],
            ));
        };

        // recurse into those descendent nodes
        Ok((
            Some(
                self.with(
                    external_sbom_id,
                    external_graph.as_ref(),
                    external_node_index,
                )
                .collect_graph()
                .await?,
            ),
            vec![],
        ))
    }

    async fn collect_package(
        self,
        current_node: &PackageNode,
    ) -> Result<(Option<Vec<Node>>, Vec<String>), Error> {
        // collect external sbom ancestor nodes
        let current_sbom_id = &current_node.sbom_id;
        let current_sbom_uuid = *current_sbom_id;
        let current_node_id = &current_node.node_id;

        let find_sbom_externals = resolve_rh_external_sbom_ancestors(
            current_sbom_uuid,
            current_node.node_id.clone().to_string(),
            self.connection,
        )
        .await?;

        let resolved_external_nodes: Vec<Node> = stream::iter(find_sbom_externals)
            .map(async |sbom_external_node| {
                let collector = self.clone();

                if &sbom_external_node.sbom_id == current_sbom_id {
                    return Ok::<_, Error>(vec![]);
                }

                // check this is a valid external relationship

                let Some(matched) = sbom_external_node::Entity::find()
                    .filter(sbom_external_node::Column::SbomId.eq(sbom_external_node.sbom_id))
                    .filter(
                        sbom_external_node::Column::ExternalNodeRef.eq(&sbom_external_node.node_id),
                    )
                    .one(self.connection)
                    .await?
                else {
                    log::debug!("no external sbom sbom_external_node {sbom_external_node:?}");
                    return Ok(vec![]);
                };

                // get the external sbom graph

                let Some(external_graph) = self.load_external_graph(matched.sbom_id).await? else {
                    log::warn!(
                        "external sbom graph {} not found in graph cache or database",
                        matched.sbom_id
                    );

                    return Ok(vec![]);
                };

                // find the node in retrieved external graph

                let Some(external_node_index) = external_graph
                    .node_indices()
                    .find(|&node| external_graph[node].node_id.eq(&matched.node_id))
                else {
                    log::warn!("Node with ID {current_node_id} not found in external sbom");
                    return Ok(vec![]);
                };

                // recurse into those external sbom nodes and save

                collector
                    .with(
                        matched.sbom_id,
                        external_graph.as_ref(),
                        external_node_index,
                    )
                    .collect_graph()
                    .await
            })
            .buffer_unordered(self.concurrency)
            .map_ok(|nodes| stream::iter(nodes.into_iter().map(Ok::<_, Error>)))
            .try_flatten()
            .try_collect()
            .await?;

        let mut result = self.collect_graph().await?;
        result.extend(resolved_external_nodes);

        Ok((Some(result), vec![]))
    }

    pub async fn collect_graph(&self) -> Result<Vec<Node>, Error> {
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
                        self.continue_node(edge.source()).collect().await?,
                        (None, vec![]),
                        self.graph.node_weight(edge.source()),
                    ),
                    // If the direction is outgoing, we are collecting descendants.
                    // We recursively call `collect` for the target of the edge.
                    Direction::Outgoing => (
                        (None, vec![]),
                        self.continue_node(edge.target()).collect().await?,
                        self.graph.node_weight(edge.target()),
                    ),
                };

                let relationship = edge.weight();

                if !self.relationships.is_empty() && !self.relationships.contains(relationship) {
                    // if we have entries, and no match, continue with the next
                    return Ok(None);
                }

                let Some(package_node) = package_node else {
                    return Ok(None);
                };

                // collect warnings
                let mut warnings = ancestor.1;
                warnings.extend(descendent.1);

                // Create a new `Node` and add it to the result
                Ok(Some(Node {
                    base: BaseSummary::from(package_node),
                    relationship: Some(*relationship),
                    ancestors: ancestor.0,
                    descendants: descendent.0,
                    warnings,
                }))
            })
            .buffer_unordered(self.concurrency)
            .try_filter_map(|x| async move { Ok(x) }) // drop None
            .try_collect::<Vec<_>>()
            .await
    }
}

#[derive(Clone)]
pub struct GraphLoader {
    service: AnalysisService,
    pub(crate) redundant_loads: Counter<u64>,
}

impl GraphLoader {
    pub fn new(service: AnalysisService) -> Self {
        let meter = global::meter("AnalysisService");
        Self {
            service,
            redundant_loads: meter.u64_counter("collector_redundant_loads").build(),
        }
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        connection: &impl ConnectionTrait,
        sbom_id: Uuid,
    ) -> Result<Option<Arc<PackageGraph>>, Error> {
        let result = self.service.load_graphs(connection, [sbom_id]).await?;

        Ok(result
            .into_iter()
            .find_map(|(id, sbom)| if id == sbom_id { Some(sbom) } else { None }))
    }
}
