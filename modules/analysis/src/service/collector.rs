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

type AncestorResult = Arc<Vec<ResolvedSbom>>;
type AncestorCell = Arc<tokio::sync::OnceCell<AncestorResult>>;
type AncestorMap = HashMap<(Uuid, String), AncestorCell>;

/// Request-scoped cache for [`resolve_rh_external_sbom_ancestors`] results.
///
/// # Why this exists
///
/// During ancestor traversal (`Direction::Incoming`) every
/// `PackageNode` visited triggers a call to
/// `resolve_rh_external_sbom_ancestors`.  A single component SBOM
/// can contain hundreds of package nodes, many of which share the
/// same `(sbom_id, node_id)` coordinates across different graph
/// traversal paths.  Without caching, the same expensive SQL query
/// is issued for each visit.
///
/// # Coalescing
///
/// A `tokio::sync::OnceCell` is stored per unique key.  When
/// multiple concurrent tasks (spawned by `buffer_unordered`) request
/// the same key simultaneously, the `OnceCell`'s internal semaphore
/// ensures only one task executes the query; the others await its
/// result.
///
/// # Scope
///
/// One `AncestorCache` is created per top-level `run_graph_query`
/// call (i.e. per HTTP request) and shared across **all** collector
/// instances via `Arc`.  This means results computed while
/// processing one result-set node are reused by later nodes and by
/// both the ancestor and descendant collectors.
#[derive(Default, Clone)]
pub struct AncestorCache {
    cache: Arc<Mutex<AncestorMap>>,
}

impl AncestorCache {
    /// Resolve ancestors for `(sbom_id, node_id)`, returning a cached
    /// result when available.
    ///
    /// The first caller for a given key drives the DB query; concurrent
    /// and subsequent callers receive a cheap `Arc` clone of the result.
    async fn resolve<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        node_id: String,
        connection: &C,
    ) -> Result<AncestorResult, Error> {
        // Acquire or create the per-key OnceCell under the lock,
        // then immediately drop the lock before awaiting the query.
        let cell = {
            let mut map = self.cache.lock();
            map.entry((sbom_id, node_id.clone())).or_default().clone()
        };

        cell.get_or_try_init(|| async {
            let result = resolve_rh_external_sbom_ancestors(sbom_id, node_id, connection).await?;
            Ok(Arc::new(result))
        })
        .await
        .cloned()
    }

    /// Batch-prefetch ancestor results for all `PackageNode`s in a
    /// graph that share the given `sbom_id`.
    ///
    /// Collects every `PackageNode.node_id` from the graph that is
    /// not already cached, issues a single batched SQL query via
    /// [`resolve_rh_external_sbom_ancestors_batch`], and populates
    /// the cache with the results.  Subsequent per-node `resolve`
    /// calls for these keys become cheap cache hits.
    ///
    /// Node IDs already present in the cache are skipped — this is
    /// safe because entries are immutable once written (backed by
    /// `OnceCell`).
    pub(super) async fn prefetch<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        graph: &NodeGraph,
        connection: &C,
    ) -> Result<(), Error> {
        // Collect uncached node_ids under the lock, then release it.
        let uncached_node_ids: Vec<String> = {
            let map = self.cache.lock();
            graph
                .node_weights()
                .filter_map(|node| match node {
                    graph::Node::Package(pkg) if pkg.sbom_id == sbom_id => {
                        let key = (sbom_id, pkg.node_id.clone());
                        if map.contains_key(&key) {
                            None
                        } else {
                            Some(pkg.node_id.clone())
                        }
                    }
                    _ => None,
                })
                .collect()
        };

        if uncached_node_ids.is_empty() {
            return Ok(());
        }

        // Batch-resolve all uncached node_ids in a single SQL query
        // (chunked to stay under the PostgreSQL bind-parameter limit).
        let chunk_size = ((u16::MAX - 128) as usize / 2).max(1);
        for chunk in uncached_node_ids.chunks(chunk_size) {
            let batch_result =
                resolve_rh_external_sbom_ancestors_batch(sbom_id, chunk, connection).await?;

            // Populate the cache with results.
            let mut map = self.cache.lock();
            for node_id in chunk {
                let key = (sbom_id, node_id.clone());
                if map.contains_key(&key) {
                    continue;
                }
                let results = batch_result.get(node_id).cloned().unwrap_or_default();
                let cell: AncestorCell =
                    Arc::new(tokio::sync::OnceCell::new_with(Some(Arc::new(results))));
                map.insert(key, cell);
            }
        }

        Ok(())
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
    ancestor_cache: AncestorCache,
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
            ancestor_cache: self.ancestor_cache.clone(),
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
        ancestor_cache: AncestorCache,
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
            ancestor_cache,
            relationships,
            connection,
            concurrency,
            loader,
        }
    }

    /// Continue with another graph and node as an entry point.
    ///
    /// Decreases depth by one and keeps the visited set.
    pub fn with(self, sbom_id: Uuid, graph: &'a NodeGraph, node: NodeIndex) -> Self {
        Self {
            sbom_id,
            graph,
            node,
            depth: self.depth.saturating_sub(1),
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
            depth: self.depth.saturating_sub(1),
            discovered: self.discovered.clone(),
            loaded_graphs: self.loaded_graphs.clone(),
            ancestor_cache: self.ancestor_cache.clone(),
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
            ..
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

        // Batch-prefetch ancestor results before recursing.
        self.ancestor_cache
            .prefetch(external_sbom_id, &external_graph, self.connection)
            .await?;

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

    /// Collect ancestor (or descendant) nodes for a `PackageNode`,
    /// including any cross-SBOM links discovered through RH-style
    /// checksum matching.
    ///
    /// Two things happen here:
    ///
    /// 1. **Cross-SBOM ancestors** — For every `PackageNode`, we ask
    ///    "does any *other* SBOM claim to be an ancestor of the SBOM
    ///    that contains this node?"  If so, we load that ancestor
    ///    SBOM's graph, find the entry-point node, and recursively
    ///    collect its graph.  This is what makes product→component
    ///    relationships visible in the API response.
    ///
    /// 2. **Intra-SBOM traversal** — We then call `collect_graph` to
    ///    walk the edges of the *current* SBOM's graph from this node
    ///    in the configured direction (ancestors or descendants).
    ///
    /// The results from both steps are merged into the output.
    async fn collect_package(
        self,
        current_node: &PackageNode,
    ) -> Result<(Option<Vec<Node>>, Vec<String>), Error> {
        let current_sbom_id = &current_node.sbom_id;
        let current_sbom_uuid = *current_sbom_id;
        let current_node_id = &current_node.node_id;

        // Step 1: find ancestor SBOMs that reference this node via
        // shared checksums.  Results are cached per (sbom_id,
        // node_id) so repeated visits to the same node (common
        // during recursive graph traversal) do not hit the DB.
        let find_sbom_externals = self
            .ancestor_cache
            .resolve(
                current_sbom_uuid,
                current_node.node_id.clone().to_string(),
                self.connection,
            )
            .await?;

        // For each ancestor SBOM found, load its graph and recurse.
        let resolved_external_nodes: Vec<Node> = stream::iter(find_sbom_externals.iter().cloned())
            .map(async |resolved| {
                let collector = self.clone();

                // Skip self-references (the current SBOM can appear
                // in its own ancestor set due to how checksums are
                // shared).
                if &resolved.sbom_id == current_sbom_id {
                    return Ok::<_, Error>(vec![]);
                }

                // Determine the ancestor SBOM id and the node_id to
                // look up in its in-memory graph.
                //
                // The RH ancestor path (`graph_node_id` populated)
                // already resolved both values in the single SQL
                // query, so no extra DB round-trip is needed.
                //
                // The SPDX/CycloneDX path (`graph_node_id` is None)
                // must fall back to a `sbom_external_node` lookup to
                // map the external_node_ref to the graph's node_id.
                let (ext_sbom_id, ext_graph_node_id) = if let Some(gid) = &resolved.graph_node_id {
                    (resolved.sbom_id, gid.clone())
                } else {
                    let Some(matched) = sbom_external_node::Entity::find()
                        .filter(sbom_external_node::Column::SbomId.eq(resolved.sbom_id))
                        .filter(sbom_external_node::Column::ExternalNodeRef.eq(&resolved.node_id))
                        .one(self.connection)
                        .await?
                    else {
                        log::debug!("no external sbom sbom_external_node {resolved:?}");
                        return Ok(vec![]);
                    };
                    (matched.sbom_id, matched.node_id)
                };

                // Load the ancestor SBOM's in-memory graph (from the
                // request-scoped or global graph cache).
                let Some(external_graph) = self.load_external_graph(ext_sbom_id).await? else {
                    log::warn!(
                        "external sbom graph {ext_sbom_id} not found \
                         in graph cache or database",
                    );
                    return Ok(vec![]);
                };

                // Batch-prefetch ancestor results for all
                // PackageNodes in this external graph.  This
                // collapses N per-node SQL queries into a single
                // batched query, so the recursive walk below finds
                // warm cache entries instead of issuing individual
                // queries.
                collector
                    .ancestor_cache
                    .prefetch(ext_sbom_id, &external_graph, collector.connection)
                    .await?;

                // Find the entry-point node in the ancestor graph.
                let Some(external_node_index) = external_graph
                    .node_indices()
                    .find(|&node| external_graph[node].node_id.eq(&ext_graph_node_id))
                else {
                    log::warn!(
                        "Node with ID {current_node_id} not found \
                         in external sbom"
                    );
                    return Ok(vec![]);
                };

                // Recurse: collect the ancestor graph from this node.
                collector
                    .with(ext_sbom_id, external_graph.as_ref(), external_node_index)
                    .collect_graph()
                    .await
            })
            .buffer_unordered(self.concurrency)
            .map_ok(|nodes| stream::iter(nodes.into_iter().map(Ok::<_, Error>)))
            .try_flatten()
            .try_collect()
            .await?;

        // Step 2: walk the current SBOM's own graph edges and merge
        // the cross-SBOM results.
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
        let result = self.service.load_graphs(connection, vec![sbom_id]).await?;

        Ok(result
            .into_iter()
            .find_map(|(id, sbom)| if id == sbom_id { Some(sbom) } else { None }))
    }
}
