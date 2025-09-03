mod load;
mod query;
mod walk;

pub use collector::*;
pub use query::*;
pub use walk::*;

mod collector;
pub mod render;
#[cfg(test)]
mod test;

use crate::{
    Error,
    config::AnalysisConfig,
    model::{AnalysisStatus, BaseSummary, GraphMap, Node, PackageGraph, graph},
};
use fixedbitset::FixedBitSet;
use futures::{StreamExt, stream};

use crate::model::AnalysisStatusDetails;
use futures::future::Shared;
use opentelemetry::{global, metrics::Counter};
use parking_lot::Mutex;
use petgraph::{
    Direction,
    graph::{Graph, NodeIndex},
    prelude::EdgeRef,
    visit::{IntoNodeIdentifiers, VisitMap, Visitable},
};
use sea_orm::{
    ColumnTrait, EntityOrSelect, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect,
    RelationTrait, prelude::ConnectionTrait,
};
use sea_query::JoinType;
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    sync::{mpsc, oneshot, oneshot::error::RecvError},
    task::JoinHandle,
};
use tracing::instrument;
use trustify_common::{
    db::query::{Value, ValueContext},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{
    relationship::Relationship,
    sbom,
    sbom_external_node::{self, DiscriminatorType, ExternalType},
    sbom_node_checksum, source_document,
};
use uuid::Uuid;

type NodeGraph = Graph<graph::Node, Relationship, petgraph::Directed>;

#[derive(Debug)]
struct QueueEntry {
    id: String,
    tx: oneshot::Sender<()>,
}

#[derive(Debug)]
pub struct Queued {
    rx: oneshot::Receiver<()>,
}

impl Future for Queued {
    type Output = Result<(), RecvError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.rx).poll(cx)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("queue already closed")]
pub struct QueueError;

#[derive(Clone)]
pub struct AnalysisService {
    inner: InnerService,
    _loader: Arc<JoinHandle<()>>,
    tx: mpsc::UnboundedSender<QueueEntry>,
    concurrency: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedSbom {
    // The ID of the SBOM the node was found in
    pub sbom_id: Uuid,
    // The ID of the node
    pub node_id: String,
}

async fn resolve_external_sbom<C: ConnectionTrait>(
    node_id: &str,
    connection: &C,
) -> Option<ResolvedSbom> {
    // we first lookup in sbom_external_node
    let sbom_external_node = match sbom_external_node::Entity::find()
        .filter(sbom_external_node::Column::NodeId.eq(node_id))
        .one(connection)
        .await
    {
        Ok(Some(entity)) => entity,
        _ => return None,
    };

    match sbom_external_node.external_type {
        ExternalType::SPDX => {
            // For spdx, sbom_external_node discriminator_type and discriminator_value are used
            // to lookup sbom_id via join to SourceDocument. The node_id is just the external_node_ref.

            let discriminator_value = sbom_external_node.discriminator_value?;

            if discriminator_value.is_empty() {
                return None;
            }

            let query =
                sbom::Entity::find().join(JoinType::Join, sbom::Relation::SourceDocument.def());

            let query = match sbom_external_node.discriminator_type? {
                DiscriminatorType::Sha256 => {
                    query.filter(source_document::Column::Sha256.eq(&discriminator_value))
                }
                _ => return None,
            };

            match query.one(connection).await {
                Ok(Some(entity)) => Some(ResolvedSbom {
                    sbom_id: entity.sbom_id,
                    node_id: sbom_external_node.external_node_ref,
                }),
                _ => None,
            }
        }
        ExternalType::CycloneDx => {
            // For cyclonedx, sbom_external_node discriminator_type and discriminator_value are used
            // we construct external_doc_id to lookup sbom_id directly from sbom entity. The node_id
            // is the external_node_ref

            let discriminator_value = sbom_external_node.discriminator_value?;

            if discriminator_value.is_empty() {
                return None;
            }

            let external_doc_ref = sbom_external_node.external_doc_ref;
            let external_doc_id = format!("urn:cdx:{external_doc_ref}/{discriminator_value}");

            match sbom::Entity::find()
                .filter(sbom::Column::DocumentId.eq(external_doc_id))
                .one(connection)
                .await
            {
                Ok(Some(entity)) => Some(ResolvedSbom {
                    sbom_id: entity.sbom_id,
                    node_id: sbom_external_node.external_node_ref,
                }),
                _ => None,
            }
        }
        ExternalType::RedHatProductComponent => {
            // for RH variations we assume the sbom_external_node_ref is the package checksum
            // which is used on sbom_node_checksum to lookup related value then
            // perform another lookup on sbom_node_checksum (matching by value) to find resultant
            // sbom_id/node_id
            resolve_rh_external_sbom_descendants(
                sbom_external_node.sbom_id,
                sbom_external_node.external_node_ref,
                connection,
            )
            .await
        }
    }
}

async fn resolve_rh_external_sbom_descendants<C: ConnectionTrait>(
    sbom_external_sbom_id: Uuid,
    sbom_external_node_ref: String,
    connection: &C,
) -> Option<ResolvedSbom> {
    // find checksum value for the node
    match sbom_node_checksum::Entity::find()
        .filter(sbom_node_checksum::Column::NodeId.eq(sbom_external_node_ref.clone()))
        .filter(sbom_node_checksum::Column::SbomId.eq(sbom_external_sbom_id))
        .one(connection)
        .await
    {
        Ok(Some(entity)) => {
            // now find if there are any other nodes with the same checksums
            match sbom_node_checksum::Entity::find()
                .filter(sbom_node_checksum::Column::Value.eq(entity.value.to_string()))
                .filter(sbom_node_checksum::Column::SbomId.ne(entity.sbom_id))
                .all(connection)
                .await
            {
                Ok(matches) => matches
                    .into_iter()
                    // The use of .find here ensures we never match on cdx top level metadata component
                    // which has not defined a bom-ref - we can 'sniff' this because such nodes always
                    // are ingested with a uuid node-id.
                    .find(|model| Uuid::parse_str(&model.node_id).is_err())
                    .map(|matched_model| ResolvedSbom {
                        sbom_id: matched_model.sbom_id,
                        node_id: matched_model.node_id,
                    }),
                _ => None,
            }
        }
        _ => None,
    }
}

async fn resolve_rh_external_sbom_ancestors<C: ConnectionTrait>(
    sbom_external_sbom_id: Uuid,
    sbom_external_node_ref: String,
    connection: &C,
) -> Vec<ResolvedSbom> {
    // find related checksum value(s) for the node, because any single component can be referred to by multiple
    // sboms, this function returns a Vec<ResolvedSbom>.
    match sbom_node_checksum::Entity::find()
        .filter(sbom_node_checksum::Column::NodeId.eq(sbom_external_node_ref.clone()))
        .filter(sbom_node_checksum::Column::SbomId.eq(sbom_external_sbom_id))
        .one(connection)
        .await
    {
        Ok(Some(entity)) => {
            // now find if there are any other nodes with the same checksums
            match sbom_node_checksum::Entity::find()
                .filter(sbom_node_checksum::Column::Value.eq(entity.value.to_string()))
                .filter(sbom_node_checksum::Column::SbomId.ne(entity.sbom_id))
                .all(connection)
                .await
            {
                Ok(matches) => matches
                    .into_iter()
                    .map(|matched| ResolvedSbom {
                        sbom_id: matched.sbom_id,
                        node_id: matched.node_id,
                    })
                    .collect(),
                _ => vec![],
            }
        }
        _ => {
            vec![]
        }
    }
}

impl AnalysisService {
    /// Create a new analysis service instance with the configured cache size.
    ///
    /// ## Caching
    ///
    /// A new instance will have a new cache. Instanced cloned from it, will share that cache.
    ///
    /// Therefore, it is ok to create a new instance. However, if you want to make use of the
    /// caching, it is necessary to re-use that instance.
    ///
    /// Also, we do not implement default because of this. As a new instance has the implication
    /// of having its own cache. So creating a new instance should be a deliberate choice.
    pub fn new<C>(config: AnalysisConfig, connection: C) -> Self
    where
        C: ConnectionTrait + Send + 'static,
    {
        let meter = global::meter("AnalysisService");

        let graph_cache = Arc::new(GraphMap::new(
            config.max_cache_size.as_u64(),
            meter.u64_counter("cache_evictions").build(),
            meter
                .u64_counter("cache_evictions_size")
                .with_unit("b")
                .build(),
        ));

        let loading_ops = Arc::new(Mutex::new(HashMap::new()));

        {
            let graph_cache = graph_cache.clone();
            meter
                .u64_observable_gauge("cache_size")
                .with_unit("b")
                .with_callback(move |inst| inst.observe(graph_cache.size_used(), &[]))
                .build();
        };
        {
            let graph_cache = graph_cache.clone();
            meter
                .u64_observable_gauge("cache_items")
                .with_callback(move |inst| inst.observe(graph_cache.len(), &[]))
                .build();
        };
        {
            let loading_ops = loading_ops.clone();
            meter
                .u64_observable_gauge("loading_operations")
                .with_callback(move |inst| inst.observe(loading_ops.lock().len() as _, &[]))
                .build();
        };

        let (tx, rx) = mpsc::unbounded_channel::<QueueEntry>();

        let inner = InnerService {
            graph_cache,
            loading_ops,
            cache_hit: meter.u64_counter("cache_hits").build(),
            cache_miss: meter.u64_counter("cache_miss").build(),
        };

        let loader = {
            let inner = inner.clone();
            Arc::new(tokio::spawn(async move {
                Self::loader(rx, inner, connection).await;
            }))
        };

        Self {
            inner,
            _loader: loader,
            tx,
            concurrency: config.concurrency.get(),
        }
    }

    async fn loader<C>(
        mut rx: mpsc::UnboundedReceiver<QueueEntry>,
        service: InnerService,
        connection: C,
    ) where
        C: ConnectionTrait + Send + 'static,
    {
        let mut next = vec![];
        while rx.recv_many(&mut next, 8).await != 0 {
            let (ids, txs): (Vec<_>, Vec<_>) =
                next.drain(..).map(|entry| (entry.id, entry.tx)).unzip();

            match service.load_graphs(&connection, ids.as_slice()).await {
                Ok(r) => {
                    log::info!("Loaded {} graphs", r.len());
                }
                Err(err) => {
                    log::warn!("Failed to load graphs into cache: {err}");
                }
            }

            // notify listeners if they are interested
            for tx in txs {
                let _ = tx.send(());
            }
        }
    }

    pub fn cache_size_used(&self) -> u64 {
        self.inner.graph_cache.size_used()
    }

    pub fn cache_len(&self) -> u64 {
        self.inner.graph_cache.len()
    }

    /// Queue an SBOM for loading into the cache
    pub fn queue_load(&self, id: String) -> Result<Queued, QueueError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(QueueEntry { id, tx })
            .map_err(|_| QueueError)?;
        Ok(Queued { rx })
    }

    #[instrument(skip_all, err)]
    pub async fn load_all_graphs<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        // retrieve all sboms in trustify

        let distinct_sbom_ids = sbom::Entity::find()
            .select()
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect::<Vec<_>>();

        self.load_graphs(connection, &distinct_sbom_ids).await
    }

    pub fn clear_all_graphs(&self) -> Result<(), Error> {
        self.inner.graph_cache.clear();
        Ok(())
    }

    pub async fn status<C: ConnectionTrait>(
        &self,
        connection: &C,
        details: bool,
    ) -> Result<AnalysisStatus, Error> {
        let distinct_sbom_ids = sbom::Entity::find().count(connection).await?;

        Ok(AnalysisStatus {
            sbom_count: distinct_sbom_ids as u32,
            graph_count: self.inner.graph_cache.len() as u32,
            graph_memory: self.inner.graph_cache.size_used(),
            graph_max_memory: self.inner.graph_cache.capacity(),
            loading_operations: self.inner.loading_ops.lock().len() as u32,
            details: details.then(|| self.inner.status_details()),
        })
    }

    /// Collect nodes from the graph
    #[instrument(skip(self, create, graphs))]
    async fn collect_graph<'a, 'g, F, Fut>(
        &self,
        query: impl Into<GraphQuery<'a>> + Debug,
        graphs: &'g [(String, Arc<PackageGraph>)],
        concurrency: usize,
        create: F,
    ) -> Vec<Node>
    where
        F: Fn(&'g Graph<graph::Node, Relationship>, NodeIndex, &'g graph::Node) -> Fut + Clone,
        Fut: Future<Output = Node>,
    {
        let query = query.into();

        stream::iter(
            graphs
                .iter()
                .filter(|(sbom_id, graph)| acyclic(sbom_id, graph)),
        )
        .flat_map(|(_, graph)| {
            let create = create.clone();
            stream::iter(
                graph
                    .node_indices()
                    .filter(|&i| Self::filter(graph, &query, i))
                    .filter_map(|i| graph.node_weight(i).map(|w| (i, w))),
            )
            .map(move |(node_index, package_node)| create(graph, node_index, package_node))
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await
    }

    #[instrument(skip(self, connection, graphs, graph_cache))]
    pub async fn run_graph_query<'a, C: ConnectionTrait>(
        &self,
        query: impl Into<GraphQuery<'a>> + Debug,
        options: QueryOptions,
        graphs: &[(String, Arc<PackageGraph>)],
        connection: &C,
        graph_cache: Arc<GraphMap>,
    ) -> Vec<Node> {
        let relationships = options.relationships;
        log::debug!("relations: {:?}", relationships);

        self.collect_graph(
            query,
            graphs,
            self.concurrency,
            |graph, node_index, node| {
                let graph_cache = graph_cache.clone();
                let relationships = relationships.clone();
                async move {
                    log::debug!(
                        "Discovered node - sbom: {}, node: {}",
                        node.sbom_id,
                        node.node_id
                    );

                    let ancestors = Collector::new(
                        &graph_cache,
                        graphs,
                        graph,
                        node_index,
                        Direction::Incoming,
                        options.ancestors,
                        &relationships,
                        connection,
                        self.concurrency,
                    )
                    .collect();

                    let descendants = Collector::new(
                        &graph_cache,
                        graphs,
                        graph,
                        node_index,
                        Direction::Outgoing,
                        options.descendants,
                        &relationships,
                        connection,
                        self.concurrency,
                    )
                    .collect();

                    let (ancestors, descendants) = futures::join!(ancestors, descendants);

                    Node {
                        base: node.into(),
                        relationship: None,
                        ancestors,
                        descendants,
                    }
                }
            },
        )
        .await
    }

    /// locate components, retrieve dependency information, from a single SBOM
    /// TODO - this is only used by a test
    #[instrument(skip(self, connection), err)]
    pub async fn retrieve_single<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        query: impl Into<GraphQuery<'_>> + Debug,
        options: impl Into<QueryOptions> + Debug,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<Node>, Error> {
        let distinct_sbom_ids = vec![sbom_id.to_string()];

        let query = query.into();
        let options = options.into();

        let graphs = self.load_graphs(connection, &distinct_sbom_ids).await?;
        let components = self
            .run_graph_query(
                query,
                options,
                &graphs,
                connection,
                self.inner.graph_cache.clone(),
            )
            .await;

        Ok(paginated.paginate_array(&components))
    }

    /// locate components, retrieve dependency information
    #[instrument(skip(self, connection), err)]
    pub async fn retrieve<C: ConnectionTrait>(
        &self,
        query: impl Into<GraphQuery<'_>> + Debug,
        options: impl Into<QueryOptions> + Debug,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<Node>, Error> {
        let query = query.into();
        let options = options.into();

        let graphs = self.inner.load_graphs_query(connection, query).await?;

        let components = self
            .run_graph_query(
                query,
                options,
                &graphs,
                connection,
                self.inner.graph_cache.clone(),
            )
            .await;

        Ok(paginated.paginate_array(&components))
    }

    #[instrument(skip(self, connection), err)]
    pub async fn retrieve_latest<C: ConnectionTrait>(
        &self,
        query: impl Into<GraphQuery<'_>> + Debug,
        options: impl Into<QueryOptions> + Debug,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<Node>, Error> {
        let query = query.into();
        let options = options.into();

        // load only latest graphs
        let graphs = self
            .inner
            .load_latest_graphs_query(connection, query)
            .await?;

        log::debug!("graph sbom count: {:?}", graphs.len());

        let components = self
            .run_graph_query(
                query,
                options,
                &graphs,
                connection,
                self.inner.graph_cache.clone(),
            )
            .await;

        Ok(paginated.paginate_array(&components))
    }

    /// check if a node in the graph matches the provided query
    fn filter(graph: &Graph<graph::Node, Relationship>, query: &GraphQuery, i: NodeIndex) -> bool {
        match query {
            GraphQuery::Component(ComponentReference::Id(component_id)) => graph
                .node_weight(i)
                .is_some_and(|node| node.node_id.eq(component_id)),
            GraphQuery::Component(ComponentReference::Name(component_name)) => graph
                .node_weight(i)
                .is_some_and(|node| node.name.eq(component_name)),
            GraphQuery::Component(ComponentReference::Purl(purl)) => {
                graph.node_weight(i).is_some_and(|node| match node {
                    graph::Node::Package(package) => package.purl.iter().any(|package_purl| {
                        package_purl.to_string().starts_with(&purl.to_string())
                    }),
                    _ => false,
                })
            }
            GraphQuery::Component(ComponentReference::Cpe(cpe)) => {
                graph.node_weight(i).is_some_and(|node| match node {
                    graph::Node::Package(package) => package.cpe.contains(cpe),
                    _ => false,
                })
            }
            GraphQuery::Query(query) => graph.node_weight(i).is_some_and(|node| {
                let purls: Vec<_> = match node {
                    graph::Node::Package(p) => {
                        p.purl.iter().map(|p| Value::Json(p.into())).collect()
                    }
                    _ => vec![],
                };
                let sbom_id = node.sbom_id.to_string();
                let mut context = ValueContext::from([
                    ("sbom_id", Value::String(&sbom_id)),
                    ("node_id", Value::String(&node.node_id)),
                    ("name", Value::String(&node.name)),
                ]);
                match node {
                    graph::Node::Package(package) => {
                        context.put_string("version", &package.version);
                        context.put_value("cpe", Value::from(&package.cpe));
                        context.put_value("purl", Value::from(&package.purl));
                        context.put_array("purl", purls);
                    }
                    graph::Node::External(external) => {
                        context.put_string(
                            "external_document_reference",
                            &external.external_document_reference,
                        );
                        context.put_string("external_node_id", &external.external_node_id);
                    }
                    _ => {}
                }
                query.apply(&context)
            }),
        }
    }
}

fn acyclic(id: &str, graph: &Arc<PackageGraph>) -> bool {
    use petgraph::visit::{DfsEvent, depth_first_search};
    let g = graph.as_ref();
    let result = depth_first_search(g, g.node_identifiers(), |event| match event {
        DfsEvent::BackEdge(source, target) => Err((source, target)),
        _ => Ok(()),
    })
    .err();
    if let Some((start, end)) = result {
        // FIXME: we need a better strategy handling such errors
        let start = graph.node_weight(start);
        let end = graph.node_weight(end);
        log::warn!(
            "analysis graph of sbom {id} has circular references (detected: {start:?} -> {end:?})!",
        );
    }
    result.is_none()
}

type LoadingOp = Shared<oneshot::Receiver<Result<Arc<PackageGraph>, String>>>;

#[derive(Clone)]
struct InnerService {
    graph_cache: Arc<GraphMap>,
    loading_ops: Arc<Mutex<HashMap<Uuid, LoadingOp>>>,
    cache_hit: Counter<u64>,
    cache_miss: Counter<u64>,
}

impl InnerService {
    /// Get detailed information of the status
    pub fn status_details(&self) -> AnalysisStatusDetails {
        AnalysisStatusDetails {
            cache: self.graph_cache.status(),
        }
    }
}
