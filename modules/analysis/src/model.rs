pub mod graph;

mod roots;
pub use roots::*;

use bytesize::ByteSize;
use deepsize::{Context, DeepSizeOf};
use moka::{notification::RemovalCause, sync::Cache};
use opentelemetry::{KeyValue, Value, metrics::Counter};
use petgraph::Graph;
use serde::Serialize;
use std::{
    fmt,
    ops::{Deref, DerefMut},
    sync::Arc,
};
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::relationship::Relationship;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, ToSchema, serde::Serialize)]
pub struct AnalysisStatus {
    /// The number of SBOMs found in the database
    pub sbom_count: u32,
    /// The number of graphs loaded in memory
    pub graph_count: u32,
    /// The number of bytes consumed by entries in the graph
    pub graph_memory: u64,
    /// The maximum number of bytes the cache will hold
    pub graph_max_memory: u64,
    /// The number of ongoing loading operations
    pub loading_operations: u32,
    /// More details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<AnalysisStatusDetails>,
}

impl fmt::Display for AnalysisStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "graph_count {}", self.graph_count)
    }
}

#[derive(Debug, Clone, PartialEq, ToSchema, serde::Serialize)]
pub struct AnalysisStatusDetails {
    /// Details about the cache
    pub cache: CacheStatusDetails,
}

#[derive(Debug, Clone, PartialEq, ToSchema, serde::Serialize)]
pub struct CacheStatusDetails {
    /// The maximum number of bytes the cache will hold
    pub capacity: u64,
    /// The number of bytes which are still free
    pub free: u64,
    /// The percentage the cache is filled (0..1)
    pub usage: f64,
    /// Entries in the cache
    pub entries: Vec<CacheStatusEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize)]
pub struct CacheStatusEntry {
    /// The ID of the SBOM
    pub sbom_id: String,
    /// The size of the cache entry, in bytes
    pub size: u64,
    /// A human-readable version of `size`
    #[schema(value_type = trustify_common::model::ByteSizeDef)]
    pub size_human: ByteSize,
    /// The number of nodes in the graph
    pub nodes: u64,
    /// The number of edges in the graph
    pub edges: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct BaseSummary {
    pub sbom_id: String,
    pub node_id: String,
    pub purl: Vec<Purl>,
    pub cpe: Vec<Cpe>,
    pub name: String,
    pub version: String,
    pub published: String,
    pub document_id: String,
    pub product_name: String,
    pub product_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Node {
    #[serde(flatten)]
    pub base: BaseSummary,

    /// The relationship the node has to it's containing node, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<Relationship>,

    /// All ancestors of this node. [`None`] if not requested on this level.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(no_recursion)]
    pub ancestors: Option<Vec<Node>>,

    /// All descendents of this node. [`None`] if not requested on this level.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(no_recursion)]
    pub descendants: Option<Vec<Node>>,
}

impl Deref for Node {
    type Target = BaseSummary;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for Node {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

pub type PackageGraph = Graph<graph::Node, Relationship, petgraph::Directed>;

pub struct GraphMap {
    /// cache capacity in bytes
    capacity: u64,
    /// the cache
    map: Cache<Uuid, Arc<PackageGraph>>,
}

#[allow(clippy::ptr_arg)] // &String is required by Cache::builder().weigher() method
fn size_of_graph_entry(_key: &Uuid, value: &Arc<PackageGraph>) -> u32 {
    (
        16 /* Uuid */
            + DeepSizeGraph(value.as_ref()).deep_size_of()
            // Also add in some entry overhead of the cache entry
            + 20
        // todo: find a better estimate for the the moka ValueEntry
    )
    .try_into()
    .unwrap_or(u32::MAX)
}

pub struct DeepSizeGraph<'a>(&'a PackageGraph);

impl DeepSizeOf for DeepSizeGraph<'_> {
    fn deep_size_of_children(&self, ctx: &mut Context) -> usize {
        let mut result = 0;

        for n in self.0.raw_nodes() {
            result += n.weight.deep_size_of_children(ctx);
        }

        for e in self.0.raw_edges() {
            result += e.weight.deep_size_of_children(ctx);
        }

        result
    }
}

struct RemovalCauseAttributeValue(pub RemovalCause);

impl From<RemovalCauseAttributeValue> for Value {
    fn from(value: RemovalCauseAttributeValue) -> Self {
        match value.0 {
            RemovalCause::Expired => "expired",
            RemovalCause::Explicit => "explicit",
            RemovalCause::Replaced => "replaced",
            RemovalCause::Size => "size",
        }
        .into()
    }
}

impl GraphMap {
    /// Create a new instance of GraphMap
    pub fn new(cap: u64, evictions: Counter<u64>, eviction_size: Counter<u64>) -> Self {
        log::info!("Setting graph cache size to {cap} bytes");

        GraphMap {
            capacity: cap,
            map: Cache::builder()
                .weigher(size_of_graph_entry)
                .max_capacity(cap)
                .eviction_listener(move |k, v, cause| {
                    let attrs = [KeyValue::new("cause", RemovalCauseAttributeValue(cause))];
                    let size = size_of_graph_entry(&k, &v);

                    evictions.add(1, &attrs);
                    eviction_size.add(size as _, &attrs);

                    log::info!("Evicting {k}: {cause:?}: {size} bytes");
                })
                .build(),
        }
    }

    /// Check if the map contains a key
    pub fn contains_key(&self, key: Uuid) -> bool {
        self.map.contains_key(&key)
    }

    /// Get the number of graphs in the map
    pub fn len(&self) -> u64 {
        self.map.entry_count()
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn size_used(&self) -> u64 {
        self.map.weighted_size()
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Add a new graph with the given key (write access)
    pub fn insert(&self, key: Uuid, graph: Arc<PackageGraph>) {
        self.map.insert(key, graph);
        self.map.run_pending_tasks();
    }

    /// Retrieve a reference to a graph by its key (read access)
    pub fn get(&self, key: Uuid) -> Option<Arc<PackageGraph>> {
        self.map.get(&key)
    }

    /// Clear all graphs from the map
    pub fn clear(&self) {
        self.map.invalidate_all();
        self.map.run_pending_tasks();
    }

    /// Get internal status
    pub fn status(&self) -> CacheStatusDetails {
        let mut entries = vec![];

        for entry in self.map.iter() {
            let size = DeepSizeGraph(&entry.1).deep_size_of() as u64;

            entries.push(CacheStatusEntry {
                sbom_id: entry.0.to_string(),
                size_human: ByteSize::b(size),
                size,
                edges: entry.1.edge_count() as _,
                nodes: entry.1.node_count() as _,
            })
        }

        let used = self.size_used();
        let free = self.capacity - used;
        let usage = used as f64 / self.capacity as f64;

        CacheStatusDetails {
            capacity: self.capacity,
            free,
            usage,
            entries,
        }
    }
}
