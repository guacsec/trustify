mod roots;

pub use roots::*;

use petgraph::Graph;
use serde::Serialize;
use std::ops::{Deref, DerefMut};
use std::{collections::HashMap, fmt};
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::relationship::Relationship;
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize)]
pub struct AnalysisStatus {
    /// The number of SBOMs found in the database
    pub sbom_count: u32,
    /// The number of graphs loaded in memory
    pub graph_count: u32,
}

impl fmt::Display for AnalysisStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "graph_count {}", self.graph_count)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize)]
pub struct PackageNode {
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

impl fmt::Display for PackageNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.purl)
    }
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

impl From<&PackageNode> for BaseSummary {
    fn from(value: &PackageNode) -> Self {
        Self {
            sbom_id: value.sbom_id.to_string(),
            node_id: value.node_id.to_string(),
            purl: value.purl.clone(),
            cpe: value.cpe.clone(),
            name: value.name.to_string(),
            version: value.version.to_string(),
            published: value.published.to_string(),
            document_id: value.document_id.to_string(),
            product_name: value.product_name.to_string(),
            product_version: value.product_version.to_string(),
        }
    }
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

#[derive(Debug)]
pub struct GraphMap {
    map: HashMap<String, Graph<PackageNode, Relationship, petgraph::Directed>>,
}

impl GraphMap {
    // Create a new instance of GraphMap
    pub fn new() -> Self {
        GraphMap {
            map: HashMap::new(),
        }
    }

    // Check if the map contains a key
    pub fn contains_key(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    // Get the number of graphs in the map
    pub fn len(&self) -> usize {
        self.map.len()
    }

    // Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    // Add a new graph with the given key (write access)
    pub fn insert(
        &mut self,
        key: String,
        graph: Graph<PackageNode, Relationship, petgraph::Directed>,
    ) {
        self.map.insert(key, graph);
    }

    // Retrieve a reference to a graph by its key (read access)
    pub fn get(&self, key: &str) -> Option<&Graph<PackageNode, Relationship, petgraph::Directed>> {
        self.map.get(key)
    }

    // Retrieve all sbom ids(read access)
    pub fn sbom_ids(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    // Clear all graphs from the map
    pub fn clear(&mut self) {
        self.map.clear();
    }
}

impl Default for GraphMap {
    fn default() -> Self {
        Self::new()
    }
}
