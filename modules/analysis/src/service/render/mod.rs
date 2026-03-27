mod graphviz;

use super::*;
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, ToSchema)]
pub enum Renderer {
    /// Graphviz
    #[serde(rename = "gv", alias = "dot")]
    Graphviz,
}

impl AnalysisService {
    #[instrument(skip_all)]
    pub fn render(&self, graph: &PackageGraph, renderer: Renderer) -> Option<(String, String)> {
        match renderer {
            Renderer::Graphviz => self.walk(graph, graphviz::Renderer::new()),
        }
    }
}
