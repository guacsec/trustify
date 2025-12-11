use crate::config::AnalysisConfig;
use crate::{
    endpoints::configure,
    model::{BaseSummary, Node as GraphNode},
    service::AnalysisService,
};
use std::fmt::Display;
use trustify_entity::relationship::Relationship;
use trustify_test_context::{
    TrustifyContext,
    call::{self, CallService},
};

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    let analysis = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());
    call::caller(|svc| configure(svc, ctx.db.clone(), analysis)).await
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct Node<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub version: &'a str,

    pub cpes: &'a [&'a str],
    pub purls: &'a [&'a str],
}

#[derive(PartialEq, Eq, Debug, Clone)]
struct OwnedNode<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub version: &'a str,

    pub cpes: Vec<String>,
    pub purls: Vec<String>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
struct RefNode<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub version: &'a str,

    pub cpes: Vec<&'a str>,
    pub purls: Vec<&'a str>,
}

impl<'a> From<&'a GraphNode> for OwnedNode<'a> {
    fn from(value: &'a GraphNode) -> Self {
        (&value.base).into()
    }
}

impl<'a> From<&'a BaseSummary> for OwnedNode<'a> {
    fn from(value: &'a BaseSummary) -> Self {
        Self {
            id: &value.node_id,
            name: &value.name,
            version: &value.version,
            cpes: value.cpe.iter().map(ToString::to_string).collect(),
            purls: value.purl.iter().map(ToString::to_string).collect(),
        }
    }
}

pub fn assert_root_traces<F>(ancestors: &[Vec<(&BaseSummary, Relationship)>], f: F)
where
    F: for<'a> FnOnce(&'a [&'a [Node]]),
{
    let ancestors = ancestors
        .iter()
        .map(|item| {
            item.iter()
                .map(|(base, _)| OwnedNode::from(*base))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let ancestors = ancestors
        .iter()
        .map(|a| {
            a.iter()
                .map(|node| RefNode {
                    id: node.id,
                    name: node.name,
                    version: node.version,
                    cpes: node.cpes.iter().map(|s| s.as_str()).collect(),
                    purls: node.purls.iter().map(|s| s.as_str()).collect(),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let ancestors = ancestors
        .iter()
        .map(|a| {
            a.iter()
                .map(|node| Node {
                    id: node.id,
                    name: node.name,
                    version: node.version,
                    cpes: node.cpes.as_slice(),
                    purls: node.purls.as_slice(),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let ancestors = ancestors.iter().map(|a| a.as_slice()).collect::<Vec<_>>();

    log::debug!("Ancestors: {ancestors:#?}");

    f(ancestors.as_slice())
}

/// escape values for putting them into a `q` parameter
pub fn escape_q(q: impl AsRef<str>) -> String {
    let q = q.as_ref();

    q.replace('\\', "\\\\")
        .replace('&', "\\&")
        .replace('=', "\\=")
}

pub(crate) trait Join: Sized {
    /// Turn a base prefix and an iterator of items into an iterator of base + item.
    fn join(self, other: impl IntoIterator<Item = impl Display>) -> impl Iterator<Item = String>;

    /// Same as [`Self::join`], but accepting iterators of iterators for joining, flattening them.
    fn chain(
        self,
        other: impl IntoIterator<Item = impl IntoIterator<Item = impl Display>>,
    ) -> impl Iterator<Item = String> {
        Self::join(self, other.into_iter().flatten())
    }
}

impl<D: Display> Join for D {
    fn join(self, other: impl IntoIterator<Item = impl Display>) -> impl Iterator<Item = String> {
        other.into_iter().map(move |s| format!("{self}{s}"))
    }
}
