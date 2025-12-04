use crate::model;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Hash, PartialOrd, PartialEq, Ord, Eq)]
pub struct Key<'a> {
    direction: Direction,
    sbom: &'a str,
    node: &'a str,
}

impl<'a> Key<'a> {
    pub fn top(sbom: &'a str, node: &'a str) -> Vec<Key<'a>> {
        vec![Self {
            direction: Direction::Top,
            sbom,
            node,
        }]
    }
}

pub trait ChainKeys<'a>: Sized {
    /// Add a key to the chain
    fn add(self, direction: Direction, sbom: &'a str, node: &'a str) -> Self;

    /// Add keys for the same SBOM to the chain
    fn chain(
        self,
        direction: Direction,
        sbom: &'a str,
        nodes: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let mut current = self;

        for node in nodes {
            current = current.add(direction, sbom, node);
        }

        current
    }

    /// add a single ancestor node to the chain
    #[allow(unused)]
    fn ancestor(self, sbom: &'a str, node: &'a str) -> Self {
        self.add(Direction::Ancestor, sbom, node)
    }

    /// add a single descendant node to the chain
    #[allow(unused)]
    fn descendant(self, sbom: &'a str, node: &'a str) -> Self {
        self.add(Direction::Descendant, sbom, node)
    }
}

impl<'a> ChainKeys<'a> for Vec<Key<'a>> {
    fn add(mut self, direction: Direction, sbom: &'a str, node: &'a str) -> Self {
        self.push(Key {
            direction,
            sbom,
            node,
        });

        self
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialOrd, PartialEq, Ord, Eq)]
pub enum Direction {
    Top,
    Ancestor,
    Descendant,
}

impl<'a> From<(Direction, &'a model::Node)> for Key<'a> {
    fn from((direction, node): (Direction, &'a model::Node)) -> Self {
        Self {
            direction,
            sbom: &node.sbom_id,
            node: &node.node_id,
        }
    }
}

/// Collect all warnings
pub fn collect_warnings(nodes: &'_ [model::Node]) -> BTreeMap<Vec<Key<'_>>, &'_ [String]> {
    fn collect<'a: 'b, 'b>(
        direction: Direction,
        nodes: &'a [model::Node],
        key: &'b mut Vec<Key<'a>>,
        result: &'b mut BTreeMap<Vec<Key<'a>>, &'a [String]>,
    ) {
        for node in nodes {
            key.push((direction, node).into());
            if !node.warnings.is_empty() {
                result.insert(key.clone(), &*node.warnings);
            }

            if let Some(ancestors) = &node.ancestors {
                collect(Direction::Ancestor, ancestors, key, result);
            }

            if let Some(descendants) = &node.descendants {
                collect(Direction::Descendant, descendants, key, result);
            }

            key.pop();
        }
    }

    let mut result = BTreeMap::new();
    let mut key = Vec::new();

    collect(Direction::Top, nodes, &mut key, &mut result);

    result
}
