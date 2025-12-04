use crate::model::{BaseSummary, Node};
use std::collections::HashMap;
use trustify_common::model::PaginatedResults;
use trustify_entity::relationship::Relationship;

pub trait Roots {
    /// Collect all top level ancestors.
    fn roots(self) -> Self;
}

impl Roots for PaginatedResults<Node> {
    fn roots(self) -> PaginatedResults<Node> {
        let items = self.items.roots();
        let total = items.len();
        Self {
            items,
            total: total as _,
        }
    }
}

impl Roots for Vec<Node> {
    fn roots(self) -> Vec<Node> {
        fn roots_into(
            nodes: impl IntoIterator<Item = Node>,
            result: &mut HashMap<(String, String), Node>,
        ) {
            for node in nodes.into_iter() {
                roots_into(node.ancestors.clone().into_iter().flatten(), result);

                if let Some(true) = node.ancestors.as_ref().map(|a| a.is_empty()) {
                    result.insert((node.base.sbom_id.clone(), node.base.node_id.clone()), node);
                }
            }
        }

        let mut result = HashMap::new();
        roots_into(self, &mut result);

        result.into_values().collect()
    }
}

pub trait RootTraces {
    type Result;

    /// Collect all traces to the root nodes
    fn root_traces(self) -> Self::Result;
}

impl<'a> RootTraces for &'a PaginatedResults<Node> {
    type Result = PaginatedResults<Vec<(&'a BaseSummary, Relationship)>>;

    fn root_traces(self) -> Self::Result {
        let items = self.items.root_traces();
        let total = items.len();
        Self::Result {
            items,
            total: total as _,
        }
    }
}

impl<'a> RootTraces for &'a Vec<Node> {
    type Result = Vec<Vec<(&'a BaseSummary, Relationship)>>;

    fn root_traces(self) -> Self::Result {
        fn roots_into<'a>(
            nodes: impl IntoIterator<Item = &'a Node>,
            parents: &[(&'a BaseSummary, Relationship)],
            result: &mut Vec<Vec<(&'a BaseSummary, Relationship)>>,
        ) {
            for node in nodes.into_iter() {
                let mut next = parents.to_owned();

                // if we don't have a relationship to the parent node, we are the initial node
                // and will be skipped
                if let Some(relationship) = node.relationship {
                    next.push((&node.base, relationship));
                };

                if let Some(true) = node.ancestors.as_ref().map(|a| a.is_empty()) {
                    result.push(next);
                } else {
                    roots_into(node.ancestors.iter().flatten(), &next, result);
                }
            }
        }

        let mut result = Vec::new();
        roots_into(self, &Vec::new(), &mut result);

        result
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::BaseSummary;
    use trustify_entity::relationship::Relationship;

    fn base(node_id: &str) -> BaseSummary {
        BaseSummary {
            sbom_id: "".to_string(),
            node_id: node_id.to_string(),
            purl: vec![],
            cpe: vec![],
            name: "".to_string(),
            version: "".to_string(),
            published: "".to_string(),
            document_id: "".to_string(),
            product_name: "".to_string(),
            product_version: "".to_string(),
        }
    }

    fn node(node_id: &str) -> Node {
        Node {
            base: base(node_id),
            relationship: None,
            ancestors: None,
            descendants: None,
            warnings: vec![],
        }
    }

    #[test]
    fn simple_roots() {
        let result = vec![Node {
            base: base("AA"),
            relationship: None,
            ancestors: Some(vec![Node {
                ancestors: Some(vec![]),
                relationship: Some(Relationship::Dependency),
                ..node("A")
            }]),
            descendants: None,
            warnings: vec![],
        }]
        .roots();

        assert_eq!(
            result,
            vec![Node {
                base: base("A"),
                relationship: Some(Relationship::Dependency),
                ancestors: Some(vec![]),
                descendants: None,
                warnings: vec![],
            }]
        );
    }

    #[test]
    fn nested_roots() {
        let result = vec![Node {
            ancestors: Some(vec![Node {
                base: base("AA"),
                relationship: Some(Relationship::Dependency),
                ancestors: Some(vec![Node {
                    ancestors: Some(vec![]),
                    relationship: Some(Relationship::Dependency),
                    ..node("A")
                }]),
                descendants: None,
                warnings: vec![],
            }]),
            ..node("AAA")
        }]
        .roots();

        assert_eq!(
            result,
            vec![Node {
                base: base("A"),
                relationship: Some(Relationship::Dependency),
                ancestors: Some(vec![]),
                descendants: None,
                warnings: vec![],
            }]
        );
    }

    #[test]
    fn nested_root_traces() {
        let result = vec![Node {
            ancestors: Some(vec![Node {
                base: base("AA"),
                relationship: Some(Relationship::Dependency),
                ancestors: Some(vec![Node {
                    ancestors: Some(vec![]),
                    relationship: Some(Relationship::Dependency),
                    ..node("A")
                }]),
                descendants: None,
                warnings: vec![],
            }]),
            ..node("AAA")
        }];
        let result = result.root_traces();

        assert_eq!(
            result,
            vec![vec![
                (&base("AA"), Relationship::Dependency),
                (&base("A"), Relationship::Dependency),
            ]]
        );
    }
}
