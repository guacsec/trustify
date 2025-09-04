use crate::service::Visitor;
use trustify_entity::relationship::Relationship;

fn escape(id: &str) -> String {
    let mut escaped = String::with_capacity(id.len());

    for ch in id.chars() {
        match ch {
            '"' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '\n' => {
                escaped.push_str("\\n");
            }
            '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }

    escaped
}

use crate::model::graph;
use crate::model::graph::Node;
use std::fmt::Write;

pub struct Renderer {
    data: String,
}

impl Renderer {
    pub fn new() -> Self {
        Self {
            data: r#"
digraph {
"#
            .to_string(),
        }
    }
}

impl Visitor for Renderer {
    type Output = (String, String);

    fn node(&mut self, node: &graph::Node) {
        match node {
            Node::Package(package) => {
                let _ = writeln!(
                    self.data,
                    r#""{id}" [label="{label}"]"#,
                    id = escape(&package.node_id),
                    label = escape(&format!(
                        "{name} / {version}: {id}",
                        name = package.name,
                        version = package.version,
                        id = package.node_id
                    ))
                );
            }
            Node::External(external) => {
                let _ = writeln!(
                    self.data,
                    r#""{id}" [label="{label}"]"#,
                    id = escape(&external.node_id),
                    label = escape(&format!(
                        "{doc} # {node}: {id}",
                        doc = external.external_document_reference,
                        node = external.external_node_id,
                        id = external.node_id
                    ))
                );
            }
            Node::Unknown(base) => {
                let _ = writeln!(
                    self.data,
                    r#""{id}" [label="{label}"]"#,
                    id = escape(&base.node_id),
                    label = escape(&base.node_id.to_string())
                );
            }
        }
    }

    fn edge(&mut self, source: &graph::Node, relationship: Relationship, target: &graph::Node) {
        let _ = writeln!(
            self.data,
            r#""{source}" -> "{target}" [label="{label}"]"#,
            source = escape(&source.node_id),
            target = escape(&target.node_id),
            label = escape(&relationship.to_string())
        );
    }

    fn complete(mut self) -> Self::Output {
        self.data.push_str(
            r#"
}
"#,
        );

        (self.data, "text/vnd.graphviz".to_string())
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn escape() {
        assert_eq!(super::escape("foo\"bar\nbaz"), r#"foo\"bar\nbaz"#);
    }
}
