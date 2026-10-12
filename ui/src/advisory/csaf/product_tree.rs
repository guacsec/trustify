//! The product tree of a CSAF document: its branches and relationships.

use super::{
    Doc,
    index::ProductIndex,
    none, product_ref,
    status::{StatusCategory, StatusCounts, status_counts, status_labels},
};
use crate::sort::{ordered, text, use_sort};
use ::csaf::schema::csaf2_0::schema::{Branch, FullProductNameT, Relationship};
use patternfly_yew::prelude::*;
use std::{cmp::Ordering, collections::HashMap, rc::Rc};
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct ProductTreeTabProps {
    pub doc: Doc,
}

#[function_component(ProductTreeTab)]
pub fn product_tree_tab(props: &ProductTreeTabProps) -> Html {
    let tree = use_memo(props.doc.clone(), BranchTree::new);
    let has_relationships = props
        .doc
        .csaf
        .product_tree
        .as_ref()
        .is_some_and(|tree| !tree.relationships.is_empty());

    let header = html_nested! {
        <TreeTableHeader<BranchColumn>>
            <TableColumn<BranchColumn> label="Branch" index={BranchColumn::Name} />
            <TableColumn<BranchColumn> label="Category" index={BranchColumn::Category} />
            <TableColumn<BranchColumn> label="Product" index={BranchColumn::Product} />
            <TableColumn<BranchColumn> label="Identifier" index={BranchColumn::Identifier} />
            <TableColumn<BranchColumn> label="Status" index={BranchColumn::Status} />
        </TreeTableHeader<BranchColumn>>
    };

    html! {
        <Stack gutter=true>
            <StackItem>
                <Title level={Level::H2}>{ "Branches" }</Title>
                if tree.0.is_empty() {
                    <p>{ "The document has no branches." }</p>
                } else {
                    <TreeTable<BranchColumn, BranchTree>
                        mode={TreeTableMode::Compact}
                        {header}
                        model={tree}
                        default_expansion=false
                    />
                }
            </StackItem>
            if has_relationships {
                <StackItem>
                    <Title level={Level::H2}>{ "Relationships" }</Title>
                    <Relationships doc={props.doc.clone()} />
                </StackItem>
            }
        </Stack>
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BranchColumn {
    Name,
    Category,
    Product,
    Identifier,
    Status,
}

/// A branch of the product tree, converted once so expanding a node does not copy subtrees.
#[derive(PartialEq)]
struct BranchNode {
    name: String,
    category: String,
    product: Option<BranchProduct>,
    children: Vec<Rc<BranchNode>>,
    /// The relationships the product of the branch takes part in.
    relationships: Vec<Rc<RelationshipNode>>,
}

/// The relationships of the product tree, by the product IDs taking part in them.
type RelationshipsById<'a> = HashMap<&'a str, Vec<&'a Relationship>>;

/// A relationship of the product of a branch, with the other product resolved.
#[derive(Debug, PartialEq)]
struct RelationshipNode {
    category: String,
    /// Whether the product of the branch is the product reference, rather than the product it
    /// relates to.
    outgoing: bool,
    other_id: String,
    other_name: Option<String>,
    result: BranchProduct,
}

impl RelationshipNode {
    fn new(
        product_id: &str,
        relationship: &Relationship,
        index: &ProductIndex,
        statuses: &StatusCounts,
    ) -> Self {
        let outgoing = *relationship.product_reference == product_id;
        let other_id = if outgoing {
            relationship.relates_to_product_reference.to_string()
        } else {
            relationship.product_reference.to_string()
        };
        Self {
            category: relationship.category.to_string(),
            outgoing,
            other_name: index.get(&other_id).map(|product| product.name.clone()),
            other_id,
            result: BranchProduct::new(&relationship.full_product_name, statuses),
        }
    }
}

#[derive(Debug, PartialEq)]
struct BranchProduct {
    id: String,
    name: String,
    /// The PURL, or the CPE.
    identifier: Option<String>,
    /// How many vulnerabilities state each status category for the product, if any does.
    statuses: Option<[usize; StatusCategory::ALL.len()]>,
}

impl BranchNode {
    fn new(
        branch: &Branch,
        by_id: &RelationshipsById,
        index: &ProductIndex,
        statuses: &StatusCounts,
    ) -> Self {
        let product = branch
            .product
            .as_ref()
            .map(|product| BranchProduct::new(product, statuses));
        let relationships = product
            .as_ref()
            .and_then(|product| {
                by_id.get(product.id.as_str()).map(|found| {
                    found
                        .iter()
                        .map(|r| Rc::new(RelationshipNode::new(&product.id, r, index, statuses)))
                        .collect()
                })
            })
            .unwrap_or_default();

        Self {
            name: branch.name.to_string(),
            category: branch.category.to_string(),
            product,
            children: branch
                .branches
                .as_ref()
                .map(|branches| {
                    branches
                        .0
                        .iter()
                        .map(|b| Rc::new(Self::new(b, by_id, index, statuses)))
                        .collect()
                })
                .unwrap_or_default(),
            relationships,
        }
    }
}

impl BranchProduct {
    fn new(product: &FullProductNameT, statuses: &StatusCounts) -> Self {
        let helper = product.product_identification_helper.as_ref();
        Self {
            id: product.product_id.to_string(),
            statuses: statuses.get(product.product_id.as_str()).copied(),
            name: product.name.to_string(),
            identifier: helper
                .and_then(|helper| helper.purl.as_deref().or(helper.cpe.as_deref()))
                .cloned(),
        }
    }
}

impl BranchProduct {
    /// The status labels, if the product is referenced by a status.
    fn status(&self) -> Html {
        match &self.statuses {
            Some(counts) => status_labels(Some(counts)),
            None => html!(),
        }
    }
}

impl TreeNode<BranchColumn> for BranchNode {
    fn render_cell(&self, ctx: CellContext<'_, BranchColumn>) -> Cell {
        match ctx.column {
            BranchColumn::Name => html!(&self.name).into(),
            BranchColumn::Category => html!(&self.category).into(),
            BranchColumn::Product => match &self.product {
                Some(product) => html! {
                    <>
                        <code>{ &product.id }</code>
                        <br />
                        <small>{ &product.name }</small>
                    </>
                }
                .into(),
                None => html!().into(),
            },
            BranchColumn::Identifier => match self.product.as_ref() {
                Some(BranchProduct {
                    identifier: Some(identifier),
                    ..
                }) => html!(<code>{ identifier }</code>).into(),
                _ => html!().into(),
            },
            BranchColumn::Status => match &self.product {
                Some(product) => product.status().into(),
                None => html!().into(),
            },
        }
    }

    fn children(&self) -> Vec<Rc<dyn TreeNode<BranchColumn>>> {
        self.children
            .iter()
            .map(|child| child.clone() as Rc<dyn TreeNode<BranchColumn>>)
            .chain(
                self.relationships
                    .iter()
                    .map(|child| child.clone() as Rc<dyn TreeNode<BranchColumn>>),
            )
            .collect()
    }
}

impl TreeNode<BranchColumn> for RelationshipNode {
    fn render_cell(&self, ctx: CellContext<'_, BranchColumn>) -> Cell {
        match ctx.column {
            // Read as a sentence, with the product of the branch as the implied other side.
            BranchColumn::Name => {
                let other = html!(<code>{ &self.other_id }</code>);
                let category = html!(<em>{ &self.category }</em>);
                html! {
                    <>
                        if self.outgoing {
                            { category } { " " } { other }
                        } else {
                            { other } { " " } { category }
                        }
                        if let Some(name) = &self.other_name {
                            <br />
                            <small>{ name }</small>
                        }
                    </>
                }
                .into()
            }
            BranchColumn::Category => html!("relationship").into(),
            BranchColumn::Product => html! {
                <>
                    <code>{ &self.result.id }</code>
                    <br />
                    <small>{ &self.result.name }</small>
                </>
            }
            .into(),
            BranchColumn::Identifier => match &self.result.identifier {
                Some(identifier) => html!(<code>{ identifier }</code>).into(),
                None => html!().into(),
            },
            BranchColumn::Status => self.result.status().into(),
        }
    }

    fn children(&self) -> Vec<Rc<dyn TreeNode<BranchColumn>>> {
        Vec::new()
    }
}

#[derive(PartialEq)]
struct BranchTree(Vec<Rc<BranchNode>>);

impl BranchTree {
    fn new(doc: &Doc) -> Self {
        let Some(tree) = &doc.csaf.product_tree else {
            return Self(Vec::new());
        };

        let statuses = status_counts(doc);
        let mut by_id = RelationshipsById::new();
        for relationship in &tree.relationships {
            by_id
                .entry(relationship.product_reference.as_str())
                .or_default()
                .push(relationship);
            by_id
                .entry(relationship.relates_to_product_reference.as_str())
                .or_default()
                .push(relationship);
        }

        Self(
            tree.branches
                .as_ref()
                .map(|branches| {
                    branches
                        .0
                        .iter()
                        .map(|b| Rc::new(BranchNode::new(b, &by_id, &doc.index, &statuses)))
                        .collect()
                })
                .unwrap_or_default(),
        )
    }
}

impl TreeTableModel<BranchColumn> for BranchTree {
    fn children(&self) -> Vec<Rc<dyn TreeNode<BranchColumn>>> {
        self.0
            .iter()
            .map(|child| child.clone() as Rc<dyn TreeNode<BranchColumn>>)
            .collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelationshipColumn {
    Product,
    Category,
    ProductReference,
    RelatesTo,
}

/// A relationship of the product tree, by its position.
#[derive(Clone, PartialEq)]
struct RelationshipEntry {
    doc: Doc,
    n: usize,
}

impl TableEntryRenderer<RelationshipColumn> for RelationshipEntry {
    fn render_cell(&self, context: CellContext<'_, RelationshipColumn>) -> Cell {
        let index: &ProductIndex = &self.doc.index;
        let Some(relationship) = self
            .doc
            .csaf
            .product_tree
            .as_ref()
            .and_then(|tree| tree.relationships.get(self.n))
        else {
            return none().into();
        };

        match context.column {
            RelationshipColumn::Product => html! {
                <>
                    <code>{ relationship.full_product_name.product_id.to_string() }</code>
                    <br />
                    <small>{ relationship.full_product_name.name.to_string() }</small>
                </>
            }
            .into(),
            RelationshipColumn::Category => html!(relationship.category.to_string()).into(),
            RelationshipColumn::ProductReference => {
                product_ref(index, &relationship.product_reference).into()
            }
            RelationshipColumn::RelatesTo => {
                product_ref(index, &relationship.relates_to_product_reference).into()
            }
        }
    }
}

/// Compare two relationships by a column, ascending, by product ID.
fn compare(column: RelationshipColumn, a: &Relationship, b: &Relationship) -> Ordering {
    match column {
        RelationshipColumn::Product => text(
            &a.full_product_name.product_id,
            &b.full_product_name.product_id,
        ),
        RelationshipColumn::Category => text(&a.category.to_string(), &b.category.to_string()),
        RelationshipColumn::ProductReference => text(&a.product_reference, &b.product_reference),
        RelationshipColumn::RelatesTo => text(
            &a.relates_to_product_reference,
            &b.relates_to_product_reference,
        ),
    }
    .then_with(|| {
        text(
            &a.full_product_name.product_id,
            &b.full_product_name.product_id,
        )
    })
}

#[derive(Clone, PartialEq, Properties)]
struct RelationshipsProps {
    doc: Doc,
}

#[function_component(Relationships)]
fn relationships(props: &RelationshipsProps) -> Html {
    let total = props
        .doc
        .csaf
        .product_tree
        .as_ref()
        .map(|tree| tree.relationships.len())
        .unwrap_or_default();

    let pagination = use_pagination(Some(total), Default::default);
    let sort = use_sort::<RelationshipColumn>(None);

    // the positions of the relationships, in the sorted order
    let order = use_memo((props.doc.clone(), sort.sortby), |(doc, sortby)| {
        let relationships = doc
            .csaf
            .product_tree
            .as_ref()
            .map(|tree| tree.relationships.as_slice())
            .unwrap_or_default();
        let mut order = (0..relationships.len()).collect::<Vec<_>>();
        if let Some(sortby) = sortby {
            order.sort_by(
                |a, b| match (relationships.get(*a), relationships.get(*b)) {
                    (Some(a), Some(b)) => ordered(sortby.order, compare(sortby.index, a, b)),
                    _ => Ordering::Equal,
                },
            );
        }
        order
    });

    let entries = use_memo(
        (props.doc.clone(), order.clone(), pagination.state.range()),
        |(doc, order, range)| {
            order
                .get(range.clone())
                .unwrap_or_default()
                .iter()
                .map(|&n| RelationshipEntry {
                    doc: doc.clone(),
                    n,
                })
                .collect::<Vec<_>>()
        },
    );

    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<RelationshipColumn>>
            <TableColumn<RelationshipColumn> label="Product" index={RelationshipColumn::Product} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<RelationshipColumn> label="Category" index={RelationshipColumn::Category} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<RelationshipColumn> label="Product reference" index={RelationshipColumn::ProductReference} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<RelationshipColumn> label="Relates to" index={RelationshipColumn::RelatesTo} sortby={sort.sortby} onsort={sort.onsort.clone()} />
        </TableHeader<RelationshipColumn>>
    };

    html! {
        <>
            <SimplePagination pagination={pagination.clone()} total={total} />
            <Table<RelationshipColumn, UseTableData<RelationshipColumn, MemoizedTableModel<RelationshipEntry>>>
                mode={TableMode::Compact}
                {header}
                {entries}
            />
            <SimplePagination {pagination} {total} position={PaginationPosition::Bottom} />
        </>
    }
}

#[cfg(test)]
mod test {
    use super::{BranchNode, BranchProduct, BranchTree, RelationshipNode};
    use crate::advisory::csaf::parse;
    use std::rc::Rc;

    const DOCUMENT: &str = include_str!("../../../../etc/test-data/csaf/CVE-2024-5154.json");

    /// Find the branch defining a product.
    fn find<'a>(nodes: &'a [Rc<BranchNode>], id: &str) -> Option<&'a BranchNode> {
        nodes.iter().find_map(|node| {
            if node
                .product
                .as_ref()
                .is_some_and(|product| product.id == id)
            {
                Some(&**node)
            } else {
                find(&node.children, id)
            }
        })
    }

    #[test]
    fn branch_relationships() {
        let doc = parse(DOCUMENT).expect("document parses");
        let tree = BranchTree::new(&doc);

        // the component: the product reference of a relationship
        let component = find(&tree.0, "bpftool-0:4.18.0-372.109.1.el8_6.aarch64")
            .expect("component branch exists");
        assert_eq!(
            component.relationships,
            vec![Rc::new(RelationshipNode {
                category: "default_component_of".to_string(),
                outgoing: true,
                other_id: "8Base-RHOSE-4.12".to_string(),
                other_name: Some("Red Hat OpenShift Container Platform 4.12".to_string()),
                result: BranchProduct {
                    id: "8Base-RHOSE-4.12:bpftool-0:4.18.0-372.109.1.el8_6.aarch64".to_string(),
                    name: "bpftool-0:4.18.0-372.109.1.el8_6.aarch64 as a component of Red Hat OpenShift Container Platform 4.12".to_string(),
                    identifier: None,
                    // stated as known not affected
                    statuses: Some([0, 0, 0, 0, 1, 0, 0, 0]),
                },
            })]
        );
        // the component itself has no status
        assert_eq!(
            component.product.as_ref().map(|product| product.statuses),
            Some(None)
        );

        // the platform: the product other products relate to
        let platform = find(&tree.0, "8Base-RHOSE-4.12").expect("platform branch exists");
        assert_eq!(
            (
                platform.relationships.len(),
                platform.relationships.iter().all(|r| !r.outgoing)
            ),
            (158, true)
        );
    }
}
