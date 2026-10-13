//! An index of the products a CSAF document defines.

use ::csaf::schema::csaf2_0::schema::{
    Branch, CommonSecurityAdvisoryFramework as Csaf, FullProductNameT, HelperToIdentifyTheProduct,
    RelationshipCategory,
};
use std::collections::HashMap;

/// How deep relationships of relationships are followed to find an identifier.
const MAX_RELATIONSHIP_DEPTH: usize = 8;

/// Where in the product tree a product is defined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProductOrigin {
    /// A leaf of the branches, with the names of the branches leading to it.
    Branch(Vec<String>),
    /// A full product name directly in the product tree.
    FullProductName,
    /// The product resulting from a relationship between two products.
    Relationship {
        category: RelationshipCategory,
        product_reference: String,
        relates_to: String,
    },
}

impl ProductOrigin {
    pub fn label(&self) -> String {
        match self {
            Self::Branch(_) => "Branch".into(),
            Self::FullProductName => "Full product name".into(),
            Self::Relationship { category, .. } => format!("Relationship: {category}"),
        }
    }
}

/// A product defined by a CSAF document.
#[derive(Clone, Debug)]
pub struct Product {
    pub id: String,
    pub name: String,
    pub helper: Option<HelperToIdentifyTheProduct>,
    pub origin: ProductOrigin,
}

impl Product {
    pub fn purl(&self) -> Option<&str> {
        self.helper.as_ref()?.purl.as_deref().map(String::as_str)
    }

    pub fn cpe(&self) -> Option<&str> {
        self.helper.as_ref()?.cpe.as_deref().map(String::as_str)
    }
}

/// The products and product groups of a CSAF document, by ID.
pub struct ProductIndex {
    products: Vec<Product>,
    by_id: HashMap<String, usize>,
    groups: HashMap<String, Vec<String>>,
}

impl ProductIndex {
    pub fn new(csaf: &Csaf) -> Self {
        let mut index = Self {
            products: Vec::new(),
            by_id: HashMap::new(),
            groups: HashMap::new(),
        };

        let Some(tree) = &csaf.product_tree else {
            return index;
        };

        if let Some(branches) = &tree.branches {
            index.add_branches(&branches.0, &mut Vec::new());
        }
        for product in &tree.full_product_names {
            index.add(product, ProductOrigin::FullProductName);
        }
        for relationship in &tree.relationships {
            index.add(
                &relationship.full_product_name,
                ProductOrigin::Relationship {
                    category: relationship.category,
                    product_reference: relationship.product_reference.to_string(),
                    relates_to: relationship.relates_to_product_reference.to_string(),
                },
            );
        }
        for group in &tree.product_groups {
            index.groups.insert(
                group.group_id.to_string(),
                group.product_ids.iter().map(|id| id.to_string()).collect(),
            );
        }

        index
    }

    fn add_branches(&mut self, branches: &[Branch], path: &mut Vec<String>) {
        for branch in branches {
            path.push(branch.name.to_string());
            if let Some(product) = &branch.product {
                self.add(product, ProductOrigin::Branch(path.clone()));
            }
            if let Some(children) = &branch.branches {
                self.add_branches(&children.0, path);
            }
            path.pop();
        }
    }

    fn add(&mut self, product: &FullProductNameT, origin: ProductOrigin) {
        let id = product.product_id.to_string();
        // A product ID must be unique. Should a document define it twice anyway, the first
        // definition is the one product references resolve to.
        self.by_id.entry(id.clone()).or_insert(self.products.len());
        self.products.push(Product {
            id,
            name: product.name.to_string(),
            helper: product.product_identification_helper.clone(),
            origin,
        });
    }

    /// All product definitions, in document order.
    pub fn products(&self) -> &[Product] {
        &self.products
    }

    pub fn get(&self, id: &str) -> Option<&Product> {
        self.by_id.get(id).map(|&n| &self.products[n])
    }

    /// The identifier of a product (its PURL, or else its CPE), and, for the product of a
    /// relationship without an identifier of its own, the identifier of the product it relates
    /// to (e.g. the platform a component is part of).
    ///
    /// A product of a relationship usually has no identification helper: the PURL is on the
    /// component, the CPE on the platform. Nested relationships are followed up to a fixed depth.
    pub fn identifiers(&self, id: &str) -> (Option<&str>, Option<&str>) {
        self.identifiers_at(id, MAX_RELATIONSHIP_DEPTH)
    }

    fn identifiers_at(&self, id: &str, depth: usize) -> (Option<&str>, Option<&str>) {
        let Some(product) = self.get(id) else {
            return (None, None);
        };
        if let Some(own) = product.purl().or(product.cpe()) {
            return (Some(own), None);
        }
        match &product.origin {
            ProductOrigin::Relationship {
                product_reference,
                relates_to,
                ..
            } if depth > 0 => (
                self.identifiers_at(product_reference, depth - 1).0,
                self.identifiers_at(relates_to, depth - 1).0,
            ),
            _ => (None, None),
        }
    }

    /// The product IDs of a product group.
    pub fn group(&self, id: &str) -> Option<&[String]> {
        self.groups.get(id).map(Vec::as_slice)
    }

    /// Resolve product IDs and product group IDs into a list of product IDs.
    pub fn resolve<'a>(
        &'a self,
        product_ids: impl IntoIterator<Item = &'a str>,
        group_ids: impl IntoIterator<Item = &'a str>,
    ) -> Vec<String> {
        let mut result = product_ids
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        for group in group_ids {
            result.extend(self.group(group).unwrap_or_default().iter().cloned());
        }
        result
    }
}
