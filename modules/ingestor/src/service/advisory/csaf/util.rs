use csaf_rs::schema::csaf2_0::schema::{
    Branch, BranchesT, CommonSecurityAdvisoryFramework as Csaf, ProductIdT, ProductTree,
    Relationship,
};
use packageurl::PackageUrl;
use std::{collections::HashMap, str::FromStr};

pub fn branch_purl(branch: &Branch) -> Option<PackageUrl<'static>> {
    branch.product.as_ref().and_then(|name| {
        name.product_identification_helper
            .iter()
            .flat_map(|pih| pih.purl.as_ref())
            .map(|purl| PackageUrl::from_str(purl.as_str()).unwrap())
            .next()
    })
}

#[allow(dead_code)]
pub fn branch_cpe(branch: &Branch) -> Option<cpe::uri::OwnedUri> {
    branch.product.as_ref().and_then(|name| {
        name.product_identification_helper
            .iter()
            .flat_map(|pih| pih.cpe.as_ref())
            .map(|cpe| cpe::uri::OwnedUri::from_str(cpe.as_str()).unwrap())
            .next()
    })
}

/// Walk the product tree, calling the closure for every branch found.
#[allow(clippy::needless_lifetimes)]
pub fn walk_product_tree_branches<'a, F>(product_tree: &'a Option<ProductTree>, f: F)
where
    F: FnMut(&[&'a Branch], &'a Branch),
{
    if let Some(product_tree) = &product_tree {
        walk_product_branches(&product_tree.branches, f);
    }
}

/// Walk a list of branches, calling the closure for every branch found.
#[allow(clippy::needless_lifetimes)]
pub fn walk_product_branches<'a, F>(branches: &'a Option<BranchesT>, mut f: F)
where
    F: FnMut(&[&'a Branch], &'a Branch),
{
    let mut parents = vec![];
    walk_product_branches_ref(branches, &mut parents, &mut f)
}

/// Walk a list of branches, calling the closure for every branch found.
fn walk_product_branches_ref<'a, F>(
    branches: &'a Option<BranchesT>,
    parents: &mut Vec<&'a Branch>,
    f: &mut F,
) where
    F: FnMut(&[&'a Branch], &'a Branch),
{
    if let Some(branches) = &branches {
        for branch in &branches.0 {
            f(parents, branch);
            parents.push(branch);
            walk_product_branches_ref(&branch.branches, parents, f);
            parents.pop();
        }
    }
}

#[derive(Debug)]
pub struct ResolveProductIdCache<'a> {
    /// A map from the full product name id, to the backtrace of branches
    full_product_name_to_backtrace: HashMap<&'a ProductIdT, Vec<&'a Branch>>,
    /// Lookup from product IDs to relationships
    product_id_to_relationship: HashMap<&'a ProductIdT, &'a Relationship>,
}

impl<'a> ResolveProductIdCache<'a> {
    pub fn new(csaf: &'a Csaf) -> Self {
        // branches

        let mut cache = HashMap::<&'a ProductIdT, Vec<&'a Branch>>::new();

        walk_product_tree_branches(&csaf.product_tree, |parents, branch| {
            if let Some(full_name) = &branch.product {
                let backtrace = parents.iter().copied().chain(Some(branch)).collect();
                cache.insert(&full_name.product_id, backtrace);
            }
        });

        // relationships

        let rels = csaf
            .product_tree
            .iter()
            .flat_map(|pt| &pt.relationships)
            .map(|rel| (&rel.full_product_name.product_id, rel))
            .collect();

        // done

        Self {
            full_product_name_to_backtrace: cache,
            product_id_to_relationship: rels,
        }
    }

    /// Find the backtrace, branches leading to that product ID.
    pub fn trace_product(&self, product_id: &ProductIdT) -> &[&'a Branch] {
        self.full_product_name_to_backtrace
            .get(product_id)
            .map(|r| r.as_slice())
            .unwrap_or_else(|| &[])
    }

    /// Get the relationship of a product (by ID).
    pub fn get_relationship(&self, product_id: &ProductIdT) -> Option<&'a Relationship> {
        self.product_id_to_relationship.get(product_id).copied()
    }
}

pub fn gen_identifier(csaf: &Csaf) -> String {
    // From the spec:
    // > The combination of `/document/publisher/namespace` and `/document/tracking/id` identifies a CSAF document globally unique.

    let mut file_name = String::with_capacity(csaf.document.tracking.id.len());

    let mut in_sequence = false;
    for c in csaf.document.tracking.id.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '-' {
            file_name.push(c);
            in_sequence = false;
        } else if !in_sequence {
            file_name.push('_');
            in_sequence = true;
        }
    }

    format!("{}/#{file_name}", csaf.document.publisher.namespace)
}
