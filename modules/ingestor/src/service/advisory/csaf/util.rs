use super::value::{self, OnInvalidData};
use crate::service::Error;
use csaf::schema::csaf2_0::schema::{
    Branch, BranchesT, CommonSecurityAdvisoryFramework as Csaf, FullProductNameT,
    HelperToIdentifyTheProduct, ProductTree, Relationship, Remediation,
};
use packageurl::PackageUrl;
use sbom_walker::report::ReportSink;
use std::collections::{BTreeSet, HashMap, HashSet};
use trustify_common::cpe::Cpe;

/// Extract and parse the purl of a branch, if it has one.
pub fn branch_purl(
    branch: &Branch,
    on_invalid: OnInvalidData,
    report: &dyn ReportSink,
) -> Result<Option<PackageUrl<'static>>, Error> {
    let Some(purl) = branch
        .product
        .as_ref()
        .and_then(|name| name.product_identification_helper.as_ref())
        .and_then(|helper| helper.purl.as_deref())
    else {
        return Ok(None);
    };

    on_invalid.validate(value::purl(purl), report)
}

/// Extract and parse the CPE of a branch, if it has one.
pub fn branch_cpe(
    branch: &Branch,
    on_invalid: OnInvalidData,
    report: &dyn ReportSink,
) -> Result<Option<Cpe>, Error> {
    let Some(cpe) = branch
        .product
        .as_ref()
        .and_then(|name| name.product_identification_helper.as_ref())
        .and_then(|helper| helper.cpe.as_deref())
    else {
        return Ok(None);
    };

    on_invalid.validate(value::cpe(cpe), report)
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

/// Resolves product IDs to their definitions.
///
/// CSAF defines a product in one of three places: a leaf of the branches, an entry of
/// `full_product_names`, or the `full_product_name` of a relationship (which combines two other
/// products).
#[derive(Debug)]
pub struct ResolveProductIdCache<'a> {
    /// A map from the full product name id, to the backtrace of branches
    full_product_name_to_backtrace: HashMap<&'a str, Vec<&'a Branch>>,
    /// Lookup from product IDs to their definition outside of branches: `full_product_names`, and
    /// the `full_product_name` of relationships
    product_id_to_definition: HashMap<&'a str, &'a FullProductNameT>,
    /// Lookup from product IDs to relationships
    product_id_to_relationship: HashMap<&'a str, &'a Relationship>,
    product_groups: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> ResolveProductIdCache<'a> {
    pub fn new(csaf: &'a Csaf) -> Self {
        // branches

        let mut cache = HashMap::<&'a str, Vec<&'a Branch>>::new();

        walk_product_tree_branches(&csaf.product_tree, |parents, branch| {
            if let Some(full_name) = &branch.product {
                let backtrace = parents.iter().copied().chain(Some(branch)).collect();
                cache.insert(full_name.product_id.as_str(), backtrace);
            }
        });

        // relationships

        let relationships = csaf.product_tree.iter().flat_map(|pt| &pt.relationships);

        let rels = relationships
            .clone()
            .map(|rel| (rel.full_product_name.product_id.as_str(), rel))
            .collect();

        // other definitions

        let definitions = csaf
            .product_tree
            .iter()
            .flat_map(|pt| &pt.full_product_names)
            .chain(relationships.map(|rel| &rel.full_product_name))
            .map(|name| (name.product_id.as_str(), name))
            .collect();

        // done

        Self {
            full_product_name_to_backtrace: cache,
            product_id_to_definition: definitions,
            product_id_to_relationship: rels,
            product_groups: csaf
                .product_tree
                .iter()
                .flat_map(|tree| &tree.product_groups)
                .map(|group| {
                    (
                        group.group_id.as_str(),
                        group.product_ids.iter().map(|id| id.as_str()).collect(),
                    )
                })
                .collect(),
        }
    }

    /// Resolve the union of direct and grouped remediation targets. Invalid references never
    /// widen a restricted remediation to all products.
    pub fn remediation_products<'r>(
        &'r self,
        remediation: &'r Remediation,
        report: &dyn ReportSink,
    ) -> BTreeSet<&'r str> {
        let mut products = remediation
            .product_ids
            .iter()
            .flat_map(|ids| ids.0.iter().map(|id| id.as_str()))
            .collect::<BTreeSet<_>>();
        for group in remediation.group_ids.iter().flat_map(|ids| &ids.0) {
            match self.product_groups.get(group.as_str()) {
                Some(members) => products.extend(members.iter().copied()),
                None => report.error(format!(
                    "unresolved remediation product group '{}'",
                    group.as_str()
                )),
            }
        }
        products.retain(|id| {
            let known = self.product_id_to_definition.contains_key(id)
                || self.full_product_name_to_backtrace.contains_key(id);
            if !known {
                report.error(format!("unresolved remediation product '{id}'"));
            }
            known
        });
        products
    }

    /// Find the backtrace, branches leading to that product ID.
    pub fn trace_product(&self, product_id: &str) -> &[&'a Branch] {
        self.full_product_name_to_backtrace
            .get(product_id)
            .map(|r| r.as_slice())
            .unwrap_or_else(|| &[])
    }

    /// The definition of a product outside of branches, in `full_product_names` or a relationship.
    pub fn definition(&self, product_id: &str) -> Option<&'a FullProductNameT> {
        self.product_id_to_definition.get(product_id).copied()
    }

    /// Get the relationship of a product (by ID).
    pub fn get_relationship(&self, product_id: &str) -> Option<&'a Relationship> {
        self.product_id_to_relationship.get(product_id).copied()
    }

    /// The products a product consists of, and whether each is a subject of a status of it.
    ///
    /// A product which isn't a relationship is just itself. A relationship consists of its
    /// platform (`relates_to_product_reference`, no subject), its component
    /// (`product_reference`), and itself, and each of those may again be a relationship. A
    /// status of the relationship is about the component, as part of the platform.
    ///
    /// The platform's parts come first, and the relationship itself last. A cyclic relationship
    /// (invalid CSAF, mandatory test 6.1.3) is resolved only once.
    pub fn parts(&self, product_id: &'a str) -> Vec<(&'a str, bool)> {
        let mut result = Vec::new();
        self.collect_parts(product_id, true, &mut HashSet::new(), &mut result);
        result
    }

    fn collect_parts(
        &self,
        product_id: &'a str,
        subject: bool,
        seen: &mut HashSet<&'a str>,
        result: &mut Vec<(&'a str, bool)>,
    ) {
        if !seen.insert(product_id) {
            return;
        }
        if let Some(rel) = self.get_relationship(product_id) {
            self.collect_parts(&rel.relates_to_product_reference, false, seen, result);
            self.collect_parts(&rel.product_reference, subject, seen, result);
        }
        result.push((product_id, subject));
    }

    /// The branch stating the version (or range) of a product: the leaf of its branches or, for
    /// a relationship, the one of its component.
    pub fn version_branch(&self, product_id: &str) -> Option<&'a Branch> {
        let mut seen = HashSet::new();
        let mut product_id = product_id;
        loop {
            if let Some(leaf) = self.trace_product(product_id).last() {
                return Some(leaf);
            }
            if !seen.insert(product_id) {
                return None;
            }
            product_id = &self.get_relationship(product_id)?.product_reference;
        }
    }

    /// The identification helpers of a product: the ones of the branches leading to it, or the
    /// one of its definition outside of branches.
    pub fn helpers(
        &self,
        product_id: &str,
    ) -> impl Iterator<Item = &'a HelperToIdentifyTheProduct> {
        let trace = self.trace_product(product_id);
        let definition = match trace.is_empty() {
            true => self.definition(product_id),
            false => None,
        };
        trace
            .iter()
            .filter_map(|branch| branch.product.as_ref())
            .chain(definition)
            .filter_map(|name| name.product_identification_helper.as_ref())
    }
}

pub fn gen_identifier(
    csaf: &Csaf,
    on_invalid: OnInvalidData,
    report: &dyn ReportSink,
) -> Result<String, Error> {
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

    // The namespace is a URL. Normalize it through `Url` so that identifiers stay stable:
    // CSAF carries it as a plain string, whereas it used to be a parsed `Url`, whose
    // `Display` adds a trailing slash to an empty path.
    let raw = &csaf.document.publisher.namespace;
    let namespace = match on_invalid.validate(value::url(raw), report)? {
        Some(namespace) => namespace.to_string(),
        None => raw.clone(),
    };

    Ok(format!("{namespace}#{file_name}"))
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    /// A product tree with a branch product `B`, full product names `F1` and `F2`, the
    /// relationship `R1` (`B` on `F1`), the nested relationship `R2` (`R1` on `F2`), and the
    /// cyclic relationships `C1` (`C2` on `F1`) and `C2` (`C1` on `F2`).
    fn csaf() -> Csaf {
        let rel = |id: &str, component: &str, platform: &str| {
            json!({
                "category": "installed_on",
                "full_product_name": { "name": id, "product_id": id },
                "product_reference": component,
                "relates_to_product_reference": platform,
            })
        };
        serde_json::from_value(json!({
            "document": {
                "category": "csaf_base",
                "csaf_version": "2.0",
                "publisher": {
                    "category": "vendor",
                    "name": "Example",
                    "namespace": "https://example.com",
                },
                "title": "Example",
                "tracking": {
                    "current_release_date": "2026-10-08T00:00:00Z",
                    "id": "EXAMPLE",
                    "initial_release_date": "2026-10-08T00:00:00Z",
                    "revision_history": [{
                        "date": "2026-10-08T00:00:00Z",
                        "number": "1",
                        "summary": "Initial version",
                    }],
                    "status": "final",
                    "version": "1",
                },
            },
            "product_tree": {
                "branches": [{
                    "category": "product_version",
                    "name": "1",
                    "product": { "name": "B", "product_id": "B" },
                }],
                "full_product_names": [
                    { "name": "F1", "product_id": "F1" },
                    { "name": "F2", "product_id": "F2" },
                ],
                "relationships": [
                    rel("R1", "B", "F1"),
                    rel("R2", "R1", "F2"),
                    rel("C1", "C2", "F1"),
                    rel("C2", "C1", "F2"),
                ],
            },
        }))
        .expect("valid CSAF")
    }

    #[rstest]
    #[case::branch("B", &[("B", true)])]
    #[case::full_product_name("F1", &[("F1", true)])]
    #[case::relationship("R1", &[("F1", false), ("B", true), ("R1", true)])]
    #[case::nested(
        "R2",
        &[("F2", false), ("F1", false), ("B", true), ("R1", true), ("R2", true)]
    )]
    #[case::cycle("C1", &[("F1", false), ("F2", false), ("C2", true), ("C1", true)])]
    fn parts(#[case] product_id: &str, #[case] expected: &[(&str, bool)]) {
        let csaf = csaf();
        let cache = ResolveProductIdCache::new(&csaf);
        assert_eq!(cache.parts(product_id), expected);
    }

    #[rstest]
    #[case::branch("B", Some("1"))]
    #[case::full_product_name("F1", None)]
    #[case::relationship("R1", Some("1"))]
    #[case::nested("R2", Some("1"))]
    #[case::cycle("C1", None)]
    fn version_branch(#[case] product_id: &str, #[case] expected: Option<&str>) {
        let csaf = csaf();
        let cache = ResolveProductIdCache::new(&csaf);
        assert_eq!(
            cache
                .version_branch(product_id)
                .map(|branch| branch.name.as_str()),
            expected
        );
    }

    #[rstest]
    #[case::branch("B", None)]
    #[case::full_product_name("F1", Some("F1"))]
    #[case::relationship("R1", Some("R1"))]
    #[case::unknown("X", None)]
    fn definition(#[case] product_id: &str, #[case] expected: Option<&str>) {
        let csaf = csaf();
        let cache = ResolveProductIdCache::new(&csaf);
        assert_eq!(
            cache
                .definition(product_id)
                .map(|name| name.product_id.as_str()),
            expected
        );
    }
}
