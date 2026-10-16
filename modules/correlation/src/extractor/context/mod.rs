//! Product context scoping of evidence.
//!
//! An advisory states most assertions about a component *in a product* (its context, see
//! `assertion_context`). A node of an SBOM is put into products by the CPEs around it: its own,
//! the ones of its ancestors in the SBOM, the SBOM's describing CPEs, and the describing CPEs of
//! ancestor SBOMs. Like the RPM stream scoping, an assertion is kept for a node whose contexts
//! match, dropped for one whose contexts are comparable but don't match, and kept unscoped
//! otherwise, unless it requires a context (e.g. a versionless statement, which identifies the
//! package only through its product).
//!
//! The confidence of a context match depends on how close the context is to the node: its own
//! CPE is most specific, the describing CPE of an ancestor SBOM the least.

use crate::{
    error::Error,
    extractor::{Assertion, NodeRef},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, FromQueryResult, QueryFilter, Statement,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tracing::{Instrument, info_span};
use trustify_common::purl::Purl;
use trustify_entity::{
    assertion_context, assertion_context_identifier,
    assertion_context_identifier::ContextIdentifierKind,
    correlation_evidence_context::ContextSource, cpe, qualified_purl, sbom_node_purl_ref,
};
use uuid::Uuid;

pub(super) mod rpm;

/// Confidence of a context of the node's own CPE.
const NODE: f64 = 1.0;
/// Confidence of a context of an ancestor node's CPE at distance 1, decreasing per hop.
const ANCESTOR_NODE: (f64, f64, f64) = (0.9, 0.05, 0.7);
/// Confidence of a context of the SBOM's describing CPE.
const DESCRIBING: f64 = 0.8;
/// Confidence of a context of an ancestor SBOM's describing CPE at 1 hop, decreasing per hop.
const ANCESTOR_SBOM: (f64, f64, f64) = (0.7, 0.05, 0.5);
/// Confidence of a context of an RPM's product, stated by the `distro=` qualifier of its PURL.
const PURL_QUALIFIER: f64 = 0.85;
/// Confidence of a context of an RPM's product, inferred from its release.
const PURL_RELEASE: f64 = 0.75;
/// Factor of an assertion stated in a product, on a node whose product can't be compared.
const UNCHECKED: f64 = 0.7;
/// Factor of a match through an ANY attribute (instead of equal values).
const ANY_MATCH: f64 = 0.9;

/// Number of values per query.
const CHUNK: usize = 5000;

/// Depth limit of the ancestor walks (within an SBOM, and across SBOMs).
const MAX_DEPTH: i32 = 16;

/// A CPE putting a node into a product, and how it got there.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeCpe {
    pub cpe: cpe::Model,
    pub source: ContextSource,
    /// Hops to the node (ancestor node) or SBOM (ancestor SBOM), 0 otherwise.
    pub distance: i32,
}

impl NodeCpe {
    /// The confidence of a context from this CPE.
    pub fn confidence(&self) -> f64 {
        let decreasing = |(start, step, min): (f64, f64, f64)| {
            (start - step * f64::from((self.distance - 1).max(0))).max(min)
        };
        match self.source {
            ContextSource::Node => NODE,
            ContextSource::AncestorNode => decreasing(ANCESTOR_NODE),
            ContextSource::Describing => DESCRIBING,
            ContextSource::AncestorSbom => decreasing(ANCESTOR_SBOM),
            ContextSource::PurlQualifier => PURL_QUALIFIER,
            ContextSource::PurlRelease => PURL_RELEASE,
        }
    }
}

/// An assertion context, with its CPEs.
#[derive(Clone, Debug, PartialEq)]
pub struct AssertionContext {
    pub context: assertion_context::Model,
    pub cpes: Vec<cpe::Model>,
}

/// A context of an assertion matched by a node CPE.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextLink {
    pub context_id: Uuid,
    pub source: ContextSource,
    pub distance: i32,
    pub node_identifier: String,
    pub context_identifier: String,
    pub confidence: f64,
}

/// The outcome of scoping an assertion by context.
#[derive(Clone, Debug, PartialEq)]
pub enum Scope {
    /// The node is in the assertion's context, with the best confidence of the links.
    Matched {
        confidence: f64,
        links: Vec<ContextLink>,
    },
    /// Nothing to compare: no context on either side, or nothing comparable. The confidence is
    /// lower for an assertion stated in a product which couldn't be checked.
    Unscoped { confidence: f64 },
    /// The contexts are comparable, but don't match, or a required context is missing.
    Dropped,
}

/// Scope an assertion with the given context against the CPEs of a node.
pub fn scope(
    context: Option<&AssertionContext>,
    node: &[NodeCpe],
    requires_context: bool,
) -> Scope {
    let unscoped = |confidence| match requires_context {
        true => Scope::Dropped,
        false => Scope::Unscoped { confidence },
    };
    // an assertion without a context isn't about a product
    let Some(context) = context else {
        return unscoped(1.0);
    };

    let mut links = Vec::new();
    let mut comparable = false;
    for context_cpe in &context.cpes {
        for node_cpe in node {
            let factor = match cpe_match(context_cpe, &node_cpe.cpe) {
                CpeMatch::Exact => 1.0,
                CpeMatch::Any => ANY_MATCH,
                CpeMatch::Different => {
                    comparable = true;
                    continue;
                }
                CpeMatch::Unrelated => continue,
            };
            links.push(ContextLink {
                context_id: context.context.id,
                source: node_cpe.source,
                distance: node_cpe.distance,
                node_identifier: format_cpe(&node_cpe.cpe),
                context_identifier: format_cpe(context_cpe),
                confidence: round(node_cpe.confidence() * factor),
            });
        }
    }

    if links.is_empty() {
        return match comparable {
            true => Scope::Dropped,
            false => unscoped(UNCHECKED),
        };
    }

    // the best link per node CPE, sorted for stable results
    links.sort_by(|a, b| {
        (&a.node_identifier, &a.context_identifier)
            .cmp(&(&b.node_identifier, &b.context_identifier))
            .then(b.confidence.total_cmp(&a.confidence))
    });
    links.dedup_by(|a, b| {
        a.node_identifier == b.node_identifier && a.context_identifier == b.context_identifier
    });
    let confidence = links.iter().map(|link| link.confidence).fold(0.0, f64::max);
    Scope::Matched { confidence, links }
}

/// Round a confidence to two digits, like the rule confidences.
pub fn round(confidence: f64) -> f64 {
    (confidence * 100.0).round() / 100.0
}

/// How a context CPE relates to a node CPE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpeMatch {
    /// All attributes are equal (or match the context's pattern).
    Exact,
    /// All attributes match, at least one through ANY on either side.
    Any,
    /// The same product (part, vendor and product), but different otherwise.
    Different,
    /// Different products, not comparable.
    Unrelated,
}

fn cpe_match(context: &cpe::Model, node: &cpe::Model) -> CpeMatch {
    let identity = [
        (&context.part, &node.part),
        (&context.vendor, &node.vendor),
        (&context.product, &node.product),
    ];
    let rest = [
        (&context.update, &node.update),
        (&context.edition, &node.edition),
        (&context.language, &node.language),
        (&context.sw_edition, &node.sw_edition),
        (&context.target_sw, &node.target_sw),
        (&context.target_hw, &node.target_hw),
        (&context.other, &node.other),
    ];

    let mut any = false;
    for (context, node) in identity {
        match attribute_match(context.as_deref(), node.as_deref()) {
            AttributeMatch::Equal => {}
            AttributeMatch::Any => any = true,
            AttributeMatch::Different => return CpeMatch::Unrelated,
        }
    }
    let version = version_match(context.version.as_deref(), node.version.as_deref());
    for result in [version].into_iter().chain(
        rest.into_iter()
            .map(|(context, node)| attribute_match(context.as_deref(), node.as_deref())),
    ) {
        match result {
            AttributeMatch::Equal => {}
            AttributeMatch::Any => any = true,
            AttributeMatch::Different => return CpeMatch::Different,
        }
    }
    match any {
        true => CpeMatch::Any,
        false => CpeMatch::Exact,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttributeMatch {
    Equal,
    Any,
    Different,
}

/// Match a context CPE attribute against a node CPE attribute.
///
/// Unlike matching an advisory CPE pattern (`cpe_attribute_matches`), ANY on either side matches:
/// an SBOM's CPE is often less specific than the advisory's (e.g. `enterprise_linux:8` vs
/// `enterprise_linux:8::baseos`). `None` is NA, `*` is ANY, other values compare case
/// insensitively, with `*` and `?` wildcards in the context's value.
fn attribute_match(context: Option<&str>, node: Option<&str>) -> AttributeMatch {
    match (context, node) {
        (Some("*"), Some("*")) => AttributeMatch::Equal,
        (Some("*"), _) | (_, Some("*")) => AttributeMatch::Any,
        (None, None) => AttributeMatch::Equal,
        (Some(context), Some(node)) if wildcard_match(context, node) => AttributeMatch::Equal,
        _ => AttributeMatch::Different,
    }
}

/// Match the version attributes: like [`attribute_match`], but a major version matches its minor
/// versions through ANY (e.g. `10` and `10.1`), as it is less specific. Red Hat states RHEL 10
/// mainline products with their minor (`enterprise_linux:10.1`), while an RPM only names the
/// major. Different minors (`10.1` and `10.2`) still differ.
fn version_match(context: Option<&str>, node: Option<&str>) -> AttributeMatch {
    let is_minor_of = |minor: &str, major: &str| {
        !major.is_empty()
            && major.bytes().all(|b| b.is_ascii_digit())
            && minor
                .strip_prefix(major)
                .is_some_and(|rest| rest.starts_with('.'))
    };
    match (context, node) {
        (Some(context), Some(node)) if is_minor_of(context, node) || is_minor_of(node, context) => {
            AttributeMatch::Any
        }
        _ => attribute_match(context, node),
    }
}

/// Case insensitive match with `*` (any number of characters) and `?` (one character).
fn wildcard_match(pattern: &str, value: &str) -> bool {
    fn matches(pattern: &[char], value: &[char]) -> bool {
        match (pattern.first(), value.first()) {
            (None, None) => true,
            (Some('*'), _) => {
                matches(&pattern[1..], value)
                    || (!value.is_empty() && matches(pattern, &value[1..]))
            }
            (Some('?'), Some(_)) => matches(&pattern[1..], &value[1..]),
            (Some(p), Some(v)) if p == v => matches(&pattern[1..], &value[1..]),
            _ => false,
        }
    }
    let pattern = pattern.to_lowercase().chars().collect::<Vec<_>>();
    let value = value.to_lowercase().chars().collect::<Vec<_>>();
    matches(&pattern, &value)
}

/// A CPE in its 2.3 formatted string form.
pub fn format_cpe(model: &cpe::Model) -> String {
    let component = |value: &Option<String>| match value.as_deref() {
        None => "-".to_string(),
        Some(value) => value.to_string(),
    };
    format!(
        "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        model.part.as_deref().unwrap_or("*"),
        component(&model.vendor),
        component(&model.product),
        component(&model.version),
        component(&model.update),
        component(&model.edition),
        component(&model.language),
        component(&model.sw_edition),
        component(&model.target_sw),
        component(&model.target_hw),
        component(&model.other),
    )
}

/// Load assertion contexts, with their CPEs.
pub async fn load_contexts<C: ConnectionTrait>(
    ids: impl IntoIterator<Item = Uuid>,
    connection: &C,
) -> Result<HashMap<Uuid, AssertionContext>, Error> {
    let ids = ids.into_iter().collect::<Vec<_>>();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut contexts = Vec::new();
    for chunk in ids.chunks(CHUNK) {
        contexts.extend(
            assertion_context::Entity::find()
                .filter(assertion_context::Column::Id.is_in(chunk.iter().copied()))
                .find_with_related(assertion_context_identifier::Entity)
                .all(connection)
                .instrument(info_span!("loading assertion contexts"))
                .await?,
        );
    }

    let cpe_ids = contexts
        .iter()
        .flat_map(|(_, identifiers)| identifiers)
        .filter(|identifier| identifier.kind == ContextIdentifierKind::Cpe)
        .filter_map(|identifier| identifier.cpe_id)
        .collect::<Vec<_>>();
    let mut cpes = HashMap::new();
    for chunk in cpe_ids.chunks(CHUNK) {
        cpes.extend(
            cpe::Entity::find()
                .filter(cpe::Column::Id.is_in(chunk.iter().copied()))
                .all(connection)
                .instrument(info_span!("loading assertion context CPEs"))
                .await?
                .into_iter()
                .map(|cpe| (cpe.id, cpe)),
        );
    }

    Ok(contexts
        .into_iter()
        .map(|(context, identifiers)| {
            let cpes = identifiers
                .iter()
                .filter_map(|identifier| identifier.cpe_id)
                .filter_map(|id| cpes.get(&id).cloned())
                .collect();
            (context.id, AssertionContext { context, cpes })
        })
        .collect())
}

/// Relationships from a parent (left) to a child (right) node, by their stored value: contains,
/// the dependencies, ancestor of, variant, and describes.
const PARENT_RELATIONSHIPS: &str = "0, 1, 2, 3, 4, 5, 6, 9, 10, 13";

#[derive(FromQueryResult)]
struct NodeCpeRow {
    sbom_id: Uuid,
    node_id: String,
    source: ContextSource,
    distance: i32,
    #[sea_orm(nested)]
    cpe: cpe::Model,
}

/// The CPEs putting the given nodes into products: from the CPEs around them, and from their
/// own PURL (an RPM's product, see [`rpm`]).
pub async fn load_node_cpes<C: ConnectionTrait>(
    nodes: impl IntoIterator<Item = NodeRef>,
    connection: &C,
) -> Result<BTreeMap<NodeRef, Vec<NodeCpe>>, Error> {
    let nodes = nodes.into_iter().collect::<BTreeSet<_>>();
    if nodes.is_empty() {
        return Ok(BTreeMap::new());
    }
    let (sboms, node_ids): (Vec<_>, Vec<_>) = nodes
        .iter()
        .map(|node| (node.sbom_id, node.node_id.clone()))
        .unzip();

    // SAFETY: only constants are interpolated, the values are bound.
    let sql = format!(
        r#"
WITH RECURSIVE
node AS (
    SELECT DISTINCT * FROM unnest($1::uuid[], $2::text[]) AS n(sbom_id, node_id)
),
up(sbom_id, node_id, ancestor_id, distance) AS (
    SELECT sbom_id, node_id, node_id, 0 FROM node
    UNION
    SELECT up.sbom_id, up.node_id, r.left_node_id, up.distance + 1
    FROM up
    JOIN package_relates_to_package r
      ON r.sbom_id = up.sbom_id AND r.right_node_id = up.ancestor_id
    WHERE r.relationship IN ({PARENT_RELATIONSHIPS}) AND up.distance < {MAX_DEPTH}
),
ancestor_sbom(sbom_id, ancestor_sbom_id, hops) AS (
    SELECT a.sbom_id, a.ancestor_sbom_id, 1
    FROM sbom_ancestor a JOIN (SELECT DISTINCT sbom_id FROM node) s ON s.sbom_id = a.sbom_id
    UNION
    SELECT anc.sbom_id, a.ancestor_sbom_id, anc.hops + 1
    FROM ancestor_sbom anc JOIN sbom_ancestor a ON a.sbom_id = anc.ancestor_sbom_id
    WHERE anc.hops < {MAX_DEPTH}
),
found(sbom_id, node_id, source, distance, cpe_id) AS (
    SELECT up.sbom_id, up.node_id,
           CASE WHEN up.distance = 0 THEN 'node' ELSE 'ancestor_node' END::correlation_context_source,
           up.distance, ref.cpe_id
    FROM up
    JOIN sbom_node_cpe_ref ref ON ref.sbom_id = up.sbom_id AND ref.node_id = up.ancestor_id
    UNION ALL
    SELECT node.sbom_id, node.node_id, 'describing'::correlation_context_source, 0, d.cpe_id
    FROM node JOIN sbom_describing_cpe d ON d.sbom_id = node.sbom_id
    UNION ALL
    SELECT node.sbom_id, node.node_id, 'ancestor_sbom'::correlation_context_source, anc.hops,
           d.cpe_id
    FROM node
    JOIN ancestor_sbom anc ON anc.sbom_id = node.sbom_id
    JOIN sbom_describing_cpe d ON d.sbom_id = anc.ancestor_sbom_id
)
SELECT f.sbom_id, f.node_id, f.source::text AS source, min(f.distance)::int4 AS distance,
       c.*
FROM found f JOIN cpe c ON c.id = f.cpe_id
GROUP BY f.sbom_id, f.node_id, f.source, c.id
"#
    );

    let rows = NodeCpeRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        [sboms.into(), node_ids.into()],
    ))
    .all(connection)
    .instrument(info_span!("loading node contexts"))
    .await?;

    let mut result = BTreeMap::<NodeRef, Vec<NodeCpe>>::new();
    for row in rows {
        result
            .entry(NodeRef {
                sbom_id: row.sbom_id,
                node_id: row.node_id,
            })
            .or_default()
            .push(NodeCpe {
                cpe: row.cpe,
                source: row.source,
                distance: row.distance,
            });
    }

    for (node, (cpe, source)) in load_rpm_contexts(&nodes, connection).await? {
        result.entry(node).or_default().push(NodeCpe {
            cpe,
            source,
            distance: 0,
        });
    }

    Ok(result)
}

/// The products of the RPMs among the given nodes, by their PURLs.
async fn load_rpm_contexts<C: ConnectionTrait>(
    nodes: &BTreeSet<NodeRef>,
    connection: &C,
) -> Result<Vec<(NodeRef, (cpe::Model, ContextSource))>, Error> {
    let sbom_ids = nodes
        .iter()
        .map(|node| node.sbom_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let node_ids = nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let mut result = Vec::new();
    for sbom_chunk in sbom_ids.chunks(CHUNK) {
        for node_chunk in node_ids.chunks(CHUNK) {
            // the cross product of SBOMs and nodes is a superset, filtered below
            let refs = sbom_node_purl_ref::Entity::find()
                .filter(sbom_node_purl_ref::Column::SbomId.is_in(sbom_chunk.iter().copied()))
                .filter(sbom_node_purl_ref::Column::NodeId.is_in(node_chunk.iter().copied()))
                .find_also_related(qualified_purl::Entity)
                .all(connection)
                .instrument(info_span!("loading node purls"))
                .await?;
            for (purl_ref, qualified) in refs {
                let node = NodeRef {
                    sbom_id: purl_ref.sbom_id,
                    node_id: purl_ref.node_id,
                };
                if !nodes.contains(&node) {
                    continue;
                }
                if let Some(context) =
                    qualified.and_then(|qualified| rpm::rpm_context(&Purl::from(qualified.purl)))
                {
                    result.push((node, context));
                }
            }
        }
    }
    Ok(result)
}

/// Scopes the assertions of an extraction by context, loading (and caching) the contexts of the
/// assertions and the CPEs of the nodes as needed.
#[derive(Default)]
pub struct Scoper {
    contexts: HashMap<Uuid, AssertionContext>,
    node_cpes: BTreeMap<NodeRef, Vec<NodeCpe>>,
}

impl Scoper {
    /// Load what's needed to scope the given matches.
    pub async fn prepare<'a, C: ConnectionTrait>(
        &mut self,
        matches: impl IntoIterator<Item = (&'a NodeRef, &'a Assertion)>,
        connection: &C,
    ) -> Result<(), Error> {
        let mut contexts = Vec::new();
        let mut nodes = Vec::new();
        for (node, assertion) in matches {
            // without a context, there is nothing to compare
            let Some(context_id) = assertion.context_id else {
                continue;
            };
            if !self.contexts.contains_key(&context_id) {
                contexts.push(context_id);
            }
            if !self.node_cpes.contains_key(node) {
                nodes.push(node.clone());
            }
        }
        contexts.sort_unstable();
        contexts.dedup();
        nodes.sort_unstable();
        nodes.dedup();

        self.contexts
            .extend(load_contexts(contexts, connection).await?);
        // nodes without CPEs are cached too, as having none
        let mut loaded = load_node_cpes(nodes.iter().cloned(), connection).await?;
        for node in nodes {
            let cpes = loaded.remove(&node).unwrap_or_default();
            self.node_cpes.insert(node, cpes);
        }
        Ok(())
    }

    /// Scope a match, see [`scope`]. The matches must have been [prepared](Self::prepare).
    pub fn scope(&self, node: &NodeRef, assertion: &Assertion) -> Scope {
        let context = assertion
            .context_id
            .and_then(|context_id| self.contexts.get(&context_id));
        let node_cpes = self
            .node_cpes
            .get(node)
            .map(Vec::as_slice)
            .unwrap_or_default();
        scope(context, node_cpes, assertion.requires_context)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;
    use trustify_common::cpe::Cpe;

    fn cpe(value: &str) -> cpe::Model {
        let model: cpe::ActiveModel = Cpe::from_str(value).expect("valid CPE").into();
        cpe::Model {
            id: model.id.unwrap(),
            part: model.part.unwrap(),
            vendor: model.vendor.unwrap(),
            product: model.product.unwrap(),
            version: model.version.unwrap(),
            update: model.update.unwrap(),
            edition: model.edition.unwrap(),
            language: model.language.unwrap(),
            sw_edition: model.sw_edition.unwrap(),
            target_sw: model.target_sw.unwrap(),
            target_hw: model.target_hw.unwrap(),
            other: model.other.unwrap(),
        }
    }

    fn context(cpes: &[&str]) -> AssertionContext {
        AssertionContext {
            context: assertion_context::Model {
                id: Uuid::nil(),
                category: None,
                name: "product".into(),
            },
            cpes: cpes.iter().map(|value| cpe(value)).collect(),
        }
    }

    fn node(value: &str, source: ContextSource, distance: i32) -> NodeCpe {
        NodeCpe {
            cpe: cpe(value),
            source,
            distance,
        }
    }

    #[rstest]
    #[case::equal("cpe:/a:redhat:storage:3", "cpe:/a:redhat:storage:3", CpeMatch::Exact)]
    #[case::node_less_specific(
        "cpe:/o:redhat:enterprise_linux:8::baseos",
        "cpe:/o:redhat:enterprise_linux:8",
        CpeMatch::Any
    )]
    #[case::context_less_specific(
        "cpe:/o:redhat:enterprise_linux",
        "cpe:/o:redhat:enterprise_linux:8",
        CpeMatch::Any
    )]
    #[case::other_version(
        "cpe:/o:redhat:enterprise_linux:8",
        "cpe:/o:redhat:enterprise_linux:9",
        CpeMatch::Different
    )]
    #[case::node_major(
        "cpe:/o:redhat:enterprise_linux:10.1",
        "cpe:/o:redhat:enterprise_linux:10",
        CpeMatch::Any
    )]
    #[case::context_major(
        "cpe:/o:redhat:enterprise_linux:10",
        "cpe:/o:redhat:enterprise_linux:10.1",
        CpeMatch::Any
    )]
    #[case::other_minor(
        "cpe:/o:redhat:enterprise_linux:10.1",
        "cpe:/o:redhat:enterprise_linux:10.2",
        CpeMatch::Different
    )]
    #[case::other_major_prefix(
        "cpe:/o:redhat:enterprise_linux:1.1",
        "cpe:/o:redhat:enterprise_linux:10",
        CpeMatch::Different
    )]
    #[case::case_insensitive("cpe:/a:RedHat:Storage:3", "cpe:/a:redhat:storage:3", CpeMatch::Exact)]
    #[case::other_product(
        "cpe:/o:redhat:enterprise_linux:8",
        "cpe:/a:redhat:openshift:4.15",
        CpeMatch::Unrelated
    )]
    #[case::other_part(
        "cpe:/h:phoenix_contact:catan_c1",
        "cpe:/o:phoenix_contact:catan_c1",
        CpeMatch::Unrelated
    )]
    fn cpe_matching(#[case] context: &str, #[case] node: &str, #[case] expected: CpeMatch) {
        assert_eq!(cpe_match(&cpe(context), &cpe(node)), expected);
    }

    #[rstest]
    #[case::node(ContextSource::Node, 0, 1.0)]
    #[case::parent(ContextSource::AncestorNode, 1, 0.9)]
    #[case::grandparent(ContextSource::AncestorNode, 2, 0.85)]
    #[case::far(ContextSource::AncestorNode, 10, 0.7)]
    #[case::describing(ContextSource::Describing, 0, 0.8)]
    #[case::ancestor_sbom(ContextSource::AncestorSbom, 1, 0.7)]
    #[case::purl_qualifier(ContextSource::PurlQualifier, 0, 0.85)]
    #[case::purl_release(ContextSource::PurlRelease, 0, 0.75)]
    #[case::far_ancestor_sbom(ContextSource::AncestorSbom, 9, 0.5)]
    fn proximity(#[case] source: ContextSource, #[case] distance: i32, #[case] expected: f64) {
        let confidence = node("cpe:/a:a:b", source, distance).confidence();
        assert_eq!(round(confidence), expected);
    }

    /// The best of several matching node CPEs wins, a less specific match counts less.
    #[test]
    fn matched() {
        let result = scope(
            Some(&context(&["cpe:/o:redhat:enterprise_linux:8::baseos"])),
            &[
                node("cpe:/o:redhat:enterprise_linux:8", ContextSource::Node, 0),
                node(
                    "cpe:/o:redhat:enterprise_linux:8::baseos",
                    ContextSource::Describing,
                    0,
                ),
            ],
            false,
        );
        let Scope::Matched { confidence, links } = result else {
            panic!("must match: {result:?}");
        };
        // own CPE (1.0) through ANY (0.9) beats the exact describing CPE (0.8)
        assert_eq!(confidence, 0.9);
        assert_eq!(
            links
                .iter()
                .map(|link| (link.source, link.confidence))
                .collect::<Vec<_>>(),
            [(ContextSource::Node, 0.9), (ContextSource::Describing, 0.8)]
        );
    }

    /// Not matched: dropped (`None`), or kept unscoped with a confidence factor.
    #[rstest]
    // comparable, but different
    #[case::mismatch(Some(&["cpe:/o:redhat:enterprise_linux:8"][..]), &["cpe:/o:redhat:enterprise_linux:9"][..], false, None)]
    // nothing comparable: a container of another product keeps the RHEL statement, unchecked
    #[case::unrelated(Some(&["cpe:/o:redhat:enterprise_linux:9"][..]), &["cpe:/a:redhat:openshift:4.15"][..], false, Some(UNCHECKED))]
    #[case::unrelated_required(Some(&["cpe:/o:redhat:enterprise_linux:9"][..]), &["cpe:/a:redhat:openshift:4.15"][..], true, None)]
    // no context on the node
    #[case::no_node_context(Some(&["cpe:/a:redhat:storage:3"][..]), &[][..], false, Some(UNCHECKED))]
    #[case::no_node_context_required(Some(&["cpe:/a:redhat:storage:3"][..]), &[][..], true, None)]
    // no context on the assertion: not about a product
    #[case::no_assertion_context(None, &["cpe:/a:redhat:storage:3"][..], false, Some(1.0))]
    #[case::no_assertion_context_required(None, &["cpe:/a:redhat:storage:3"][..], true, None)]
    // an SLE 15 SP6 RPM: another service pack, another product
    #[case::suse_other_sp(Some(&["cpe:/o:suse:sles:12:sp2"][..]), &["cpe:/o:suse::15:sp6"][..], true, None)]
    #[case::suse_tumbleweed(Some(&["cpe:/o:opensuse:tumbleweed"][..]), &["cpe:/o:suse::15:sp6"][..], false, Some(UNCHECKED))]
    fn not_matched(
        #[case] assertion: Option<&[&str]>,
        #[case] node_cpes: &[&str],
        #[case] requires_context: bool,
        #[case] kept: Option<f64>,
    ) {
        let assertion = assertion.map(context);
        let node_cpes = node_cpes
            .iter()
            .map(|value| node(value, ContextSource::Describing, 0))
            .collect::<Vec<_>>();
        let expected = match kept {
            Some(confidence) => Scope::Unscoped { confidence },
            None => Scope::Dropped,
        };
        assert_eq!(
            scope(assertion.as_ref(), &node_cpes, requires_context),
            expected
        );
    }

    /// An SLE 15 SP6 RPM (by its PURL) is in every product of that service pack.
    #[test]
    fn suse_service_pack() {
        let result = scope(
            Some(&context(&[
                "cpe:/o:suse:sles:15:sp6",
                "cpe:/o:suse:sle-module-basesystem:15:sp6",
            ])),
            &[node("cpe:/o:suse::15:sp6", ContextSource::PurlQualifier, 0)],
            true,
        );
        let Scope::Matched { confidence, links } = result else {
            panic!("must match: {result:?}");
        };
        // the qualifier (0.85), through ANY (0.9)
        assert_eq!(confidence, 0.77);
        assert_eq!(links.len(), 2);
    }

    /// The CPEs putting nodes into products: their own, their ancestors' (by distance, also
    /// through a dependency cycle), the describing CPE, and an ancestor SBOM's describing CPE.
    #[test_context::test_context(trustify_test_context::TrustifyContext)]
    #[test_log::test(actix_web::test)]
    async fn node_cpes(ctx: &trustify_test_context::TrustifyContext) -> anyhow::Result<()> {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};
        use trustify_entity::sbom_ancestor;

        let child = Uuid::parse_str(
            &ctx.ingest_document("correlation/context/child.cdx.json")
                .await?
                .id,
        )?;
        let parent = Uuid::parse_str(
            &ctx.ingest_document("correlation/context/parent.cdx.json")
                .await?
                .id,
        )?;
        sbom_ancestor::ActiveModel {
            sbom_id: Set(child),
            ancestor_sbom_id: Set(parent),
        }
        .insert(&ctx.db)
        .await?;

        let node = |node_id: &str| NodeRef {
            sbom_id: child,
            node_id: node_id.into(),
        };
        let result = load_node_cpes(
            [
                node("app"),
                node("helper"),
                node("rpm-distro"),
                node("rpm-release"),
            ],
            &ctx.db,
        )
        .await?;
        let cpes = |node_id: &str| {
            let mut cpes = result
                .get(&node(node_id))
                .into_iter()
                .flatten()
                .map(|cpe| (cpe.source, cpe.distance, format_cpe(&cpe.cpe)))
                .collect::<Vec<_>>();
            cpes.sort();
            cpes
        };

        let cpe = |product: &str| format!("cpe:2.3:{product}:*:*:*:*:*:*:*");
        assert_eq!(
            cpes("app"),
            [
                (ContextSource::Node, 0, cpe("a:example:app:2")),
                (ContextSource::AncestorNode, 1, cpe("a:example:product:1")),
                (ContextSource::Describing, 0, cpe("a:example:product:1")),
                (ContextSource::AncestorSbom, 1, cpe("o:example:platform:5")),
            ]
        );
        assert_eq!(
            cpes("helper"),
            [
                (ContextSource::AncestorNode, 2, cpe("a:example:app:2")),
                (ContextSource::AncestorNode, 3, cpe("a:example:product:1")),
                (ContextSource::Describing, 0, cpe("a:example:product:1")),
                (ContextSource::AncestorSbom, 1, cpe("o:example:platform:5")),
            ]
        );

        // RPMs: their product by the PURL's qualifier, or else the release
        assert_eq!(
            cpes("rpm-distro"),
            [
                (ContextSource::AncestorNode, 1, cpe("a:example:product:1")),
                (ContextSource::Describing, 0, cpe("a:example:product:1")),
                (ContextSource::AncestorSbom, 1, cpe("o:example:platform:5")),
                (
                    ContextSource::PurlQualifier,
                    0,
                    "cpe:2.3:o:suse:*:15:sp6:*:*:*:*:*:*".to_string()
                ),
            ]
        );
        assert_eq!(
            cpes("rpm-release")
                .into_iter()
                .filter(|(source, ..)| *source == ContextSource::PurlRelease)
                .collect::<Vec<_>>(),
            [(
                ContextSource::PurlRelease,
                0,
                "cpe:2.3:*:redhat:enterprise_linux:8:*:*:*:*:*:*:*".to_string()
            )]
        );

        Ok(())
    }
}
