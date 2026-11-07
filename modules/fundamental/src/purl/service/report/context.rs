//! Weighted product scoping over the release's existing CPE and relationship tables.

use super::ReportError;
use crate::purl::service::SbomPurlRow;
use sea_orm::{ConnectionTrait, DbBackend, FromQueryResult, Statement};
use std::collections::{BTreeSet, HashMap};
use trustify_common::purl::Purl;
use trustify_entity::{cpe, version_range};
use uuid::Uuid;

/// A product CPE and its specificity relative to one original SBOM node.
#[derive(Clone)]
pub(super) struct WeightedCpe {
    pub(super) cpe: cpe::Model,
    source: String,
    distance: i32,
    confidence: i32,
}

impl WeightedCpe {
    /// Provider hints come from the component's own CPEs, never an inherited product CPE.
    pub(super) fn confidence_is_local(&self) -> bool {
        self.source == "node"
    }
}

/// The relational query result includes the original target, not merely its shared PURL.
#[derive(FromQueryResult)]
struct NodeCpeRow {
    sbom_id: Uuid,
    node_id: String,
    source: String,
    distance: i32,
    confidence: i32,
    #[sea_orm(nested)]
    cpe: cpe::Model,
}

/// Load canonical local/ancestor/describing/ancestor-SBOM scopes without introducing evidence tables.
pub(super) async fn load<C: ConnectionTrait>(
    rows: &[SbomPurlRow],
    connection: &C,
) -> Result<HashMap<(Uuid, String), Vec<WeightedCpe>>, ReportError> {
    let nodes = rows
        .iter()
        .map(|row| (row.sbom_id, row.node_id.to_string()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut result = HashMap::<_, Vec<_>>::new();
    for chunk in nodes.chunks(5000) {
        let (sboms, ids): (Vec<_>, Vec<_>) = chunk.iter().cloned().unzip();
        // Only constant relationship IDs and the canonical depth bound are embedded; all node IDs are bound.
        let sql = r#"
WITH RECURSIVE node AS (
    SELECT DISTINCT * FROM unnest($1::uuid[], $2::text[]) AS n(sbom_id, node_id)
), up(sbom_id,node_id,ancestor_id,distance) AS (
    SELECT sbom_id,node_id,node_id,0 FROM node
    UNION
    SELECT up.sbom_id,up.node_id,r.left_node_id,up.distance+1 FROM up
    JOIN package_relates_to_package r ON r.sbom_id=up.sbom_id AND r.right_node_id=up.ancestor_id
    WHERE r.relationship IN (0,1,2,3,4,5,6,9,10,13) AND up.distance<16
), ancestor_sbom(sbom_id,ancestor_sbom_id,hops) AS (
    SELECT a.sbom_id,a.ancestor_sbom_id,1 FROM sbom_ancestor a JOIN (SELECT DISTINCT sbom_id FROM node) n ON n.sbom_id=a.sbom_id
    UNION
    SELECT anc.sbom_id,a.ancestor_sbom_id,anc.hops+1 FROM ancestor_sbom anc
    JOIN sbom_ancestor a ON a.sbom_id=anc.ancestor_sbom_id WHERE anc.hops<16
), found AS (
    SELECT up.sbom_id,up.node_id,CASE WHEN up.distance=0 THEN 'node' ELSE 'ancestor_node' END AS source,
        up.distance,CASE WHEN up.distance=0 THEN 100 ELSE greatest(70,90-(up.distance-1)*5) END AS confidence,ref.cpe_id
    FROM up JOIN sbom_node_cpe_ref ref ON ref.sbom_id=up.sbom_id AND ref.node_id=up.ancestor_id
    UNION ALL
    SELECT n.sbom_id,n.node_id,'describing',0,80,d.cpe_id FROM node n JOIN sbom_describing_cpe d ON d.sbom_id=n.sbom_id
    UNION ALL
    SELECT n.sbom_id,n.node_id,'ancestor_sbom',anc.hops,greatest(50,70-(anc.hops-1)*5),d.cpe_id FROM node n
    JOIN ancestor_sbom anc ON anc.sbom_id=n.sbom_id JOIN sbom_describing_cpe d ON d.sbom_id=anc.ancestor_sbom_id
)
SELECT f.sbom_id,f.node_id,f.source,min(f.distance)::int4 AS distance,max(f.confidence)::int4 AS confidence,c.*
FROM found f JOIN cpe c ON c.id=f.cpe_id GROUP BY f.sbom_id,f.node_id,f.source,c.id
"#;
        for row in NodeCpeRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            [sboms.into(), ids.into()],
        ))
        .all(connection)
        .await?
        {
            result
                .entry((row.sbom_id, row.node_id))
                .or_default()
                .push(WeightedCpe {
                    cpe: row.cpe,
                    source: row.source,
                    distance: row.distance,
                    confidence: row.confidence,
                });
        }
    }
    let mut seen = BTreeSet::new();
    for row in rows {
        if !seen.insert((row.sbom_id, row.node_id.clone())) {
            continue;
        }
        for purl in row.node_purls.iter() {
            if let Some(scope) = rpm_context(purl) {
                result
                    .entry((row.sbom_id, row.node_id.to_string()))
                    .or_default()
                    .push(scope);
            }
        }
    }
    Ok(result)
}

/// Canonical RPM product hints: qualifier first, then the release; no evidence-table dependency.
pub(super) fn rpm_context(purl: &Purl) -> Option<WeightedCpe> {
    if purl.ty != "rpm" {
        return None;
    }
    let vendor = purl.namespace.as_deref()?;
    if !matches!(vendor, "redhat" | "suse") {
        return None;
    }
    let product = |major: u32, minor: Option<u32>| {
        if vendor == "suse" && !matches!(major, 12 | 15) {
            None
        } else {
            Some((major, minor))
        }
    };
    let from_distro = purl.qualifiers.get("distro").and_then(|distro| {
        let version = distro.strip_prefix(if vendor == "redhat" { "rhel-" } else { "sles-" })?;
        let (major, minor) = match version.split_once('.') {
            Some((major, minor)) => (major.parse().ok()?, Some(minor.parse().ok()?)),
            None => (version.parse().ok()?, None),
        };
        product(major, minor)
    });
    let (major, minor, source, confidence) = if let Some((major, minor)) = from_distro {
        (major, minor, "purl_qualifier", 85)
    } else {
        let release = purl.version.as_deref()?.rsplit_once('-')?.1;
        let (major, minor) = if vendor == "redhat" {
            let major = release
                .split(['.', '+', '_'])
                .find_map(|token| token.strip_prefix("el")?.parse().ok())?;
            product(major, None)?
        } else {
            let code = release.split('.').next()?;
            if code.len() != 6
                || !code.ends_with("00")
                || !code.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            product(code[..2].parse().ok()?, Some(code[2..4].parse().ok()?))?
        };
        (major, minor, "purl_release", 75)
    };
    let any = || Some("*".to_owned());
    let mut cpe = cpe::Model {
        id: Uuid::nil(),
        part: if vendor == "redhat" {
            any()
        } else {
            Some("o".into())
        },
        vendor: Some(vendor.into()),
        product: if vendor == "redhat" {
            Some("enterprise_linux".into())
        } else {
            any()
        },
        version: Some(major.to_string()),
        update: if vendor == "suse" {
            minor
                .filter(|minor| *minor > 0)
                .map(|minor| format!("sp{minor}"))
                .or_else(any)
        } else {
            any()
        },
        edition: any(),
        language: any(),
        sw_edition: any(),
        target_sw: any(),
        target_hw: any(),
        other: any(),
    };
    let namespace = Uuid::from_u128(0x6a0f2d917e344bc8851ad360e7dce71c);
    cpe.id = Uuid::new_v5(&namespace, format_cpe(&cpe).as_bytes());
    Some(WeightedCpe {
        cpe,
        source: source.into(),
        distance: 0,
        confidence,
    })
}

/// Preserve source/distance even when two scopes happen to have the same numerical weight.
pub(super) fn key(scopes: &[WeightedCpe]) -> Vec<(String, String, i32)> {
    scopes
        .iter()
        .map(|scope| (format_cpe(&scope.cpe), scope.source.clone(), scope.distance))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Confidence of the best applicable scope, 0 for comparable mismatches and 70 when unconfirmed.
pub(super) fn confidence(context: &cpe::Model, scopes: &[WeightedCpe]) -> i32 {
    let (best, comparable) = scoped_confidence(context, scopes);
    if best > 0 || comparable { best } else { 70 }
}

/// Publisher-policy ranges require confirmation rather than an unconfirmed product fallback.
pub(super) fn confidence_required(
    context: &cpe::Model,
    scopes: &[WeightedCpe],
    required: bool,
) -> i32 {
    if required {
        scoped_confidence(context, scopes).0
    } else {
        confidence(context, scopes)
    }
}

fn scoped_confidence(context: &cpe::Model, scopes: &[WeightedCpe]) -> (i32, bool) {
    let mut comparable = false;
    let mut best = 0;
    for scope in scopes {
        match cpe_match(context, &scope.cpe) {
            CpeMatch::Exact => best = best.max(scope.confidence),
            CpeMatch::Any => best = best.max((scope.confidence * 90 + 50) / 100),
            CpeMatch::Different => comparable = true,
            CpeMatch::Unrelated => {}
        }
    }
    (best, comparable)
}

/// Stream relation used by stated and legacy publisher-policy range evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamScope {
    Unscoped,
    Exact,
    Major,
    Minor,
}

impl StreamScope {
    /// Exact and unscoped matches retain full confidence; related minor streams are less specific.
    pub(super) fn confidence(self) -> i32 {
        if matches!(self, Self::Major | Self::Minor) {
            80
        } else {
            100
        }
    }
    /// Canonical evidence kind participates in deterministic tie-breaking.
    pub(super) fn extractor(self) -> &'static str {
        if self == Self::Unscoped {
            "purl"
        } else {
            "purl_stream"
        }
    }
}

/// The release is the suffix after the last dash, including when an epoch precedes the version.
fn rpm_release(version: &str) -> Option<&str> {
    version.rsplit_once('-').map(|(_, release)| release)
}

fn suse_stream(version: &str) -> Option<&str> {
    let release = rpm_release(version)?;
    if release.starts_with("slfo.") {
        return Some(
            release
                .split_once('_')
                .map_or(release, |(prefix, _)| prefix),
        );
    }
    let first = release.split('.').next()?;
    (first.len() >= 6 && first.bytes().all(|byte| byte.is_ascii_digit())).then_some(first)
}

fn rpm_stream(version: &str) -> Option<&str> {
    rpm_release(version)?.split('.').find(|part| {
        let letters = part.bytes().take_while(u8::is_ascii_alphabetic).count();
        letters > 0 && part.as_bytes().get(letters).is_some_and(u8::is_ascii_digit)
    })
}

fn stream_major(stream: &str) -> &str {
    let letters = stream.bytes().take_while(u8::is_ascii_alphabetic).count();
    let digits = stream[letters..]
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    &stream[..letters + digits]
}

/// Match RPM dist tags/codestreams without adding main-only persistence or correlation modules.
pub(super) fn stream_match(target: &Purl, range: &version_range::Model) -> Option<StreamScope> {
    if target.ty != "rpm" {
        return Some(StreamScope::Unscoped);
    }
    let version = target.version.as_deref().unwrap_or_default();
    let bound = range
        .high_version
        .as_deref()
        .or(range.low_version.as_deref());
    if target.namespace.as_deref() == Some("suse") {
        let Some(bound) = bound else {
            return Some(StreamScope::Unscoped);
        };
        return match (suse_stream(version), suse_stream(bound)) {
            (None, None) => Some(StreamScope::Unscoped),
            (Some(a), Some(b)) if a == b => Some(StreamScope::Exact),
            _ => None,
        };
    }
    let (Some(target), Some(stated)) = (rpm_stream(version), bound.and_then(rpm_stream)) else {
        return Some(StreamScope::Unscoped);
    };
    if target == stated {
        return Some(StreamScope::Exact);
    }
    let (a, b) = (stream_major(target), stream_major(stated));
    if a != b {
        None
    } else if target == a || stated == b {
        Some(StreamScope::Major)
    } else {
        Some(StreamScope::Minor)
    }
}

/// CPE identity mismatch is different from an unrelated product that cannot confirm a context.
enum CpeMatch {
    Exact,
    Any,
    Different,
    Unrelated,
}

fn cpe_match(context: &cpe::Model, node: &cpe::Model) -> CpeMatch {
    let mut any = false;
    for (left, right) in [
        (&context.part, &node.part),
        (&context.vendor, &node.vendor),
        (&context.product, &node.product),
    ] {
        match attribute_match(left.as_deref(), right.as_deref()) {
            Some(wildcard) => any |= wildcard,
            None => return CpeMatch::Unrelated,
        }
    }
    let version = version_match(context.version.as_deref(), node.version.as_deref());
    let rest = [
        (&context.update, &node.update),
        (&context.edition, &node.edition),
        (&context.language, &node.language),
        (&context.sw_edition, &node.sw_edition),
        (&context.target_sw, &node.target_sw),
        (&context.target_hw, &node.target_hw),
        (&context.other, &node.other),
    ];
    for comparison in [version].into_iter().chain(
        rest.into_iter()
            .map(|(left, right)| attribute_match(left.as_deref(), right.as_deref())),
    ) {
        match comparison {
            Some(wildcard) => any |= wildcard,
            None => return CpeMatch::Different,
        }
    }
    if any { CpeMatch::Any } else { CpeMatch::Exact }
}

fn attribute_match(context: Option<&str>, node: Option<&str>) -> Option<bool> {
    match (context, node) {
        (Some("*"), Some("*")) | (None, None) => Some(false),
        (Some("*"), _) | (_, Some("*")) => Some(true),
        (Some(pattern), Some(value)) if wildcard_match(pattern, value) => Some(false),
        _ => None,
    }
}

fn version_match(context: Option<&str>, node: Option<&str>) -> Option<bool> {
    let minor_of = |minor: &str, major: &str| {
        !major.is_empty()
            && major.bytes().all(|b| b.is_ascii_digit())
            && minor
                .strip_prefix(major)
                .is_some_and(|rest| rest.starts_with('.'))
    };
    match (context, node) {
        (Some(left), Some(right)) if minor_of(left, right) || minor_of(right, left) => Some(true),
        _ => attribute_match(context, node),
    }
}

/// Iterative glob matching avoids recursive exponential work on external CPE attributes.
fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase().chars().collect::<Vec<_>>();
    let value = value.to_lowercase().chars().collect::<Vec<_>>();
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(position) = star {
            retry += 1;
            v = retry;
            p = position + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

fn format_cpe(model: &cpe::Model) -> String {
    fn component(value: &Option<String>) -> &str {
        value.as_deref().unwrap_or("-")
    }
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
        component(&model.other)
    )
}
