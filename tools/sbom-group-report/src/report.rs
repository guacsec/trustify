//! Aggregation of per-SBOM advisory data into a report, and HTML rendering.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use trustify_client::api::types::{SbomAdvisory, Severity};

/// Severity buckets shown as table columns, worst first.
pub const SEVERITIES: [Bucket; 6] = [
    Bucket::Critical,
    Bucket::High,
    Bucket::Medium,
    Bucket::Low,
    Bucket::None,
    Bucket::Unknown,
];

/// A CVSS severity, plus `Unknown` for vulnerabilities that carry no score.
///
/// Declared worst-first, so `min` picks the worst of several severities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Bucket {
    Critical,
    High,
    Medium,
    Low,
    None,
    Unknown,
}

impl Bucket {
    /// The column heading used for this severity in both output formats.
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::None => "None",
            Self::Unknown => "Unrated",
        }
    }

    /// The CSS class that colours this severity's cells; `None` and `Unknown`
    /// share one, because neither carries a usable score.
    fn css_class(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::None | Self::Unknown => "unrated",
        }
    }
}

impl From<Severity> for Bucket {
    fn from(value: Severity) -> Self {
        match value {
            Severity::Critical => Self::Critical,
            Severity::High => Self::High,
            Severity::Medium => Self::Medium,
            Severity::Low => Self::Low,
            Severity::None => Self::None,
        }
    }
}

/// One affected vulnerability in one SBOM, after de-duplication by identifier.
#[derive(Debug, Clone)]
pub struct Finding {
    pub identifier: String,
    pub severity: Bucket,
    /// A fixed version is published for this vulnerability.
    pub fix_available: bool,
    /// Affected components, keyed by PURL or (group, name, version).
    pub artifacts: BTreeSet<String>,
}

/// Collapse the advisories of one SBOM into one finding per vulnerability.
///
/// Resolved statuses are dropped: the report counts what the SBOM is still
/// exposed to. The same CVE can arrive from several advisories, so findings
/// are merged by identifier, keeping the worst severity.
pub fn findings(advisories: &[SbomAdvisory]) -> Vec<Finding> {
    let mut merged: Vec<Finding> = Vec::new();

    for status in advisories
        .iter()
        .flat_map(|advisory| &advisory.status)
        .filter(|status| status.status == "affected")
    {
        let severity = status
            .scores
            .iter()
            .map(|score| Bucket::from(score.severity))
            .min()
            .unwrap_or(Bucket::Unknown);
        let artifacts = status.packages.iter().flat_map(|package| {
            // shortcut: a package with no PURL is keyed by the Debug form of its
            // group, name and version, which is not a format Rust guarantees.
            // These keys are only ever counted, never shown, so the risk is a
            // silently changed artifact total. Swap in a typed `Artifact` key
            // if the artifacts are ever listed or compared across runs.
            if package.purl.is_empty() {
                vec![format!(
                    "{:?}",
                    (&package.group, &package.name, &package.version)
                )]
            } else {
                package
                    .purl
                    .iter()
                    .map(|purl| purl.purl.to_string())
                    .collect()
            }
        });

        match merged
            .iter_mut()
            .find(|found| found.identifier == status.identifier)
        {
            Some(found) => {
                found.severity = found.severity.min(severity);
                found.fix_available |= !status.fixed_versions.is_empty();
                found.artifacts.extend(artifacts);
            }
            None => merged.push(Finding {
                identifier: status.identifier.clone(),
                severity,
                fix_available: !status.fixed_versions.is_empty(),
                artifacts: artifacts.collect(),
            }),
        }
    }

    merged
}

/// One row of the detailed results table.
#[derive(Debug, Clone)]
pub struct SbomRow {
    pub name: String,
    pub url: String,
    pub packages: i64,
    pub findings: Vec<Finding>,
}

impl SbomRow {
    /// How many of this SBOM's vulnerabilities fall in one severity bucket.
    fn count(&self, bucket: Bucket) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == bucket)
            .count()
    }

    /// How many of this SBOM's vulnerabilities have a published fixed version.
    fn fixable(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.fix_available)
            .count()
    }
}

/// Everything the renderers need; the summary figures are derived from `rows`,
/// so the two sections of the report cannot disagree.
pub struct Report {
    /// Base URL of the Trustify instance the data came from.
    pub instance_url: String,
    /// Name of the group the report was requested for.
    pub group_name: String,
    /// ID of that group, shown so a report can be reproduced.
    pub group_id: String,
    /// The group plus its nested children, as resolved by `groups::subtree`.
    pub groups_scanned: usize,
    /// When the report was produced.
    pub generated: DateTime<Utc>,
    /// One entry per distinct SBOM in the subtree.
    pub rows: Vec<SbomRow>,
}

/// Figures shown in the executive summary, all derived from `Report::rows`.
pub struct Summary {
    pub sboms: usize,
    pub sboms_with_vulnerabilities: usize,
    pub sboms_with_fixes: usize,
    pub unique_vulnerabilities: usize,
    pub unique_artifacts: usize,
    pub fixable_vulnerabilities: usize,
}

impl Report {
    /// Roll the per-SBOM rows up into the executive summary figures.
    pub fn summary(&self) -> Summary {
        let mut unique_vulnerabilities = BTreeSet::new();
        let mut fixable = BTreeSet::new();
        let mut unique_artifacts = BTreeSet::new();

        for finding in self.rows.iter().flat_map(|row| &row.findings) {
            unique_vulnerabilities.insert(&finding.identifier);
            if finding.fix_available {
                fixable.insert(&finding.identifier);
            }
            unique_artifacts.extend(&finding.artifacts);
        }

        Summary {
            sboms: self.rows.len(),
            sboms_with_vulnerabilities: self
                .rows
                .iter()
                .filter(|row| !row.findings.is_empty())
                .count(),
            sboms_with_fixes: self.rows.iter().filter(|row| row.fixable() > 0).count(),
            unique_vulnerabilities: unique_vulnerabilities.len(),
            unique_artifacts: unique_artifacts.len(),
            fixable_vulnerabilities: fixable.len(),
        }
    }
}

/// Escape text for use in HTML element content and double-quoted attributes.
fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

const STYLE: &str = r#"
:root { color-scheme: light; }
body { font-family: "Red Hat Text", system-ui, sans-serif; margin: 0 auto; max-width: 70rem;
       padding: 2rem 1.5rem 4rem; color: #151515; }
h1 { font-weight: 400; color: #c9190b; margin: 0 0 .25rem; }
h2 { font-weight: 400; margin: 2.5rem 0 .75rem; border-bottom: 1px solid #d2d2d2; padding-bottom: .25rem; }
.sub { color: #6a6e73; margin: 0; }
.disclaimer { margin-top: 3rem; color: #6a6e73; font-size: .8rem; border-top: 1px solid #d2d2d2; padding-top: .75rem; }
.cards { display: flex; flex-wrap: wrap; gap: 1.5rem 2.5rem; align-items: center; }
.card .value { font-size: 2.25rem; line-height: 1.1; }
.card .label { color: #6a6e73; font-size: .8rem; }
table { border-collapse: collapse; width: 100%; font-size: .85rem; }
th, td { text-align: right; padding: .35rem .5rem; border-bottom: 1px solid #ebebeb; }
th:first-child, td:first-child { text-align: left; }
thead th { color: #6a6e73; font-weight: 600; border-bottom: 1px solid #8a8d90; }
tbody tr:nth-child(even) { background: #fafafa; }
td.zero { color: #d2d2d2; }
th.critical, td.critical { color: #a30000; }
th.high, td.high { color: #c46100; }
th.medium, td.medium { color: #795600; }
th.low, td.low { color: #0066cc; }
th.unrated, td.unrated { color: #6a6e73; }
@media print { body { max-width: none; padding: 0; } thead { display: table-header-group; } }
"#;

/// A donut showing `part` of `whole`, sized to sit next to the summary cards.
fn donut(part: usize, whole: usize) -> String {
    let circumference = 2.0 * std::f64::consts::PI * 40.0;
    let filled = if whole == 0 {
        0.0
    } else {
        circumference * part as f64 / whole as f64
    };
    format!(
        r##"<svg width="110" height="110" viewBox="0 0 100 100" role="img" aria-label="{part} of {whole}">
  <circle cx="50" cy="50" r="40" fill="none" stroke="#d2d2d2" stroke-width="12"/>
  <circle cx="50" cy="50" r="40" fill="none" stroke="#3e8635" stroke-width="12"
          stroke-dasharray="{filled:.2} {circumference:.2}" transform="rotate(-90 50 50)"/>
</svg>"##
    )
}

/// One headline figure and its caption in the executive summary.
fn card(value: impl std::fmt::Display, label: &str) -> String {
    format!(
        r#"<div class="card"><div class="value">{value}</div><div class="label">{}</div></div>"#,
        esc(label)
    )
}

/// Render the whole report as one self-contained HTML document, with no
/// external assets so it can be mailed or printed to PDF as-is.
pub fn render_html(report: &Report) -> String {
    let summary = report.summary();
    let generated = report.generated.format("%d %b %Y %H:%M UTC");

    let cards = [
        card(summary.sboms, "SBOMs in group"),
        card(summary.sboms_with_vulnerabilities, "With vulnerabilities"),
        card(summary.sboms_with_fixes, "With a fix available"),
        card(summary.unique_vulnerabilities, "Unique vulnerabilities"),
        card(summary.fixable_vulnerabilities, "Of which fixable"),
        card(summary.unique_artifacts, "Affected artifacts"),
    ]
    .concat();

    let headers = SEVERITIES
        .iter()
        .map(|bucket| {
            format!(
                r#"<th class="{}">{}</th>"#,
                bucket.css_class(),
                bucket.label()
            )
        })
        .collect::<String>();

    let mut rows = report.rows.clone();
    rows.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.url.cmp(&b.url)));
    let rows = rows
        .iter()
        .map(|row| {
            let counts = SEVERITIES
                .iter()
                .map(|bucket| cell(row.count(*bucket), bucket.css_class()))
                .collect::<String>();
            format!(
                "<tr><td><a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{}</a></td><td>{}</td>{counts}{}</tr>",
                esc(&row.url),
                esc(&row.name),
                row.packages,
                cell(row.fixable(), "")
            )
        })
        .collect::<String>();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SBOM group report: {name}</title>
<style>{STYLE}</style>
</head>
<body>
<h1>SBOM Group Vulnerability Report</h1>
<p class="sub">Group: {name} ({id}) &middot; {groups} group(s) including nested children</p>
<p class="sub">Generated: {generated}</p>
<p class="sub">Source: <a href="{instance_url}" target="_blank" rel="noopener noreferrer">{instance_url}</a></p>

<h2>Executive summary</h2>
<div class="cards">{donut}{cards}</div>

<h2>Detailed results</h2>
<table>
<thead><tr><th>SBOM</th><th>Packages</th>{headers}<th>Fix available</th></tr></thead>
<tbody>{rows}</tbody>
</table>

<p class="disclaimer">
Generated by sbom-group-report from Trustify advisory data
(<code>GET /api/v3/sbom/{{id}}/advisory</code>). Counts cover vulnerabilities whose
status is <em>affected</em>, de-duplicated per SBOM. &ldquo;Fix available&rdquo; means a
fixed version is published, not that the fix has been applied.
This is not an official Red Hat product report.
</p>
</body>
</html>
"#,
        name = esc(&report.group_name),
        instance_url = esc(&report.instance_url),
        id = esc(&report.group_id),
        groups = report.groups_scanned,
        donut = donut(summary.sboms_with_fixes, summary.sboms),
    )
}

/// One count cell; zeros are greyed out so the populated columns stand out.
fn cell(count: usize, class: &str) -> String {
    let class = if count == 0 { "zero" } else { class };
    format!(r#"<td class="{class}">{count}</td>"#)
}

/// Quote a field for RFC 4180, and defuse spreadsheet formula injection.
///
/// SBOM names come from uploaded documents, and a name starting with `=`, `+`,
/// `-` or `@` is executed as a formula when the CSV is opened in a spreadsheet.
/// A leading apostrophe keeps the text intact and inert. Leading whitespace is
/// skipped, because spreadsheets trim it before deciding what the cell is.
fn csv_field(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    let inert = match value.trim_start().chars().next() {
        Some('=' | '+' | '-' | '@') => format!("'{escaped}"),
        _ => escaped,
    };

    if inert.contains([',', '"', '\n', '\r']) {
        format!("\"{inert}\"")
    } else {
        inert
    }
}

/// The detailed results table as CSV, for spreadsheets and further analysis.
pub fn render_csv(report: &Report) -> String {
    let mut rows = report.rows.clone();
    rows.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.url.cmp(&b.url)));

    let headers = SEVERITIES.map(Bucket::label).join(",");
    let mut out = format!("SBOM,Packages,{headers},Fix available,SBOM URL\n");

    for row in &rows {
        let counts = SEVERITIES
            .map(|bucket| row.count(bucket).to_string())
            .join(",");
        out.push_str(&format!(
            "{},{},{counts},{},{}\n",
            csv_field(&row.name),
            row.packages,
            row.fixable(),
            csv_field(&row.url)
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::{Bucket, Report, SbomRow, csv_field, esc, findings, render_csv, render_html};
    use chrono::Utc;
    use trustify_client::api::types::SbomAdvisory;

    /// Two advisories naming the same CVE for one SBOM, plus a resolved entry.
    const ADVISORIES: &str = r#"[
      {
        "uuid": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "identifier": "ADV-1", "document_id": "ADV-1", "issuer": null,
        "labels": {}, "published": null, "withdrawn": null, "title": null,
        "status": [
          {
            "identifier": "CVE-2024-0001", "status": "affected", "normative": true,
            "cwes": [], "description": null, "discovered": null, "modified": null,
            "published": null, "released": null, "reserved": null, "withdrawn": null,
            "title": null, "fixed_versions": ["2.0.0"],
            "scores": [{"type": "3.1", "value": 7.5, "severity": "high",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
            "packages": [{"id": "p1", "name": "widget", "version": "1.0.0", "cpe": [],
                          "licenses": [], "licenses_ref_mapping": [],
                          "purl": [{"uuid": "00000000-0000-0000-0000-0000000000a1",
                                    "purl": "pkg:maven/com.example/widget@1.0.0",
                                    "base": {"uuid": "00000000-0000-0000-0000-0000000000a2",
                                             "purl": "pkg:maven/com.example/widget"},
                                    "version": {"uuid": "00000000-0000-0000-0000-0000000000a3",
                                                "purl": "pkg:maven/com.example/widget@1.0.0",
                                                "version": "1.0.0"},
                                    "qualifiers": {}}]}]
          }
        ]
      },
      {
        "uuid": "urn:uuid:00000000-0000-0000-0000-000000000002",
        "identifier": "ADV-2", "document_id": "ADV-2", "issuer": null,
        "labels": {}, "published": null, "withdrawn": null, "title": null,
        "status": [
          {
            "identifier": "CVE-2024-0001", "status": "affected", "normative": true,
            "cwes": [], "description": null, "discovered": null, "modified": null,
            "published": null, "released": null, "reserved": null, "withdrawn": null,
            "title": null, "fixed_versions": [],
            "scores": [{"type": "3.1", "value": 9.8, "severity": "critical",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "packages": [{"id": "p2", "name": "gadget", "version": "0.1.0", "cpe": [],
                          "licenses": [], "licenses_ref_mapping": [], "purl": []}]
          },
          {
            "identifier": "CVE-2024-0002", "status": "fixed", "normative": true,
            "cwes": [], "description": null, "discovered": null, "modified": null,
            "published": null, "released": null, "reserved": null, "withdrawn": null,
            "title": null, "fixed_versions": ["3.0.0"], "scores": [], "packages": []
          }
        ]
      }
    ]"#;

    fn parsed() -> Vec<SbomAdvisory> {
        serde_json::from_str(ADVISORIES).expect("fixture parses")
    }

    #[test]
    fn merges_one_cve_across_advisories_and_drops_resolved() {
        let found = findings(&parsed());

        assert_eq!(
            found.len(),
            1,
            "CVE-2024-0002 is fixed, CVE-2024-0001 merges"
        );
        let finding = &found[0];
        assert_eq!(finding.identifier, "CVE-2024-0001");
        assert_eq!(finding.severity, Bucket::Critical, "worst severity wins");
        assert!(finding.fix_available, "one advisory lists a fixed version");
        assert_eq!(finding.artifacts.len(), 2);
        assert!(
            finding
                .artifacts
                .contains("pkg:maven/com.example/widget@1.0.0")
        );
        assert!(
            finding
                .artifacts
                .contains(&format!("{:?}", (None::<String>, "gadget", Some("0.1.0")))),
            "falls back to group, name and version"
        );
    }

    #[test]
    fn packages_without_purls_keep_their_namespace_and_version() {
        let mut advisories = parsed();
        let mut package = advisories[1].status[0].packages[0].clone();
        package.version = Some("0.2.0".to_owned());
        advisories[1].status[0].packages.push(package.clone());
        package.group = Some("another-namespace".to_owned());
        advisories[1].status[0].packages.push(package.clone());
        advisories[1].status[0].packages.push(package);

        assert_eq!(
            findings(&advisories)[0].artifacts.len(),
            4,
            "one PURL and three distinct fallback identities"
        );
    }

    #[test]
    fn unscored_vulnerabilities_are_unrated() {
        let json = r#"[
          {
            "uuid": "urn:uuid:00000000-0000-0000-0000-000000000003",
            "identifier": "ADV-3", "document_id": "ADV-3", "issuer": null,
            "labels": {}, "published": null, "withdrawn": null, "title": null,
            "status": [
              {
                "identifier": "CVE-2024-0003", "status": "affected", "normative": true,
                "cwes": [], "description": null, "discovered": null, "modified": null,
                "published": null, "released": null, "reserved": null, "withdrawn": null,
                "title": null, "fixed_versions": [], "scores": [], "packages": []
              }
            ]
          }
        ]"#;
        let advisories: Vec<SbomAdvisory> = serde_json::from_str(json).expect("fixture parses");
        let found = findings(&advisories);

        assert_eq!(found[0].severity, Bucket::Unknown);
        assert!(!found[0].fix_available);
    }

    fn report() -> Report {
        Report {
            instance_url: "https://trustify.example/".to_owned(),
            group_name: "acme <prod>".to_owned(),
            group_id: "g-1".to_owned(),
            groups_scanned: 3,
            generated: Utc::now(),
            rows: vec![
                SbomRow {
                    name: "service-a".to_owned(),
                    url: "https://trustify.example/sboms/a?sd%3AactiveTab=vulnerabilities"
                        .to_owned(),
                    packages: 120,
                    findings: findings(&parsed()),
                },
                SbomRow {
                    name: "service-b".to_owned(),
                    url: "https://trustify.example/sboms/b?sd%3AactiveTab=vulnerabilities"
                        .to_owned(),
                    packages: 4,
                    findings: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn summary_totals_match_the_detail_rows() {
        let report = report();
        let summary = report.summary();

        assert_eq!(summary.sboms, report.rows.len());
        assert_eq!(summary.sboms_with_vulnerabilities, 1);
        assert_eq!(summary.sboms_with_fixes, 1);
        assert_eq!(summary.unique_vulnerabilities, 1);
        assert_eq!(summary.fixable_vulnerabilities, 1);
        assert_eq!(summary.unique_artifacts, 2);
    }

    #[test]
    fn group_names_are_escaped() {
        let html = render_html(&report());
        assert!(html.contains("acme &lt;prod&gt;"));
        assert!(!html.contains("acme <prod>"));
    }

    #[test]
    fn csv_has_one_row_per_sbom_matching_the_html_counts() {
        let csv = render_csv(&report());
        let lines: Vec<&str> = csv.lines().collect();

        assert_eq!(lines.len(), 3, "a header and two SBOMs");
        assert_eq!(
            lines[0],
            "SBOM,Packages,Critical,High,Medium,Low,None,Unrated,Fix available,SBOM URL"
        );
        assert_eq!(
            lines[1],
            "service-a,120,1,0,0,0,0,0,1,https://trustify.example/sboms/a?sd%3AactiveTab=vulnerabilities"
        );
        assert_eq!(
            lines[2],
            "service-b,4,0,0,0,0,0,0,0,https://trustify.example/sboms/b?sd%3AactiveTab=vulnerabilities"
        );
    }

    #[test]
    fn html_links_back_to_the_instance_and_escapes_sbom_links() {
        let mut report = report();
        report.rows[0].name = "<service>".to_owned();
        report.rows[0].url = "https://trustify.example/sboms/a?x=1&y=\"2\"".to_owned();
        let html = render_html(&report);
        assert!(html.contains("<a href=\"https://trustify.example/\" target=\"_blank\""));
        assert_eq!(
            html.matches("target=\"_blank\" rel=\"noopener noreferrer\"")
                .count(),
            3
        );
        assert!(html.contains(
            "href=\"https://trustify.example/sboms/a?x=1&amp;y=&quot;2&quot;\" target=\"_blank\" rel=\"noopener noreferrer\">&lt;service&gt;</a>"
        ));
    }

    #[test]
    fn csv_quotes_separators_and_defuses_formulas() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field(r#"a,b"c"#), r#""a,b""c""#);
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(csv_field("=A1,B1"), "\"'=A1,B1\"");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_field("-lib"), "'-lib");
        // Whitespace a spreadsheet trims must not hide the formula marker.
        assert_eq!(csv_field(" =1+1"), "' =1+1");
        assert_eq!(csv_field("\t=1+1"), "'\t=1+1");
    }

    #[test]
    fn every_purl_of_a_package_counts_as_an_artifact() {
        let mut advisories = parsed();
        let mut purl = advisories[0].status[0].packages[0].purl[0].clone();
        purl.purl = "pkg:maven/com.example/widget@1.0.0?classifier=sources"
            .parse()
            .expect("valid purl");
        advisories[0].status[0].packages[0].purl.push(purl);

        assert_eq!(
            findings(&advisories)[0].artifacts.len(),
            3,
            "both PURLs of the widget, plus the gadget fallback"
        );
    }

    #[test]
    fn escapes_every_html_metacharacter() {
        assert_eq!(
            esc(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
