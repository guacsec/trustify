//! The vulnerabilities of a CSAF document, with the product statuses and remediations.

use super::{
    Doc, none, notes::notes_list, product_ref, status::StatusCategory, vulnerability_name,
};
use crate::sort::{missing_last, ordered, text, use_sort};
use ::csaf::schema::csaf2_0::schema::{
    CategoryOfTheRemediation, ProductGroupsT, ProductsT, Remediation, Score, Vulnerability,
};
use patternfly_yew::prelude::*;
use serde_json::{Map, Value};
use std::{cmp::Ordering, rc::Rc};
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct VulnerabilitiesTabProps {
    pub doc: Doc,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VulnColumn {
    Vulnerability,
    Cwe,
    Scores,
    Status,
    Remediations,
}

/// A vulnerability of the document, by its position.
#[derive(Clone, PartialEq)]
struct VulnEntry {
    doc: Doc,
    n: usize,
}

impl VulnEntry {
    fn vulnerability(&self) -> Option<&Vulnerability> {
        self.doc.csaf.vulnerabilities.get(self.n)
    }
}

impl TableEntryRenderer<VulnColumn> for VulnEntry {
    fn render_cell(&self, context: CellContext<'_, VulnColumn>) -> Cell {
        let Some(vuln) = self.vulnerability() else {
            return none().into();
        };

        match context.column {
            VulnColumn::Vulnerability => {
                let id = vuln.cve.as_deref().cloned().or_else(|| {
                    vuln.ids
                        .as_ref()
                        .and_then(|ids| ids.first())
                        .map(|id| format!("{}: {}", *id.system_name, *id.text))
                });
                html! {
                    <>
                        <strong>{ id.unwrap_or_else(|| format!("#{}", self.n + 1)) }</strong>
                        if let Some(title) = &vuln.title {
                            <br />
                            <small>{ title.to_string() }</small>
                        }
                    </>
                }
                .into()
            }
            VulnColumn::Cwe => match &vuln.cwe {
                Some(cwe) => html! {
                    <>
                        { cwe.id.to_string() }
                        <br />
                        <small>{ cwe.name.to_string() }</small>
                    </>
                }
                .into(),
                None => none().into(),
            },
            VulnColumn::Scores => {
                let mut scores = vuln
                    .scores
                    .iter()
                    .filter_map(|score| Cvss::from_score(score).map(|cvss| cvss.short()))
                    .collect::<Vec<_>>();
                scores.sort();
                scores.dedup();
                if scores.is_empty() {
                    none().into()
                } else {
                    html!(scores.join(", ")).into()
                }
            }
            VulnColumn::Status => match &vuln.product_status {
                Some(status) => html! {
                    <Flex space_items={[SpaceItems::Small]}>
                        { for StatusCategory::ALL.into_iter().filter_map(|category| {
                            let count = category.products(status).len();
                            (count > 0).then(|| html_nested!(<FlexItem>{ category.label(count) }</FlexItem>))
                        }) }
                    </Flex>
                }
                .into(),
                None => none().into(),
            },
            VulnColumn::Remediations => html!(vuln.remediations.len().to_string()).into(),
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let Some(vuln) = self.vulnerability() else {
            return vec![];
        };
        vec![Span::max(vulnerability_details(&self.doc, self.n, vuln))]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

/// The CVSS values of a score, read from the JSON as the document carries them.
struct Cvss<'a> {
    version: &'a str,
    base_score: Option<f64>,
    base_severity: Option<&'a str>,
    vector: Option<&'a str>,
}

impl<'a> Cvss<'a> {
    /// The CVSS v3 values of a score, or the CVSS v2 ones.
    fn from_score(score: &'a Score) -> Option<Self> {
        Self::from_map(&score.cvss_v3).or_else(|| Self::from_map(&score.cvss_v2))
    }

    fn from_map(map: &'a Map<String, Value>) -> Option<Self> {
        if map.is_empty() {
            return None;
        }
        Some(Self {
            version: map.get("version").and_then(Value::as_str).unwrap_or("?"),
            base_score: map.get("baseScore").and_then(Value::as_f64),
            base_severity: map.get("baseSeverity").and_then(Value::as_str),
            vector: map.get("vectorString").and_then(Value::as_str),
        })
    }

    fn short(&self) -> String {
        let score = self
            .base_score
            .map(|score| format!("{score:.1}"))
            .unwrap_or_else(|| "?".into());
        match self.base_severity {
            Some(severity) => format!("{score} ({severity})"),
            None => score,
        }
    }
}

/// Product IDs and group IDs, resolved to product IDs.
fn resolve(
    doc: &Doc,
    products: Option<&ProductsT>,
    groups: Option<&ProductGroupsT>,
) -> Rc<Vec<String>> {
    Rc::new(
        doc.index.resolve(
            products
                .into_iter()
                .flat_map(|ProductsT(ids)| ids.iter().map(|id| id.as_str())),
            groups
                .into_iter()
                .flat_map(|ProductGroupsT(ids)| ids.iter().map(|id| id.as_str())),
        ),
    )
}

fn products_section(doc: &Doc, title: String, ids: Rc<Vec<String>>) -> Html {
    let title = format!("{title} ({})", ids.len());
    html! {
        <ExpandableSection toggle_text_hidden={title.clone()} toggle_text_expanded={title}>
            <ProductList doc={doc.clone()} {ids} />
        </ExpandableSection>
    }
}

fn vulnerability_details(doc: &Doc, n: usize, vuln: &Vulnerability) -> Html {
    let statuses = vuln
        .product_status
        .as_ref()
        .map(|status| {
            StatusCategory::ALL
                .into_iter()
                .filter_map(|category| {
                    let ids = category.products(status);
                    (!ids.is_empty()).then(|| {
                        (
                            category,
                            Rc::new(ids.iter().map(|id| id.to_string()).collect::<Vec<_>>()),
                        )
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let notes = vuln
        .notes
        .as_ref()
        .map(|notes| notes.0.as_slice())
        .unwrap_or_default();

    html! {
        <Stack gutter=true>
            if !statuses.is_empty() {
                <StackItem>
                    <Title level={Level::H4}>{ "Product status" }</Title>
                    <ProductStatuses doc={doc.clone()} statuses={Rc::new(statuses)} />
                </StackItem>
            }
            if !vuln.scores.is_empty() {
                <StackItem>
                    <Title level={Level::H4}>{ "Scores" }</Title>
                    { for vuln.scores.iter().map(|score| {
                        let title = match Cvss::from_score(score) {
                            Some(cvss) => format!(
                                "CVSS {} {} {}",
                                cvss.version,
                                cvss.short(),
                                cvss.vector.unwrap_or_default(),
                            ),
                            None => "Unknown score".into(),
                        };
                        products_section(doc, title, resolve(doc, Some(&score.products), None))
                    }) }
                </StackItem>
            }
            if !vuln.remediations.is_empty() {
                <StackItem>
                    <Title level={Level::H4}>{ "Remediations" }</Title>
                    <Remediations doc={doc.clone()} vulnerability={n} />
                </StackItem>
            }
            if !vuln.threats.is_empty() {
                <StackItem>
                    <Title level={Level::H4}>{ "Threats" }</Title>
                    <Stack gutter=true>
                        { for vuln.threats.iter().map(|threat| html! {
                            <StackItem>
                                <strong>{ threat.category.to_string() }</strong>
                                <p class="trustify-pre-wrap">{ threat.details.to_string() }</p>
                                if threat.product_ids.is_some() || threat.group_ids.is_some() {
                                    { products_section(
                                        doc,
                                        "Products".into(),
                                        resolve(doc, threat.product_ids.as_ref(), threat.group_ids.as_ref()),
                                    ) }
                                }
                            </StackItem>
                        }) }
                    </Stack>
                </StackItem>
            }
            if let Some(flags) = &vuln.flags {
                <StackItem>
                    <Title level={Level::H4}>{ "Flags" }</Title>
                    { for flags.iter().map(|flag| products_section(
                        doc,
                        flag.label.to_string(),
                        resolve(doc, flag.product_ids.as_ref(), flag.group_ids.as_ref()),
                    )) }
                </StackItem>
            }
            if !notes.is_empty() {
                <StackItem>
                    <Title level={Level::H4}>{ "Notes" }</Title>
                    { notes_list(notes) }
                </StackItem>
            }
        </Stack>
    }
}

/// The highest base score of a vulnerability.
fn max_score(vuln: &Vulnerability) -> Option<f64> {
    vuln.scores
        .iter()
        .filter_map(|score| Cvss::from_score(score)?.base_score)
        .max_by(f64::total_cmp)
}

/// The most severe status category of a vulnerability, by its position in
/// [`StatusCategory::ALL`].
fn most_severe(vuln: &Vulnerability) -> Option<usize> {
    let status = vuln.product_status.as_ref()?;
    StatusCategory::ALL
        .into_iter()
        .position(|category| !category.products(status).is_empty())
}

/// Compare two vulnerabilities (with their positions) by a column, ascending, in document order
/// otherwise. Scores sort by the highest base score, product status by the most severe category.
fn compare_vulnerabilities(
    column: VulnColumn,
    (na, a): (usize, &Vulnerability),
    (nb, b): (usize, &Vulnerability),
) -> Ordering {
    match column {
        VulnColumn::Vulnerability => text(&vulnerability_name(na, a), &vulnerability_name(nb, b)),
        VulnColumn::Cwe => missing_last(
            a.cwe.as_ref().map(|cwe| cwe.id.as_str()),
            b.cwe.as_ref().map(|cwe| cwe.id.as_str()),
        ),
        VulnColumn::Scores => match (max_score(a), max_score(b)) {
            (Some(a), Some(b)) => a.total_cmp(&b),
            (a, b) => missing_last(a.map(|_| ()), b.map(|_| ())),
        },
        VulnColumn::Status => missing_last(most_severe(a), most_severe(b)),
        VulnColumn::Remediations => a.remediations.len().cmp(&b.remediations.len()),
    }
    .then_with(|| na.cmp(&nb))
}

#[function_component(VulnerabilitiesTab)]
pub fn vulnerabilities_tab(props: &VulnerabilitiesTabProps) -> Html {
    let sort = use_sort::<VulnColumn>(None);

    let entries = use_memo((props.doc.clone(), sort.sortby), |(doc, sortby)| {
        let vulnerabilities = &doc.csaf.vulnerabilities;
        let mut order = (0..vulnerabilities.len()).collect::<Vec<_>>();
        if let Some(sortby) = sortby {
            order.sort_by(
                |a, b| match (vulnerabilities.get(*a), vulnerabilities.get(*b)) {
                    (Some(va), Some(vb)) => ordered(
                        sortby.order,
                        compare_vulnerabilities(sortby.index, (*a, va), (*b, vb)),
                    ),
                    _ => Ordering::Equal,
                },
            );
        }
        order
            .into_iter()
            .map(|n| VulnEntry {
                doc: doc.clone(),
                n,
            })
            .collect::<Vec<_>>()
    });

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<VulnColumn>>
            <TableColumn<VulnColumn> label="Vulnerability" index={VulnColumn::Vulnerability} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<VulnColumn> label="CWE" index={VulnColumn::Cwe} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<VulnColumn> label="Scores" index={VulnColumn::Scores} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<VulnColumn> label="Product status" index={VulnColumn::Status} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<VulnColumn> label="Remediations" index={VulnColumn::Remediations} sortby={sort.sortby} onsort={sort.onsort.clone()} />
        </TableHeader<VulnColumn>>
    };

    if props.doc.csaf.vulnerabilities.is_empty() {
        return html! {
            <EmptyState title="No vulnerabilities" icon={Icon::CheckCircle} size={Size::XXXXLarge}>
                { "The document does not contain any vulnerabilities." }
            </EmptyState>
        };
    }

    html! {
        <Table<VulnColumn, UseTableData<VulnColumn, MemoizedTableModel<VulnEntry>>>
            mode={TableMode::Expandable}
            {header}
            {entries}
            {onexpand}
        />
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProductListColumn {
    Product,
    Identifier,
}

#[derive(Clone, PartialEq)]
struct ProductListEntry {
    doc: Doc,
    id: String,
}

impl TableEntryRenderer<ProductListColumn> for ProductListEntry {
    fn render_cell(&self, context: CellContext<'_, ProductListColumn>) -> Cell {
        match context.column {
            ProductListColumn::Product => product_ref(&self.doc.index, &self.id).into(),
            ProductListColumn::Identifier => match self.doc.index.identifiers(&self.id) {
                (Some(identifier), platform) => html! {
                    <>
                        <code>{ identifier }</code>
                        if let Some(platform) = platform {
                            <br />
                            <small>{ "on " }<code>{ platform }</code></small>
                        }
                    </>
                }
                .into(),
                (None, Some(platform)) => {
                    html!(<small>{ "on " }<code>{ platform }</code></small>).into()
                }
                (None, None) => none().into(),
            },
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
struct ProductListProps {
    doc: Doc,
    ids: Rc<Vec<String>>,
}

/// Whether a product matches the (lower case) filter text, by its ID, its name, or its
/// identifiers, including those resolved through a relationship.
fn product_matches(doc: &Doc, id: &str, filter: &str) -> bool {
    let (identifier, platform) = doc.index.identifiers(id);
    [
        Some(id),
        doc.index.get(id).map(|product| product.name.as_str()),
        identifier,
        platform,
    ]
    .into_iter()
    .flatten()
    .any(|value| value.to_lowercase().contains(filter))
}

/// A paginated list of product IDs, resolved to the products.
#[function_component(ProductList)]
fn product_list(props: &ProductListProps) -> Html {
    let total = props.ids.len();
    let pagination = use_pagination(Some(total), Default::default);
    let sort = use_sort::<ProductListColumn>(None);

    let sorted = use_memo(
        (props.doc.clone(), props.ids.clone(), sort.sortby),
        |(doc, ids, sortby)| {
            let mut ids = (**ids).clone();
            if let Some(sortby) = sortby {
                ids.sort_by(|a, b| {
                    let ordering = match sortby.index {
                        ProductListColumn::Product => text(a, b),
                        ProductListColumn::Identifier => {
                            missing_last(doc.index.identifiers(a).0, doc.index.identifiers(b).0)
                        }
                    };
                    ordered(sortby.order, ordering.then_with(|| text(a, b)))
                });
            }
            ids
        },
    );

    let entries = use_memo(
        (props.doc.clone(), sorted.clone(), pagination.state.range()),
        |(doc, ids, range)| {
            ids.get(range.clone())
                .unwrap_or_default()
                .iter()
                .map(|id| ProductListEntry {
                    doc: doc.clone(),
                    id: id.clone(),
                })
                .collect::<Vec<_>>()
        },
    );

    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<ProductListColumn>>
            <TableColumn<ProductListColumn> label="Product" index={ProductListColumn::Product} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<ProductListColumn> label="Identifier" index={ProductListColumn::Identifier} sortby={sort.sortby} onsort={sort.onsort.clone()} />
        </TableHeader<ProductListColumn>>
    };

    html! {
        <>
            if total > pagination.control.per_page {
                <SimplePagination pagination={pagination.clone()} {total} />
            }
            <Table<ProductListColumn, UseTableData<ProductListColumn, MemoizedTableModel<ProductListEntry>>>
                mode={TableMode::Compact}
                {header}
                {entries}
            />
        </>
    }
}

/// The product IDs of each status category of a vulnerability, those without any left out.
type Statuses = Rc<Vec<(StatusCategory, Rc<Vec<String>>)>>;

#[derive(Clone, PartialEq, Properties)]
struct ProductStatusesProps {
    doc: Doc,
    statuses: Statuses,
}

/// The products of each status category, with one filter over all of them.
///
/// While filtering, categories without a match are left out, and those with one are expanded.
#[function_component(ProductStatuses)]
fn product_statuses(props: &ProductStatusesProps) -> Html {
    let filter = use_state_eq(String::new);

    let matching = use_memo(
        (props.doc.clone(), props.statuses.clone(), (*filter).clone()),
        |(doc, statuses, filter)| {
            let filter = filter.trim().to_lowercase();
            statuses
                .iter()
                .map(|(category, ids)| {
                    let matching = match filter.is_empty() {
                        true => ids.clone(),
                        false => Rc::new(
                            ids.iter()
                                .filter(|id| product_matches(doc, id, &filter))
                                .cloned()
                                .collect(),
                        ),
                    };
                    (*category, ids.len(), matching)
                })
                .collect::<Vec<_>>()
        },
    );

    let onfilter = {
        let filter = filter.clone();
        Callback::from(move |value: String| filter.set(value))
    };

    let filtering = !filter.trim().is_empty();
    let any = matching.iter().any(|(_, _, ids)| !ids.is_empty());
    // a single product needs no search
    let searchable = props
        .statuses
        .iter()
        .map(|(_, ids)| ids.len())
        .sum::<usize>()
        > 1;

    html! {
        <>
            if searchable {
                <Toolbar>
                    <ToolbarContent>
                        <ToolbarItem>
                            <TextInput
                                placeholder="Filter all statuses by ID, name, PURL or CPE"
                                onchange={onfilter}
                                value={(*filter).clone()}
                            />
                        </ToolbarItem>
                    </ToolbarContent>
                </Toolbar>
            }
            if !any {
                <p>{ "No product matches the filter." }</p>
            }
            { for matching.iter().filter(|(_, _, ids)| !filtering || !ids.is_empty()).map(|(category, total, ids)| {
                let title = match filtering {
                    true => format!("{} ({} of {total})", category.title(), ids.len()),
                    false => format!("{} ({total})", category.title()),
                };
                html! {
                    <ExpandableSection
                        toggle_text_hidden={title.clone()}
                        toggle_text_expanded={title}
                        expanded={filtering.then_some(true)}
                    >
                        <ProductList doc={props.doc.clone()} ids={ids.clone()} />
                    </ExpandableSection>
                }
            }) }
        </>
    }
}

#[cfg(test)]
mod test {
    use super::{link_label, preview, product_matches};
    use crate::advisory::csaf::parse;

    const DOCUMENT: &str = include_str!("../../../../etc/test-data/csaf/CVE-2024-5154.json");

    #[test]
    fn remediation_preview() {
        assert_eq!(
            [
                "Short.",
                "For OpenShift 4.12 see the following documentation:\n\nhttps://docs.openshift.com/",
                "\n\nLeading blank lines",
                &"x".repeat(130),
            ]
            .map(preview),
            [
                "Short.".to_string(),
                "For OpenShift 4.12 see the following documentation:\u{2026}".to_string(),
                "Leading blank lines".to_string(),
                format!("{}\u{2026}", "x".repeat(120)),
            ]
        );
    }

    #[test]
    fn remediation_link_label() {
        assert_eq!(
            [
                "https://access.redhat.com/errata/RHSA-2024:4008",
                "https://example.com/advisory/",
                "not a url",
            ]
            .map(link_label),
            ["RHSA-2024:4008", "advisory", "not a url"]
        );
    }

    #[test]
    fn filter_products() {
        let doc = parse(DOCUMENT).expect("document parses");
        let id = "8Base-RHOSE-4.12:bpftool-0:4.18.0-372.109.1.el8_6.aarch64";

        assert_eq!(
            [
                // the product ID
                "rhose-4.12:bpftool",
                // the name of the product
                "as a component of red hat openshift",
                // the PURL of the component
                "pkg:rpm/redhat/bpftool@",
                // the CPE of the platform
                "cpe:/a:redhat:openshift:4.12",
                "kernel",
            ]
            .map(|filter| product_matches(&doc, id, filter)),
            [true, true, true, true, false]
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemediationColumn {
    Category,
    Details,
    Link,
    Restart,
    Products,
}

/// A remediation of a vulnerability, by their positions, with its products resolved.
#[derive(Clone, PartialEq)]
struct RemediationEntry {
    doc: Doc,
    vulnerability: usize,
    n: usize,
    products: Rc<Vec<String>>,
}

impl RemediationEntry {
    fn remediation(&self) -> Option<&Remediation> {
        self.doc
            .csaf
            .vulnerabilities
            .get(self.vulnerability)?
            .remediations
            .get(self.n)
    }
}

/// The maximum length of the details shown in the table, the rest is shown when expanding.
const DETAILS_PREVIEW: usize = 120;

/// The first line of a text, shortened to a preview.
fn preview(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default();
    let truncated = line.chars().count() > DETAILS_PREVIEW || text.trim().lines().count() > 1;
    let mut result = line.chars().take(DETAILS_PREVIEW).collect::<String>();
    if truncated {
        result.push('\u{2026}');
    }
    result
}

/// A short label for a link, e.g. the advisory ID at the end of an errata URL.
fn link_label(url: &str) -> &str {
    url.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or(url)
}

fn remediation_category(category: CategoryOfTheRemediation) -> Html {
    let color = match category {
        CategoryOfTheRemediation::VendorFix => Color::Blue,
        CategoryOfTheRemediation::Mitigation | CategoryOfTheRemediation::Workaround => {
            Color::Orange
        }
        CategoryOfTheRemediation::NoFixPlanned | CategoryOfTheRemediation::NoneAvailable => {
            Color::Red
        }
    };
    html!(<Label label={category.to_string().replace('_', " ")} {color} compact=true />)
}

impl TableEntryRenderer<RemediationColumn> for RemediationEntry {
    fn render_cell(&self, context: CellContext<'_, RemediationColumn>) -> Cell {
        let Some(remediation) = self.remediation() else {
            return none().into();
        };

        match context.column {
            RemediationColumn::Category => remediation_category(remediation.category).into(),
            RemediationColumn::Details => html!(preview(&remediation.details)).into(),
            RemediationColumn::Link => match &remediation.url {
                Some(url) => html! {
                    <a href={url.clone()} target="_blank" rel="noopener noreferrer" title={url.clone()}>
                        { link_label(url) }
                    </a>
                }
                .into(),
                None => none().into(),
            },
            RemediationColumn::Restart => match &remediation.restart_required {
                Some(restart) => html!(restart.category.to_string()).into(),
                None => none().into(),
            },
            RemediationColumn::Products => html!(self.products.len().to_string()).into(),
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let Some(remediation) = self.remediation() else {
            return vec![];
        };
        vec![Span::max(html! {
            <Stack gutter=true>
                <StackItem>
                    <p class="trustify-pre-wrap">{ remediation.details.to_string() }</p>
                </StackItem>
                if let Some(details) = remediation.restart_required.as_ref().and_then(|restart| restart.details.as_ref()) {
                    <StackItem>
                        <small>{ "Restart: " }{ details.to_string() }</small>
                    </StackItem>
                }
                if let Some(url) = &remediation.url {
                    <StackItem>
                        <a href={url.clone()} target="_blank" rel="noopener noreferrer">{ url }</a>
                    </StackItem>
                }
                if !self.products.is_empty() {
                    <StackItem>
                        <ProductList doc={self.doc.clone()} ids={self.products.clone()} />
                    </StackItem>
                }
            </Stack>
        })]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

/// Compare two remediations by a column, ascending, in document order otherwise.
fn compare_remediations(
    column: RemediationColumn,
    a: &RemediationEntry,
    b: &RemediationEntry,
) -> Ordering {
    let (Some(ra), Some(rb)) = (a.remediation(), b.remediation()) else {
        return Ordering::Equal;
    };
    match column {
        RemediationColumn::Category => text(&ra.category.to_string(), &rb.category.to_string()),
        RemediationColumn::Details => text(&ra.details, &rb.details),
        RemediationColumn::Link => missing_last(ra.url.as_deref(), rb.url.as_deref()),
        RemediationColumn::Restart => missing_last(
            ra.restart_required
                .as_ref()
                .map(|restart| restart.category.to_string()),
            rb.restart_required
                .as_ref()
                .map(|restart| restart.category.to_string()),
        ),
        RemediationColumn::Products => a.products.len().cmp(&b.products.len()),
    }
    .then_with(|| a.n.cmp(&b.n))
}

#[derive(Clone, PartialEq, Properties)]
struct RemediationsProps {
    doc: Doc,
    /// The position of the vulnerability in the document.
    vulnerability: usize,
}

/// The remediations of a vulnerability, one row each, expanding to the full details and the
/// products.
#[function_component(Remediations)]
fn remediations(props: &RemediationsProps) -> Html {
    let sort = use_sort::<RemediationColumn>(None);

    let entries = use_memo(
        (props.doc.clone(), props.vulnerability, sort.sortby),
        |(doc, vulnerability, sortby)| {
            let mut entries = doc
                .csaf
                .vulnerabilities
                .get(*vulnerability)
                .map(|vuln| {
                    vuln.remediations
                        .iter()
                        .enumerate()
                        .map(|(n, remediation)| RemediationEntry {
                            doc: doc.clone(),
                            vulnerability: *vulnerability,
                            n,
                            products: resolve(
                                doc,
                                remediation.product_ids.as_ref(),
                                remediation.group_ids.as_ref(),
                            ),
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if let Some(sortby) = sortby {
                entries.sort_by(|a, b| {
                    ordered(sortby.order, compare_remediations(sortby.index, a, b))
                });
            }
            entries
        },
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<RemediationColumn>>
            <TableColumn<RemediationColumn> label="Category" index={RemediationColumn::Category} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<RemediationColumn> label="Details" index={RemediationColumn::Details} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<RemediationColumn> label="Link" index={RemediationColumn::Link} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<RemediationColumn> label="Restart" index={RemediationColumn::Restart} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<RemediationColumn> label="Products" index={RemediationColumn::Products} sortby={sort.sortby} onsort={sort.onsort.clone()} />
        </TableHeader<RemediationColumn>>
    };

    html! {
        <Table<RemediationColumn, UseTableData<RemediationColumn, MemoizedTableModel<RemediationEntry>>>
            mode={TableMode::CompactExpandable}
            {header}
            {entries}
            {onexpand}
        />
    }
}
