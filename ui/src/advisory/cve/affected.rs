//! The affected products of a CVE record, of all its containers.
//!
//! The identifier-like fields of an entry (`vendor` and `product`, `collectionURL` and
//! `packageName`, `packageURL`, `cpes`) are synonyms of the same software (see the CVE schema's RFD
//! "Supporting Package URLs"): its versions and default status apply to each of them.

use super::{Container, Doc, none, provider_label};
use ::cve::common::{Product, Range, Status, Version, VersionRange};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct AffectedTabProps {
    pub doc: Doc,
}

fn status_label(status: &Status) -> Html {
    let (label, color) = match status {
        Status::Affected => ("affected", Color::Red),
        Status::Unaffected => ("unaffected", Color::Green),
        Status::Unknown => ("unknown", Color::Grey),
    };
    html!(<Label {label} {color} compact=true />)
}

/// An upper bound, `None` for `*` (no upper bound). A bound ending in `*` (e.g. `5.4.*`) is
/// "an arbitrarily large number in the version ordering": the whole branch.
fn upper_bound(range: &VersionRange) -> Option<String> {
    let (bound, inclusive) = match range {
        VersionRange::LessThan(bound) => (bound, false),
        VersionRange::LessThanOrEqual(bound) => (bound, true),
    };
    match bound.strip_suffix('*') {
        Some("") => None,
        Some(branch) => Some(format!("<= {branch}x")),
        None if inclusive => Some(format!("<= {bound}")),
        None => Some(format!("< {bound}")),
    }
}

/// The versions of a range, e.g. `>= 5.4.269, <= 5.4.x`.
fn range_versions(range: &Range) -> String {
    let low = format!(">= {}", range.version);
    match upper_bound(&range.range) {
        Some(high) => format!("{low}, {high}"),
        None => low,
    }
}

/// How correlation reads an entry differently from what one may expect.
fn hints(product: &Product) -> Vec<String> {
    let mut hints = Vec::new();

    if let Some(purl) = &product.package_url
        && purl
            .split(['?', '#'])
            .next()
            .is_some_and(|p| p.contains('@'))
    {
        hints.push(
            "The packageURL has a version, although it must not include one. The version is \
             ignored."
                .to_string(),
        );
    }
    let ranges = product.versions.iter().filter_map(|version| match version {
        Version::Range(range) => Some(range),
        Version::Single(_) => None,
    });
    if ranges.clone().any(|range| range.version_type == "custom") {
        hints.push(
            "A range of the version type 'custom' has an unspecified versioning scheme. It is \
             evaluated with the scheme of the package's PURL type."
                .to_string(),
        );
    }
    if product.versions.iter().any(
        |version| matches!(version, Version::Single(single) if single.status == Status::Unknown),
    ) || ranges.clone().any(|range| range.status == Status::Unknown)
    {
        hints.push("The status 'unknown' states nothing about a version.".to_string());
    }

    hints
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AffectedColumn {
    Source,
    Product,
    Package,
    Cpes,
    Default,
    Versions,
}

/// An affected entry, by its container and position.
#[derive(Clone, PartialEq)]
struct AffectedEntry {
    doc: Doc,
    container: usize,
    n: usize,
}

impl AffectedEntry {
    fn with<T>(&self, f: impl FnOnce(&Container<'_>, &Product) -> T) -> Option<T> {
        let containers = self.doc.containers();
        let container = containers.get(self.container)?;
        let product = container.affected.get(self.n)?;
        Some(f(container, product))
    }
}

impl TableEntryRenderer<AffectedColumn> for AffectedEntry {
    fn render_cell(&self, context: CellContext<'_, AffectedColumn>) -> Cell {
        self.with(|container, product| match context.column {
            AffectedColumn::Source => provider_label(container),
            AffectedColumn::Product => html! {
                <>
                    <strong>{ product.product.as_deref().unwrap_or("\u{2014}") }</strong>
                    if let Some(vendor) = &product.vendor {
                        <br />
                        <small>{ vendor }</small>
                    }
                    if !hints(product).is_empty() {
                        { " " }
                        <Label label="Note" color={Color::Orange} compact=true />
                    }
                </>
            },
            AffectedColumn::Package => match (&product.package_url, &product.package_name) {
                (Some(purl), _) => html!(<code>{ purl }</code>),
                (None, Some(name)) => html! {
                    <>
                        <code>{ name }</code>
                        if let Some(collection) = &product.collection_url {
                            <br />
                            <small>{ collection }</small>
                        }
                    </>
                },
                (None, None) => none(),
            },
            AffectedColumn::Cpes => html!(product.cpes.len().to_string()),
            AffectedColumn::Default => product
                .default_status
                .as_ref()
                .map(status_label)
                .unwrap_or_else(|| html!(<i>{ "unknown" }</i>)),
            AffectedColumn::Versions => html!(product.versions.len().to_string()),
        })
        .unwrap_or_else(none)
        .into()
    }

    fn render_details(&self) -> Vec<Span> {
        self.with(|_, product| vec![Span::max(product_details(product))])
            .unwrap_or_default()
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

/// A list of values, if any.
fn values(term: &'static str, values: &[String]) -> Html {
    if values.is_empty() {
        return html!();
    }
    html! {
        <DescriptionGroup {term}>
            <Flex space_items={[SpaceItems::Small]}>
                { for values.iter().map(|v| html_nested!(<FlexItem><code>{ v }</code></FlexItem>)) }
            </Flex>
        </DescriptionGroup>
    }
}

fn product_details(product: &Product) -> Html {
    let routines = product
        .program_routines
        .iter()
        .map(|routine| routine.name.clone())
        .collect::<Vec<_>>();

    html! {
        <Stack gutter=true>
            { for hints(product).into_iter().map(|hint| html_nested! {
                <StackItem>
                    <Alert title={hint} r#type={AlertType::Info} inline=true plain=true />
                </StackItem>
            }) }
            <StackItem>
                <DescriptionList mode={[DescriptionListMode::Horizontal.all()]} compact=true>
                    { values("CPEs", &product.cpes) }
                    { values("Platforms", &product.platforms) }
                    { values("Modules", &product.modules) }
                    { values("Program files", &product.program_files) }
                    { values("Program routines", &routines) }
                    if let Some(repo) = &product.repository {
                        <DescriptionGroup term="Repository">
                            <a href={repo.clone()} target="_blank" rel="noopener noreferrer">{ repo }</a>
                        </DescriptionGroup>
                    }
                </DescriptionList>
            </StackItem>
            <StackItem>
                <List>
                    { for product.versions.iter().map(|version| html_nested!(<ListItem>{ version_item(version) }</ListItem>)) }
                    <ListItem>
                        { product.default_status.as_ref().map(status_label).unwrap_or_else(|| status_label(&Status::Unknown)) }
                        { " all other versions (default)" }
                    </ListItem>
                </List>
            </StackItem>
        </Stack>
    }
}

/// A listed version or range, with its changes.
fn version_item(version: &Version) -> Html {
    match version {
        Version::Single(single) => html! {
            <>
                { status_label(&single.status) }
                { " " }
                <code>{ format!("= {}", single.version) }</code>
                if let Some(version_type) = &single.version_type {
                    <small>{ format!(" ({version_type})") }</small>
                }
            </>
        },
        Version::Range(range) => html! {
            <>
                { status_label(&range.status) }
                { " " }
                <code>{ range_versions(range) }</code>
                <small>{ format!(" ({})", range.version_type) }</small>
                if !range.changes.is_empty() {
                    <List>
                        { for range.changes.iter().map(|change| html_nested! {
                            <ListItem>
                                { "from " }<code>{ &change.at }</code>{ " " }
                                { status_label(&change.status) }
                            </ListItem>
                        }) }
                    </List>
                }
            </>
        },
    }
}

#[function_component(AffectedTab)]
pub fn affected_tab(props: &AffectedTabProps) -> Html {
    let entries = use_memo(props.doc.clone(), |doc| {
        doc.containers()
            .iter()
            .enumerate()
            .flat_map(|(container, c)| {
                (0..c.affected.len()).map(move |n| AffectedEntry {
                    doc: doc.clone(),
                    container,
                    n,
                })
            })
            .collect::<Vec<_>>()
    });

    let empty = entries.is_empty();
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    if empty {
        return html! {
            <EmptyState title="No affected products" icon={Icon::InfoCircle} size={Size::XXXXLarge}>
                { "The record does not state any affected products." }
            </EmptyState>
        };
    }

    let header = html_nested! {
        <TableHeader<AffectedColumn>>
            <TableColumn<AffectedColumn> label="Source" index={AffectedColumn::Source} />
            <TableColumn<AffectedColumn> label="Product" index={AffectedColumn::Product} />
            <TableColumn<AffectedColumn> label="Package" index={AffectedColumn::Package} />
            <TableColumn<AffectedColumn> label="CPEs" index={AffectedColumn::Cpes} />
            <TableColumn<AffectedColumn> label="Default" index={AffectedColumn::Default} />
            <TableColumn<AffectedColumn> label="Versions" index={AffectedColumn::Versions} />
        </TableHeader<AffectedColumn>>
    };

    html! {
        <Table<AffectedColumn, UseTableData<AffectedColumn, MemoizedTableModel<AffectedEntry>>>
            mode={TableMode::Expandable}
            {header}
            {entries}
            {onexpand}
        />
    }
}

#[cfg(test)]
mod test {
    use super::{super::parse, *};

    const KERNEL: &str = include_str!(
        "../../../../etc/test-data/scenarios/S26_cve_cpe_applicability_kernel/cve/CVE-2024-26581.json"
    );
    const PYTEST: &str = include_str!(
        "../../../../etc/test-data/scenarios/S25_cve_package_url/cve/CVE-2025-71176.json"
    );

    /// The ranges of an entry, as shown.
    fn ranges(document: &str, n: usize) -> Vec<String> {
        let doc = parse(document).expect("record parses");
        let containers = doc.containers();
        containers[0].affected[n]
            .versions
            .iter()
            .filter_map(|version| match version {
                Version::Range(range) => Some(range_versions(range)),
                Version::Single(_) => None,
            })
            .collect()
    }

    /// The semver ranges of the Linux kernel (CVE-2024-26581), with wildcards.
    #[test]
    fn wildcards() {
        assert_eq!(
            ranges(KERNEL, 1),
            [
                ">= 0, < 6.5",
                ">= 5.4.269, <= 5.4.x",
                ">= 5.10.210, <= 5.10.x",
                ">= 5.15.149, <= 5.15.x",
                ">= 6.1.78, <= 6.1.x",
                ">= 6.6.17, <= 6.6.x",
                ">= 6.7.5, <= 6.7.x",
                ">= 6.8",
            ]
        );
    }

    /// pytest (CVE-2025-71176): a `custom` range of a `packageURL`.
    #[test]
    fn custom_hint() {
        let doc = parse(PYTEST).expect("record parses");
        let containers = doc.containers();
        assert_eq!(
            hints(&containers[0].affected[0]),
            [
                "A range of the version type 'custom' has an unspecified versioning scheme. It is \
              evaluated with the scheme of the package's PURL type."
            ]
        );
    }
}
