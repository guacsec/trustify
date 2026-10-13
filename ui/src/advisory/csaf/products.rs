//! All products of a CSAF document, with their identification helpers.

use super::{
    Doc,
    index::{Product, ProductOrigin},
    none, product_ref,
    status::{StatusCategory, StatusCounts, status_counts, status_labels},
    vulnerability_name,
};
use crate::sort::{missing_last, ordered, text, use_sort};
use ::csaf::schema::csaf2_0::schema::{ProductGroupsT, ProductsT, Remediation};
use patternfly_yew::prelude::*;
use std::{cmp::Ordering, rc::Rc};
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct ProductsTabProps {
    pub doc: Doc,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProductColumn {
    Id,
    Name,
    Origin,
    Status,
}

/// A product of the index, by its position.
#[derive(Clone, PartialEq)]
struct ProductEntry {
    doc: Doc,
    n: usize,
    statuses: Rc<StatusCounts>,
}

impl ProductEntry {
    fn product(&self) -> Option<&Product> {
        self.doc.index.products().get(self.n)
    }
}

impl TableEntryRenderer<ProductColumn> for ProductEntry {
    fn render_cell(&self, context: CellContext<'_, ProductColumn>) -> Cell {
        let Some(product) = self.product() else {
            return none().into();
        };

        match context.column {
            ProductColumn::Id => html!(<code>{ &product.id }</code>).into(),
            ProductColumn::Name => html!(&product.name).into(),
            ProductColumn::Origin => html!(product.origin.label()).into(),
            ProductColumn::Status => status_labels(self.statuses.get(&product.id)).into(),
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let Some(product) = self.product() else {
            return vec![];
        };
        vec![Span::max(product_details(&self.doc, product))]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

/// The details of a product: its definition, and its status for each vulnerability.
fn product_details(doc: &Doc, product: &Product) -> Html {
    html! {
        <Stack gutter=true>
            <StackItem>{ product_definition(doc, product) }</StackItem>
            <StackItem>
                <Title level={Level::H4}>{ "Vulnerabilities" }</Title>
                { product_vulnerabilities(doc, &product.id) }
            </StackItem>
        </Stack>
    }
}

/// Whether a remediation applies to a product, directly or through a product group.
fn remediation_applies(doc: &Doc, remediation: &Remediation, id: &str) -> bool {
    let products = remediation
        .product_ids
        .iter()
        .flat_map(|ProductsT(ids)| ids.iter().map(|id| id.as_str()));
    let groups = remediation
        .group_ids
        .iter()
        .flat_map(|ProductGroupsT(ids)| ids.iter().map(|id| id.as_str()));
    doc.index
        .resolve(products, groups)
        .iter()
        .any(|product| product == id)
}

/// A vulnerability stating something about a product: its name, the statuses of the product,
/// and the remediations applying to it.
type VulnerabilityRow<'a> = (String, Vec<StatusCategory>, Vec<&'a Remediation>);

/// The vulnerabilities which state a status or a remediation for a product.
fn vulnerability_rows<'a>(doc: &'a Doc, id: &str) -> Vec<VulnerabilityRow<'a>> {
    doc.csaf
        .vulnerabilities
        .iter()
        .enumerate()
        .filter_map(|(n, vuln)| {
            let statuses = vuln
                .product_status
                .as_ref()
                .map(|status| {
                    StatusCategory::ALL
                        .into_iter()
                        .filter(|category| {
                            category
                                .products(status)
                                .iter()
                                .any(|product| product.as_str() == id)
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let remediations = vuln
                .remediations
                .iter()
                .filter(|remediation| remediation_applies(doc, remediation, id))
                .collect::<Vec<_>>();

            (!statuses.is_empty() || !remediations.is_empty())
                .then(|| (vulnerability_name(n, vuln), statuses, remediations))
        })
        .collect()
}

/// The status of a product for each vulnerability which states one, with the remediations
/// applying to it.
fn product_vulnerabilities(doc: &Doc, id: &str) -> Html {
    let rows = vulnerability_rows(doc, id);

    if rows.is_empty() {
        return html!(<p>{ "The document states no status for this product." }</p>);
    }

    html! {
        <DescriptionList mode={[DescriptionListMode::Horizontal.all()]} compact=true>
            { for rows.into_iter().map(|(name, statuses, remediations)| html! {
                <DescriptionGroup term={name}>
                    <Flex space_items={[SpaceItems::Small]}>
                        { for statuses.into_iter().map(|category| html_nested! {
                            <FlexItem>
                                <Label label={category.title()} color={category.color()} compact=true />
                            </FlexItem>
                        }) }
                    </Flex>
                    { for remediations.into_iter().map(|remediation| html! {
                        <div>
                            <small>
                                <strong>{ remediation.category.to_string() }</strong>
                                { ": " }
                                { remediation.details.to_string() }
                                if let Some(url) = &remediation.url {
                                    { " " }
                                    <a href={url.clone()} target="_blank" rel="noopener noreferrer">{ url }</a>
                                }
                            </small>
                        </div>
                    }) }
                </DescriptionGroup>
            }) }
        </DescriptionList>
    }
}

/// Where the product is defined, and all of its identification helpers.
fn product_definition(doc: &Doc, product: &Product) -> Html {
    let origin = match &product.origin {
        ProductOrigin::Branch(path) => html!(path.join(" \u{203a} ")),
        ProductOrigin::FullProductName => html!("Full product name"),
        ProductOrigin::Relationship {
            category,
            product_reference,
            relates_to,
        } => html! {
            <>
                { product_ref(&doc.index, product_reference) }
                <br />
                <strong>{ category.to_string() }</strong>
                <br />
                { product_ref(&doc.index, relates_to) }
            </>
        },
    };

    let Some(helper) = &product.helper else {
        return html! {
            <DescriptionList mode={[DescriptionListMode::Horizontal.all()]} compact=true>
                <DescriptionGroup term="Defined by">{ origin }</DescriptionGroup>
                <DescriptionGroup term="Identification helper">{ none() }</DescriptionGroup>
            </DescriptionList>
        };
    };

    let list = |values: Vec<String>| -> Html {
        html! {
            <List>
                { for values.into_iter().map(|value| html_nested!(<ListItem><code>{ value }</code></ListItem>)) }
            </List>
        }
    };

    html! {
        <DescriptionList mode={[DescriptionListMode::Horizontal.all()]} compact=true>
            <DescriptionGroup term="Defined by">{ origin }</DescriptionGroup>
            if let Some(purl) = &helper.purl {
                <DescriptionGroup term="PURL"><code>{ purl.to_string() }</code></DescriptionGroup>
            }
            if let Some(cpe) = &helper.cpe {
                <DescriptionGroup term="CPE"><code>{ cpe.to_string() }</code></DescriptionGroup>
            }
            if !helper.hashes.is_empty() {
                <DescriptionGroup term="Hashes">
                    { list(helper.hashes.iter().flat_map(|hashes| hashes.file_hashes.iter().map(|hash| {
                        format!("{}: {}:{}", *hashes.filename, *hash.algorithm, *hash.value)
                    })).collect()) }
                </DescriptionGroup>
            }
            if !helper.sbom_urls.is_empty() {
                <DescriptionGroup term="SBOM URLs">{ list(helper.sbom_urls.clone()) }</DescriptionGroup>
            }
            if let Some(serial_numbers) = &helper.serial_numbers {
                <DescriptionGroup term="Serial numbers">
                    { list(serial_numbers.iter().map(|n| n.to_string()).collect()) }
                </DescriptionGroup>
            }
            if let Some(model_numbers) = &helper.model_numbers {
                <DescriptionGroup term="Model numbers">
                    { list(model_numbers.iter().map(|n| n.to_string()).collect()) }
                </DescriptionGroup>
            }
            if !helper.skus.is_empty() {
                <DescriptionGroup term="SKUs">
                    { list(helper.skus.iter().map(|sku| sku.to_string()).collect()) }
                </DescriptionGroup>
            }
            if !helper.x_generic_uris.is_empty() {
                <DescriptionGroup term="Generic URIs">
                    { list(helper.x_generic_uris.iter().map(|uri| format!("{} ({})", uri.uri, uri.namespace)).collect()) }
                </DescriptionGroup>
            }
        </DescriptionList>
    }
}

/// The status categories selected to filter by, in the order of [`StatusCategory::ALL`].
type SelectedStatuses = [bool; StatusCategory::ALL.len()];

/// A count per status category, in the order of [`StatusCategory::ALL`].
type SelectedCounts = [usize; StatusCategory::ALL.len()];

/// Whether a product has one of the selected status categories. Without a selection, every
/// product does.
fn has_status(counts: Option<&SelectedCounts>, selected: &SelectedStatuses) -> bool {
    if !selected.iter().any(|selected| *selected) {
        return true;
    }
    counts.is_some_and(|counts| {
        counts
            .iter()
            .zip(selected)
            .any(|(count, selected)| *selected && *count > 0)
    })
}

/// The most severe status category of a product, by its position in [`StatusCategory::ALL`].
fn most_severe(statuses: &StatusCounts, id: &str) -> Option<usize> {
    statuses.get(id)?.iter().position(|count| *count > 0)
}

/// Compare two products by a column, ascending. Status sorts by the most severe category, products
/// without a status last.
fn compare(column: ProductColumn, statuses: &StatusCounts, a: &Product, b: &Product) -> Ordering {
    match column {
        ProductColumn::Id => text(&a.id, &b.id),
        ProductColumn::Name => text(&a.name, &b.name),
        ProductColumn::Origin => text(&a.origin.label(), &b.origin.label()),
        ProductColumn::Status => {
            missing_last(most_severe(statuses, &a.id), most_severe(statuses, &b.id))
        }
    }
    .then_with(|| text(&a.id, &b.id))
}

/// Whether a product matches the (lower case) filter text, by its ID, its name, or its
/// identifiers, including those resolved through a relationship.
fn matches(doc: &Doc, product: &Product, filter: &str) -> bool {
    let (identifier, platform) = doc.index.identifiers(&product.id);
    [
        Some(product.id.as_str()),
        Some(product.name.as_str()),
        identifier,
        platform,
    ]
    .into_iter()
    .flatten()
    .any(|value| value.to_lowercase().contains(filter))
}

#[function_component(ProductsTab)]
pub fn products_tab(props: &ProductsTabProps) -> Html {
    let filter = use_state_eq(String::new);
    let selected_statuses = use_state_eq(SelectedStatuses::default);

    let statuses = use_memo(props.doc.clone(), status_counts);
    let sort = use_sort::<ProductColumn>(None);

    // the number of products of each status category, in the order of `StatusCategory::ALL`
    let category_totals = use_memo(statuses.clone(), |statuses| {
        let mut totals = SelectedCounts::default();
        for counts in statuses.values() {
            for (total, count) in totals.iter_mut().zip(counts) {
                if *count > 0 {
                    *total += 1;
                }
            }
        }
        totals
    });

    let matching = use_memo(
        (
            props.doc.clone(),
            statuses.clone(),
            (*filter).clone(),
            *selected_statuses,
            sort.sortby,
        ),
        |(doc, statuses, filter, selected_statuses, sortby)| {
            let filter = filter.trim().to_lowercase();
            let products = doc.index.products();
            let mut matching = products
                .iter()
                .enumerate()
                .filter(|(_, product)| has_status(statuses.get(&product.id), selected_statuses))
                .filter(|(_, product)| filter.is_empty() || matches(doc, product, &filter))
                .map(|(n, _)| n)
                .collect::<Vec<_>>();
            if let Some(sortby) = sortby {
                matching.sort_by(|a, b| match (products.get(*a), products.get(*b)) {
                    (Some(a), Some(b)) => {
                        ordered(sortby.order, compare(sortby.index, statuses, a, b))
                    }
                    _ => Ordering::Equal,
                });
            }
            matching
        },
    );

    let total = matching.len();
    let pagination = use_pagination(Some(total), Default::default);

    let entries = use_memo(
        (
            props.doc.clone(),
            matching.clone(),
            statuses.clone(),
            pagination.state.range(),
        ),
        |(doc, matching, statuses, range)| {
            matching
                .get(range.clone())
                .unwrap_or_default()
                .iter()
                .map(|&n| ProductEntry {
                    doc: doc.clone(),
                    n,
                    statuses: statuses.clone(),
                })
                .collect::<Vec<_>>()
        },
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    let onfilter = {
        let filter = filter.clone();
        Callback::from(move |value: String| filter.set(value))
    };

    // a checkbox for each status category the document has products for
    let status_options = StatusCategory::ALL
        .into_iter()
        .enumerate()
        .filter(|(n, _)| category_totals[*n] > 0)
        .map(|(n, category)| {
            let onchange = {
                let selected_statuses = selected_statuses.clone();
                Callback::from(move |checked| {
                    let mut selected = *selected_statuses;
                    selected[n] = checked;
                    selected_statuses.set(selected);
                })
            };
            html_nested! {
                <MenuCheckbox checked={selected_statuses[n]} {onchange}>
                    { format!("{} ({})", category.title(), category_totals[n]) }
                </MenuCheckbox>
            }
        })
        .collect::<Vec<_>>();
    let status_text = match selected_statuses
        .iter()
        .filter(|selected| **selected)
        .count()
    {
        0 => "Filter by status".to_string(),
        count => format!("Status ({count} selected)"),
    };

    let header = html_nested! {
        <TableHeader<ProductColumn>>
            <TableColumn<ProductColumn> label="Product ID" index={ProductColumn::Id} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<ProductColumn> label="Name" index={ProductColumn::Name} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<ProductColumn> label="Defined by" index={ProductColumn::Origin} sortby={sort.sortby} onsort={sort.onsort.clone()} />
            <TableColumn<ProductColumn> label="Status" index={ProductColumn::Status} sortby={sort.sortby} onsort={sort.onsort.clone()} />
        </TableHeader<ProductColumn>>
    };

    html! {
        <>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem>
                        <TextInput
                            placeholder="Filter by ID, name, PURL or CPE"
                            onchange={onfilter}
                            value={(*filter).clone()}
                        />
                    </ToolbarItem>
                    { for (!status_options.is_empty()).then(|| html_nested! {
                        <ToolbarItem>
                            <Dropdown text={html!(status_text)}>
                                { for status_options }
                            </Dropdown>
                        </ToolbarItem>
                    }) }
                    <ToolbarItem r#type={ToolbarItemType::Pagination}>
                        <SimplePagination pagination={pagination.clone()} {total} />
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>
            <Table<ProductColumn, UseTableData<ProductColumn, MemoizedTableModel<ProductEntry>>>
                mode={TableMode::CompactExpandable}
                {header}
                {entries}
                {onexpand}
            />
            <SimplePagination {pagination} {total} position={PaginationPosition::Bottom} />
        </>
    }
}

#[cfg(test)]
mod test {
    use super::{ProductColumn, compare, has_status, status_counts, vulnerability_rows};
    use crate::advisory::csaf::{parse, status::StatusCategory};

    const DOCUMENT: &str = include_str!("../../../../etc/test-data/csaf/CVE-2024-5154.json");

    /// The statuses and remediation categories stated for a product.
    fn rows(id: &str) -> Vec<(String, Vec<StatusCategory>, Vec<String>)> {
        let doc = parse(DOCUMENT).expect("document parses");
        vulnerability_rows(&doc, id)
            .into_iter()
            .map(|(name, statuses, remediations)| {
                (
                    name,
                    statuses,
                    remediations
                        .into_iter()
                        .map(|remediation| remediation.category.to_string())
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn filter_by_status() {
        // known affected (first) and fixed (seventh)
        let counts = [1, 0, 0, 0, 0, 0, 2, 0];
        let select = |positions: &[usize]| {
            let mut selected = [false; 8];
            for n in positions {
                selected[*n] = true;
            }
            selected
        };

        assert_eq!(
            [
                has_status(Some(&counts), &select(&[])),
                has_status(Some(&counts), &select(&[0])),
                has_status(Some(&counts), &select(&[4, 6])),
                has_status(Some(&counts), &select(&[4])),
                has_status(None, &select(&[])),
                has_status(None, &select(&[0])),
            ],
            [true, true, true, false, true, false]
        );
    }

    #[test]
    fn sort_by_status() {
        let doc = parse(DOCUMENT).expect("document parses");
        let statuses = status_counts(&doc);

        let mut products = doc.index.products().iter().collect::<Vec<_>>();
        products.sort_by(|a, b| compare(ProductColumn::Status, &statuses, a, b));

        // the most severe first, products without a status last
        assert_eq!(
            (
                products.first().map(|product| product.id.as_str()),
                products
                    .last()
                    .map(|product| statuses.contains_key(&product.id)),
            ),
            (
                Some("red_hat_openshift_container_platform_3.11:cri-o"),
                Some(false)
            )
        );
    }

    #[test]
    fn product_status_counts() {
        let doc = parse(DOCUMENT).expect("document parses");
        let counts = status_counts(&doc);
        let categories = |id: &str| {
            counts.get(id).map(|counts| {
                StatusCategory::ALL
                    .into_iter()
                    .zip(counts)
                    .filter(|(_, count)| **count > 0)
                    .map(|(category, count)| (category, *count))
                    .collect::<Vec<_>>()
            })
        };

        assert_eq!(
            [
                "8Base-RHOSE-4.12:cri-o-0:1.25.5-21.2.rhaos4.12.gita3eb75f.el8.aarch64",
                "red_hat_openshift_container_platform_3.11:cri-o",
                "8Base-RHOSE-4.12",
            ]
            .map(categories),
            [
                Some(vec![(StatusCategory::Fixed, 1)]),
                Some(vec![(StatusCategory::KnownAffected, 1)]),
                None,
            ]
        );
    }

    #[test]
    fn products_with_status() {
        let doc = parse(DOCUMENT).expect("document parses");
        let statuses = status_counts(&doc);

        assert_eq!(
            (
                statuses.len(),
                [
                    "8Base-RHOSE-4.12:bpftool-0:4.18.0-372.109.1.el8_6.aarch64",
                    "red_hat_openshift_container_platform_3.11:cri-o",
                    // a platform, which components relate to
                    "8Base-RHOSE-4.12",
                ]
                .map(|id| statuses.contains_key(id)),
            ),
            (621, [true, true, false])
        );
    }

    #[test]
    fn product_statuses() {
        assert_eq!(
            rows("8Base-RHOSE-4.12:cri-o-0:1.25.5-21.2.rhaos4.12.gita3eb75f.el8.aarch64"),
            vec![(
                "CVE-2024-5154".to_string(),
                vec![StatusCategory::Fixed],
                vec!["vendor_fix".to_string(), "workaround".to_string()],
            )]
        );
        assert_eq!(
            rows("red_hat_openshift_container_platform_3.11:cri-o"),
            vec![(
                "CVE-2024-5154".to_string(),
                vec![StatusCategory::KnownAffected],
                vec!["workaround".to_string(), "no_fix_planned".to_string()],
            )]
        );
        // a platform has no status of its own
        assert_eq!(rows("8Base-RHOSE-4.12"), vec![]);
    }
}
