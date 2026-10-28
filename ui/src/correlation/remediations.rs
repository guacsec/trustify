//! Paginated advisory remediations and their provenance.
use super::{
    CorrelationContentProps,
    common::{remediation, status_label},
    pagination::{page_status, use_collection},
};
use crate::advisory::advisory_link;
use patternfly_yew::prelude::*;
use trustify_api::correlation::SbomRemediation;
use yew::prelude::*;

/// Show one page of remediations with resolved verdict status and advisory provenance.
#[function_component(RemediationTable)]
pub(super) fn remediation_table(props: &CorrelationContentProps) -> Html {
    let (page, pagination, loading, error) =
        use_collection::<SbomRemediation>(props.sbom_id, "/remediations", false);
    let total = page.total.and_then(|n| usize::try_from(n).ok());
    let rows = use_memo(page.items.clone(), |items| {
        items
            .iter()
            .cloned()
            .map(RemediationEntry)
            .collect::<Vec<_>>()
    });
    let (entries, _) = use_table_data(MemoizedTableModel::new(rows));
    let header = html_nested! {
        <TableHeader<RemediationColumn>>
            <TableColumn<RemediationColumn> label="Component" index={RemediationColumn::Component} />
            <TableColumn<RemediationColumn> label="Vulnerability" index={RemediationColumn::Vulnerability} />
            <TableColumn<RemediationColumn> label="Status" index={RemediationColumn::Status} />
            <TableColumn<RemediationColumn> label="Remediation" index={RemediationColumn::Remediation} />
            <TableColumn<RemediationColumn> label="Advisory" index={RemediationColumn::Advisory} />
        </TableHeader<RemediationColumn>>
    };
    html! {
        <>
            <Title level={Level::H2}>{"Remediations "}<Badge>{page.total.map(|n| n.to_string()).unwrap_or_default()}</Badge></Title>
            <p>{"What the advisories state to remediate the vulnerabilities of the components, e.g. the version fixing them."}</p>
            <SimplePagination {pagination} {total} />
            {page_status(&page, loading, error.as_deref(), "No remediations")}
            if !loading && error.is_none() && !page.items.is_empty() {
                <Table<RemediationColumn, UseTableData<RemediationColumn, MemoizedTableModel<RemediationEntry>>>
                    mode={TableMode::Compact} {header} {entries}
                />
            }
        </>
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemediationColumn {
    Component,
    Vulnerability,
    Status,
    Remediation,
    Advisory,
}

/// A remediation an advisory states for the statement of a verdict's evidence.
#[derive(Clone, PartialEq)]
struct RemediationEntry(SbomRemediation);

impl TableEntryRenderer<RemediationColumn> for RemediationEntry {
    fn render_cell(&self, context: CellContext<'_, RemediationColumn>) -> Cell {
        match context.column {
            RemediationColumn::Component => Cell::new(html! {
                <div>
                    { &self.0.component.name }
                    <div class="pf-v6-u-text-color-subtle pf-v6-u-font-size-sm">
                        <code style="color: inherit;">{ &self.0.component.node_id }</code>
                    </div>
                </div>
            })
            .text_modifier(TextModifier::NoWrap),
            RemediationColumn::Vulnerability => {
                html!(<strong>{ &self.0.vulnerability }</strong>).into()
            }
            RemediationColumn::Status => status_label(self.0.status).into(),
            RemediationColumn::Remediation => remediation(&self.0.remediation).into(),
            RemediationColumn::Advisory => advisory_link(
                self.0.advisory_id,
                &self.0.advisory_identifier,
                self.0.advisory_type.as_deref(),
            )
            .into(),
        }
    }
}
