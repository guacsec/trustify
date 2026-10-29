//! Paginated components without correlation evidence.
use super::{
    CorrelationContentProps,
    common::identifiers,
    pagination::{page_status, use_collection},
};
use crate::model::ComponentRef;
use patternfly_yew::prelude::*;
use yew::prelude::*;

/// Show one page of unmatched components and their identifiers.
#[function_component(UnmatchedTable)]
pub(super) fn unmatched_table(props: &CorrelationContentProps) -> Html {
    let (page, pagination, loading, error, ..) =
        use_collection::<ComponentRef>(props.sbom_id, "/unmatched", false);
    let total = page.total.and_then(|n| usize::try_from(n).ok());
    let rows = use_memo(page.items.clone(), |items| {
        items
            .iter()
            .cloned()
            .map(UnmatchedEntry)
            .collect::<Vec<_>>()
    });
    let (entries, _) = use_table_data(MemoizedTableModel::new(rows));
    let header = html_nested! {
        <TableHeader<UnmatchedColumn>>
            <TableColumn<UnmatchedColumn> label="Component" index={UnmatchedColumn::Name} />
            <TableColumn<UnmatchedColumn> label="Identifiers" index={UnmatchedColumn::Identifiers} />
        </TableHeader<UnmatchedColumn>>
    };
    html! {
        <>
            <Title level={Level::H2}>{"Unmatched components "}<Badge>{page.total.map(|n| n.to_string()).unwrap_or_default()}</Badge></Title>
            <SimplePagination {pagination} {total} />
            {page_status(&page, loading, error.as_deref(), "No unmatched components")}
            if !loading && error.is_none() && !page.items.is_empty() {
                <Table<UnmatchedColumn, UseTableData<UnmatchedColumn, MemoizedTableModel<UnmatchedEntry>>>
                    mode={TableMode::Compact} {header} {entries}
                />
            }
        </>
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum UnmatchedColumn {
    Name,
    Identifiers,
}

#[derive(Clone, PartialEq)]
struct UnmatchedEntry(ComponentRef);

impl TableEntryRenderer<UnmatchedColumn> for UnmatchedEntry {
    fn render_cell(&self, context: CellContext<'_, UnmatchedColumn>) -> Cell {
        match context.column {
            UnmatchedColumn::Name => html!(&self.0.name).into(),
            UnmatchedColumn::Identifiers => identifiers(&self.0.identifiers).into(),
        }
    }
}
