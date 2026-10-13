//! The references of an OSV record.

use super::{Doc, stated};
use ::osv::schema::Reference;
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct ReferencesTabProps {
    pub doc: Doc,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferenceColumn {
    Type,
    Url,
}

#[derive(Clone, PartialEq)]
struct ReferenceEntry {
    r#type: String,
    url: String,
}

impl From<&Reference> for ReferenceEntry {
    fn from(reference: &Reference) -> Self {
        Self {
            r#type: stated(&reference.reference_type),
            url: reference.url.clone(),
        }
    }
}

impl TableEntryRenderer<ReferenceColumn> for ReferenceEntry {
    fn render_cell(&self, context: CellContext<'_, ReferenceColumn>) -> Cell {
        match context.column {
            ReferenceColumn::Type => html!(<Label label={self.r#type.clone()} compact=true />),
            ReferenceColumn::Url => html! {
                <a href={self.url.clone()} target="_blank" rel="noopener noreferrer">{ &self.url }</a>
            },
        }
        .into()
    }
}

#[function_component(ReferencesTab)]
pub fn references_tab(props: &ReferencesTabProps) -> Html {
    let entries = use_memo(props.doc.clone(), |doc| {
        doc.references
            .iter()
            .flatten()
            .map(ReferenceEntry::from)
            .collect::<Vec<_>>()
    });

    let empty = entries.is_empty();
    let (entries, _) = use_table_data(MemoizedTableModel::new(entries));

    if empty {
        return html! {
            <EmptyState title="No references" icon={Icon::InfoCircle} size={Size::XXXXLarge}>
                { "The record does not contain any references." }
            </EmptyState>
        };
    }

    let header = html_nested! {
        <TableHeader<ReferenceColumn>>
            <TableColumn<ReferenceColumn> label="Type" index={ReferenceColumn::Type} />
            <TableColumn<ReferenceColumn> label="URL" index={ReferenceColumn::Url} />
        </TableHeader<ReferenceColumn>>
    };

    html! {
        <Table<ReferenceColumn, UseTableData<ReferenceColumn, MemoizedTableModel<ReferenceEntry>>>
            {header}
            {entries}
        />
    }
}
