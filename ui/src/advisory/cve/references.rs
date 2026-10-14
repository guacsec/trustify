//! The references of a CVE record, of all its containers.

use super::{Doc, provider_label};
use patternfly_yew::prelude::*;
use serde_json::Value;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct ReferencesTabProps {
    pub doc: Doc,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferenceColumn {
    Source,
    Url,
    Tags,
}

#[derive(Clone, PartialEq)]
struct ReferenceEntry {
    source: Html,
    url: String,
    name: Option<String>,
    tags: Vec<String>,
}

impl TableEntryRenderer<ReferenceColumn> for ReferenceEntry {
    fn render_cell(&self, context: CellContext<'_, ReferenceColumn>) -> Cell {
        match context.column {
            ReferenceColumn::Source => self.source.clone(),
            ReferenceColumn::Url => html! {
                <>
                    <a href={self.url.clone()} target="_blank" rel="noopener noreferrer">{ &self.url }</a>
                    if let Some(name) = self.name.as_ref().filter(|name| **name != self.url) {
                        <br />
                        <small>{ name }</small>
                    }
                </>
            },
            ReferenceColumn::Tags => html! {
                <Flex space_items={[SpaceItems::Small]}>
                    { for self.tags.iter().map(|tag| html_nested! {
                        <FlexItem><Label label={tag.clone()} compact=true /></FlexItem>
                    }) }
                </Flex>
            },
        }
        .into()
    }
}

#[function_component(ReferencesTab)]
pub fn references_tab(props: &ReferencesTabProps) -> Html {
    let entries = use_memo(props.doc.clone(), |doc| {
        doc.containers()
            .iter()
            .flat_map(|container| {
                let source = provider_label(container);
                container
                    .references
                    .iter()
                    .map(move |reference| ReferenceEntry {
                        source: source.clone(),
                        url: reference.url.clone(),
                        name: reference.name.clone(),
                        // tags as the record states them
                        tags: reference
                            .tags
                            .iter()
                            .filter_map(|tag| match serde_json::to_value(tag) {
                                Ok(Value::String(tag)) => Some(tag),
                                _ => None,
                            })
                            .collect(),
                    })
            })
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
            <TableColumn<ReferenceColumn> label="Source" index={ReferenceColumn::Source} />
            <TableColumn<ReferenceColumn> label="URL" index={ReferenceColumn::Url} />
            <TableColumn<ReferenceColumn> label="Tags" index={ReferenceColumn::Tags} />
        </TableHeader<ReferenceColumn>>
    };

    html! {
        <Table<ReferenceColumn, UseTableData<ReferenceColumn, MemoizedTableModel<ReferenceEntry>>>
            {header}
            {entries}
        />
    }
}
