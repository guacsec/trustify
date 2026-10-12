//! The notes of a CSAF document: those of the document, and those of each vulnerability.

use super::{Doc, vulnerability_name};
use ::csaf::schema::csaf2_0::schema::{Note, NoteCategory, NotesT};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct NotesTabProps {
    pub doc: Doc,
}

fn notes(notes: &Option<NotesT>) -> &[Note] {
    notes
        .as_ref()
        .map(|notes| notes.0.as_slice())
        .unwrap_or_default()
}

#[function_component(NotesTab)]
pub fn notes_tab(props: &NotesTabProps) -> Html {
    let csaf = &props.doc.csaf;
    let document = notes(&csaf.document.notes);
    let vulnerabilities = csaf
        .vulnerabilities
        .iter()
        .enumerate()
        .filter(|(_, vuln)| !notes(&vuln.notes).is_empty())
        .collect::<Vec<_>>();
    // nothing to choose from, so no need to collapse
    let single_vulnerability = vulnerabilities.len() == 1;

    if document.is_empty() && vulnerabilities.is_empty() {
        return html! {
            <EmptyState title="No notes" icon={Icon::InfoCircle} size={Size::XXXXLarge}>
                { "The document does not contain any notes." }
            </EmptyState>
        };
    }

    html! {
        <Stack gutter=true>
            if !document.is_empty() {
                <StackItem>
                    <Title level={Level::H2}>{ "Document" }</Title>
                </StackItem>
                { for document.iter().map(|note| html!(<StackItem>{ note_card(note) }</StackItem>)) }
            }
            { for vulnerabilities.into_iter().map(|(n, vuln)| {
                let notes = notes(&vuln.notes);
                let title = format!(
                    "{} ({} {})",
                    vulnerability_name(n, vuln),
                    notes.len(),
                    if notes.len() == 1 { "note" } else { "notes" },
                );
                html! {
                    <StackItem>
                        <ExpandableSection
                            toggle_text_hidden={title.clone()}
                            toggle_text_expanded={title}
                            initially_open={single_vulnerability}
                            display_size={ExpandableSectionSize::Large}
                        >
                            <Stack gutter=true>
                                { for notes.iter().map(|note| html!(<StackItem>{ note_card(note) }</StackItem>)) }
                            </Stack>
                        </ExpandableSection>
                    </StackItem>
                }
            }) }
        </Stack>
    }
}

/// A note in full, with its category and audience.
fn note_card(note: &Note) -> Html {
    html! {
        <Card size={CardSize::Compact}>
            <CardTitle>
                <Flex space_items={[SpaceItems::Small]} modifiers={[FlexModifier::Align(Alignment::Center)]}>
                    <FlexItem>
                        <strong>{ note.title.as_deref().map(String::as_str).unwrap_or("Note") }</strong>
                    </FlexItem>
                    <FlexItem>
                        <Label label={note.category.to_string()} compact=true />
                    </FlexItem>
                    { for note.audience.as_ref().map(|audience| html_nested! {
                        <FlexItem>
                            <small>{ format!("for {}", **audience) }</small>
                        </FlexItem>
                    }) }
                </Flex>
            </CardTitle>
            <CardBody>
                <p class="trustify-pre-wrap">{ note.text.to_string() }</p>
            </CardBody>
        </Card>
    }
}

/// Render notes in a compact way: summaries in full, the others collapsed.
pub fn notes_list(notes: &[Note]) -> Html {
    html! {
        <Stack gutter=true>
            { for notes.iter().map(|note| {
                let title = format!(
                    "{} ({})",
                    note.title.as_deref().map(String::as_str).unwrap_or("Note"),
                    note.category,
                );
                html! {
                    <StackItem>
                        if note.category == NoteCategory::Summary {
                            <strong>{ title }</strong>
                            <p class="trustify-pre-wrap">{ note.text.to_string() }</p>
                        } else {
                            <ExpandableSection toggle_text_hidden={title.clone()} toggle_text_expanded={title}>
                                <p class="trustify-pre-wrap">{ note.text.to_string() }</p>
                            </ExpandableSection>
                        }
                    </StackItem>
                }
            }) }
        </Stack>
    }
}
