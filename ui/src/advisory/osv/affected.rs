//! The affected packages of an OSV record, with the intervals of their ranges.

use super::{Doc, json_section, none, stated};
use ::osv::schema::{Affected, Ecosystem, Event, Range};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct AffectedTabProps {
    pub doc: Doc,
}

/// An interval of affected versions of a range.
#[derive(Debug, PartialEq, Eq)]
struct Interval<'a> {
    /// The first affected version, `None` for `0` (all versions before).
    introduced: Option<&'a str>,
    /// The end of the interval, `None` if open.
    end: Option<End<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
enum End<'a> {
    /// The version fixing it, which isn't affected.
    Fixed(&'a str),
    /// The last affected version.
    LastAffected(&'a str),
}

/// The affected intervals of the events of a range, as the ingestion reads them: in the order the
/// events are listed, ignoring `limit`.
fn intervals(events: &[Event]) -> Vec<Interval<'_>> {
    let mut result = Vec::new();
    let mut start = None;

    for event in events {
        let end = match event {
            Event::Introduced(version) => {
                if start.is_none() {
                    start = Some((version != "0").then_some(version.as_str()));
                }
                continue;
            }
            Event::Fixed(version) => End::Fixed(version),
            Event::LastAffected(version) => End::LastAffected(version),
            _ => continue,
        };
        if let Some(introduced) = start.take() {
            result.push(Interval {
                introduced,
                end: Some(end),
            });
        }
    }

    if let Some(introduced) = start {
        result.push(Interval {
            introduced,
            end: None,
        });
    }

    result
}

impl Interval<'_> {
    /// The affected versions, e.g. `>= 2.0.0, < 2.0.7`.
    fn versions(&self) -> String {
        let low = self.introduced.map(|v| format!(">= {v}"));
        let high = self.end.as_ref().map(|end| match end {
            End::Fixed(v) => format!("< {v}"),
            End::LastAffected(v) => format!("<= {v}"),
        });
        match (low, high) {
            (Some(low), Some(high)) => format!("{low}, {high}"),
            (Some(bound), None) | (None, Some(bound)) => bound,
            (None, None) => "any version".to_string(),
        }
    }
}

/// How correlation reads an entry differently from what one may expect.
fn hints(affected: &Affected) -> Vec<String> {
    let mut hints = Vec::new();
    let Some(package) = &affected.package else {
        hints.push("The entry has no package, it is ignored.".to_string());
        return hints;
    };

    if let Some(purl) = &package.purl
        && purl
            .split(['?', '#'])
            .next()
            .is_some_and(|p| p.contains('@'))
    {
        hints.push(
            "The PURL has a version, although it must only identify the package. The version is \
             ignored."
                .to_string(),
        );
    }
    if affected.ranges.as_ref().is_none_or(Vec::is_empty)
        && affected.versions.as_ref().is_none_or(Vec::is_empty)
    {
        hints.push(
            "The entry states neither ranges nor versions, so no version is affected.".into(),
        );
    }
    let ecosystem = stated(&package.ecosystem);
    if !matches!(package.ecosystem, Ecosystem::Maven(_)) && ecosystem.contains(':') {
        hints.push(format!(
            "The release of the ecosystem ({ecosystem}) doesn't scope the matches yet, the \
             statements apply to the package of any release."
        ));
    }

    hints
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AffectedColumn {
    Package,
    Ecosystem,
    Purl,
    Ranges,
    Versions,
}

/// An affected entry of the record, by its position.
#[derive(Clone, PartialEq)]
struct AffectedEntry {
    doc: Doc,
    n: usize,
}

impl AffectedEntry {
    fn affected(&self) -> Option<&Affected> {
        self.doc.affected.as_ref()?.get(self.n)
    }
}

impl TableEntryRenderer<AffectedColumn> for AffectedEntry {
    fn render_cell(&self, context: CellContext<'_, AffectedColumn>) -> Cell {
        let Some(affected) = self.affected() else {
            return none().into();
        };
        let package = affected.package.as_ref();
        let count = |len: Option<usize>| html!(len.unwrap_or_default().to_string());

        match context.column {
            AffectedColumn::Package => match package {
                Some(package) => html! {
                    <>
                        <strong>{ &package.name }</strong>
                        if !hints(affected).is_empty() {
                            { " " }
                            <Label label="Note" color={Color::Orange} compact=true />
                        }
                    </>
                },
                None => none(),
            }
            .into(),
            AffectedColumn::Ecosystem => package
                .map(|package| html!(stated(&package.ecosystem)))
                .unwrap_or_else(none)
                .into(),
            AffectedColumn::Purl => package
                .and_then(|package| package.purl.as_ref())
                .map(|purl| html!(<code>{ purl }</code>))
                .unwrap_or_else(none)
                .into(),
            AffectedColumn::Ranges => count(affected.ranges.as_ref().map(Vec::len)).into(),
            AffectedColumn::Versions => count(affected.versions.as_ref().map(Vec::len)).into(),
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let Some(affected) = self.affected() else {
            return vec![];
        };
        vec![Span::max(affected_details(affected))]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

fn affected_details(affected: &Affected) -> Html {
    let versions = affected.versions.as_deref().unwrap_or_default();
    let versions_title = format!("Listed versions ({})", versions.len());

    html! {
        <Stack gutter=true>
            { for hints(affected).into_iter().map(|hint| html_nested! {
                <StackItem>
                    <Alert title={hint} r#type={AlertType::Info} inline=true plain=true />
                </StackItem>
            }) }
            { for affected.ranges.iter().flatten().map(|range| html_nested!(<StackItem>{ range_card(range) }</StackItem>)) }
            if !versions.is_empty() {
                <StackItem>
                    <ExpandableSection toggle_text_hidden={versions_title.clone()} toggle_text_expanded={versions_title}>
                        <Flex space_items={[SpaceItems::Small]}>
                            { for versions.iter().map(|v| html_nested!(<FlexItem><code>{ v }</code></FlexItem>)) }
                        </Flex>
                    </ExpandableSection>
                </StackItem>
            }
            <StackItem>{ json_section("Ecosystem specific", affected.ecosystem_specific.as_ref()) }</StackItem>
            <StackItem>{ json_section("Database specific", affected.database_specific.as_ref()) }</StackItem>
        </Stack>
    }
}

/// A range with its affected intervals, and the versions fixing them.
fn range_card(range: &Range) -> Html {
    let intervals = intervals(&range.events);

    html! {
        <Card size={CardSize::Compact}>
            <CardTitle>
                <Flex space_items={[SpaceItems::Small]} modifiers={[FlexModifier::Align(Alignment::Center)]}>
                    <FlexItem><Label label={stated(&range.range_type)} compact=true /></FlexItem>
                    { for range.repo.as_ref().map(|repo| html_nested!(<FlexItem><small>{ repo }</small></FlexItem>)) }
                </Flex>
            </CardTitle>
            <CardBody>
                if intervals.is_empty() {
                    { "No affected versions." }
                } else {
                    <List>
                        { for intervals.iter().map(|interval| html_nested! {
                            <ListItem>
                                <Label label="affected" color={Color::Red} compact=true />
                                { " " }
                                <code>{ interval.versions() }</code>
                                if let Some(End::Fixed(fixed)) = &interval.end {
                                    { " \u{2014} fixed in " }
                                    <code>{ *fixed }</code>
                                }
                            </ListItem>
                        }) }
                    </List>
                }
            </CardBody>
        </Card>
    }
}

#[function_component(AffectedTab)]
pub fn affected_tab(props: &AffectedTabProps) -> Html {
    let entries = use_memo(props.doc.clone(), |doc| {
        (0..doc.affected.as_ref().map(Vec::len).unwrap_or_default())
            .map(|n| AffectedEntry {
                doc: doc.clone(),
                n,
            })
            .collect::<Vec<_>>()
    });

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    if props.doc.affected.as_ref().is_none_or(Vec::is_empty) {
        return html! {
            <EmptyState title="No affected packages" icon={Icon::InfoCircle} size={Size::XXXXLarge}>
                { "The record does not state any affected packages." }
            </EmptyState>
        };
    }

    let header = html_nested! {
        <TableHeader<AffectedColumn>>
            <TableColumn<AffectedColumn> label="Package" index={AffectedColumn::Package} />
            <TableColumn<AffectedColumn> label="Ecosystem" index={AffectedColumn::Ecosystem} />
            <TableColumn<AffectedColumn> label="PURL" index={AffectedColumn::Purl} />
            <TableColumn<AffectedColumn> label="Ranges" index={AffectedColumn::Ranges} />
            <TableColumn<AffectedColumn> label="Listed versions" index={AffectedColumn::Versions} />
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
    use super::*;
    use ::osv::schema::Package;

    fn introduced(v: &str) -> Event {
        Event::Introduced(v.into())
    }

    #[test]
    fn intervals_of_events() {
        let events = [
            introduced("0"),
            Event::Fixed("1.0".into()),
            introduced("2.0"),
            introduced("2.1"),
            Event::LastAffected("2.5".into()),
            Event::Fixed("2.6".into()),
            introduced("3.0"),
            Event::Limit("4.0".into()),
        ];
        assert_eq!(
            intervals(&events)
                .iter()
                .map(Interval::versions)
                .collect::<Vec<_>>(),
            ["< 1.0", ">= 2.0, <= 2.5", ">= 3.0"]
        );
        assert_eq!(
            intervals(&[introduced("0")])
                .iter()
                .map(Interval::versions)
                .collect::<Vec<_>>(),
            ["any version"]
        );
    }

    #[test]
    fn hints_of_entries() {
        let affected = |ecosystem: Ecosystem, purl: &str, versions: Option<Vec<String>>| Affected {
            package: Some(Package {
                name: "openssl".into(),
                ecosystem,
                purl: Some(purl.into()),
            }),
            severity: None,
            ranges: None,
            versions,
            ecosystem_specific: None,
            database_specific: None,
        };

        assert_eq!(
            hints(&affected(
                Ecosystem::PyPI,
                "pkg:pypi/urllib3?foo=a@b",
                Some(vec!["1.0".into()])
            )),
            Vec::<String>::new()
        );
        assert_eq!(
            hints(&affected(
                Ecosystem::Debian(Some("12".into())),
                "pkg:deb/debian/openssl@3.0.11",
                None
            )),
            [
                "The PURL has a version, although it must only identify the package. The version \
                 is ignored.",
                "The entry states neither ranges nor versions, so no version is affected.",
                "The release of the ecosystem (Debian:12) doesn't scope the matches yet, the \
                 statements apply to the package of any release.",
            ]
        );
    }
}
