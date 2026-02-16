use crate::{
    common::test::{Group, UpdateAssignments, create_groups, locate_id, read_assignments},
    sbom_group::model::{GroupDetails, GroupListResult},
    test::caller,
};
use actix_http::body::to_bytes;
use actix_web::test::TestRequest;
use rstest::rstest;
use serde_json::Value;
use std::collections::HashMap;
use test_context::test_context;
use trustify_test_context::{TrustifyContext, call::CallService};

#[derive(Debug, PartialEq, Eq)]
struct Item {
    id: &'static [&'static str],
    name: &'static str,
    description: Option<&'static str>,
    labels: HashMap<&'static str, &'static str>,
    total_groups: Option<u64>,
    total_sboms: Option<u64>,
    parents: Option<&'static [&'static str]>,
}

impl Item {
    pub fn new(id: &'static [&'static str]) -> Self {
        Self {
            id,
            name: id[id.len() - 1],
            labels: HashMap::new(),
            description: None,
            total_groups: None,
            total_sboms: None,
            parents: None,
        }
    }

    pub fn description(mut self, description: &'static str) -> Self {
        self.description = Some(description);
        self
    }

    pub fn label(mut self, key: &'static str, value: &'static str) -> Self {
        self.labels.insert(key, value);
        self
    }

    pub fn total_groups(mut self, n: u64) -> Self {
        self.total_groups = Some(n);
        self
    }

    pub fn total_sboms(mut self, n: u64) -> Self {
        self.total_sboms = Some(n);
        self
    }

    pub fn parents(mut self, parents: &'static [&'static str]) -> Self {
        self.parents = Some(parents);
        self
    }
}

trait ItemExt {
    fn without_parents(self) -> impl IntoIterator<Item = Item>;
    fn without_totals(self) -> impl IntoIterator<Item = Item>;
}

impl<T> ItemExt for T
where
    T: IntoIterator<Item = Item>,
{
    fn without_parents(self) -> impl IntoIterator<Item = Item> {
        self.into_iter().map(|mut item| {
            item.parents = None;
            item
        })
    }

    fn without_totals(self) -> impl IntoIterator<Item = Item> {
        self.into_iter().map(|mut item| {
            item.total_groups = None;
            item.total_sboms = None;
            item
        })
    }
}

/// tests for searching (q style) for folders
#[test_context(TrustifyContext)]
#[rstest]
// with an empty (get all) query filter
#[case::no_filter("", [
    Item::new(&["A"]).description("Product A group").label("product", "A"),
    Item::new(&["A", "A1"]),
    Item::new(&["A", "A1", "A1a"]),
    Item::new(&["A", "A1", "A1b"]),
    Item::new(&["A", "A2"]),
    Item::new(&["A", "A2", "A2a"]),
    Item::new(&["A", "A2", "A2b"]),
    Item::new(&["B"]).label("product", "B"),
    Item::new(&["B", "B1"]),
    Item::new(&["B", "B1", "B1a"]),
    Item::new(&["B", "B1", "B1b"]),
    Item::new(&["B", "B2"]),
    Item::new(&["B", "B2", "B2a"]),
    Item::new(&["B", "B2", "B2b"]),
])]
// search for name equals "A", root level folder
#[case::name_eq("name=A", [
    Item::new(&["A"]).description("Product A group").label("product", "A"),
])]
// search for name equals "A1", level 2 folder
#[case::name_eq_l2("name=A1", [
    Item::new(&["A", "A1"]),
])]
// search for name contains "A"
#[case::name_like("name~A", [
    Item::new(&["A"]).description("Product A group").label("product", "A"),
    Item::new(&["A", "A1"]),
    Item::new(&["A", "A1", "A1a"]),
    Item::new(&["A", "A1", "A1b"]),
    Item::new(&["A", "A2"]),
    Item::new(&["A", "A2","A2a"]),
    Item::new(&["A", "A2","A2b"]),
    Item::new(&["B", "B1", "B1a"]),
    Item::new(&["B", "B2", "B2a"]),
])]
#[test_log::test(actix_web::test)]
pub async fn list_groups(
    ctx: &TrustifyContext,
    #[case] q: String,
    #[case] expected_items: impl IntoIterator<Item = Item>,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    run_list_test(app, ids, &q, Default::default(), expected_items, None).await?;

    Ok(())
}

/// A simple 3 level group setup
fn group_fixture_3_levels() -> Vec<Group> {
    vec![
        // level 1
        Group::new("A")
            .description(Some("Product A group"))
            .labels(("product", "A"))
            // level 2
            .group(
                Group::new("A1")
                    // level 3
                    .group("A1a")
                    .group("A1b"),
            )
            .group(
                Group::new("A2")
                    // level 3
                    .group("A2a")
                    .group("A2b"),
            ),
        Group::new("B")
            .labels(("product", "B"))
            // level 2
            .group(
                Group::new("B1")
                    // level 3
                    .group("B1a")
                    .group("B1b"),
            )
            .group(
                Group::new("B2")
                    // level 3
                    .group("B2a")
                    .group("B2b"),
            ),
    ]
}

/// Test query filtering by parent
#[test_context(TrustifyContext)]
#[rstest]
#[case::root_folder([], [
    Item::new(&["A"]).description("Product A group").label("product", "A"),
    Item::new(&["B"]).label("product", "B"),
])]
#[case::level_2_folder(["A", "A1"], [
    Item::new(&["A", "A1", "A1a"]),
    Item::new(&["A", "A1", "A1b"]),
])]
#[test_log::test(actix_web::test)]
pub async fn list_groups_with_parent(
    ctx: &TrustifyContext,
    #[case] parent: impl IntoIterator<Item = &'static str>,
    #[case] expected: impl IntoIterator<Item = Item>,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    let parent: Vec<_> = parent.into_iter().collect();

    let parent = match parent.is_empty() {
        true => "\x00".to_string(),
        false => locate_id(&ids, parent),
    };

    run_list_test(
        app,
        ids,
        &format!("parent={parent}"),
        Default::default(),
        expected,
        None,
    )
    .await?;

    Ok(())
}

/// Test using an invalid parent ID
#[ignore = "Caused by the q implementation"]
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
pub async fn list_groups_with_invalid_parent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    run_list_test(
        app,
        ids,
        "parent=this-is-wrong",
        Default::default(),
        [],
        None,
    )
    .await?;

    Ok(())
}

/// Test using a missing parent ID
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
pub async fn list_groups_with_missing_parent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    run_list_test(
        app,
        ids,
        "parent=cc43ae38-d32d-49b8-9863-5e7f4409a133",
        Default::default(),
        [],
        None,
    )
    .await?;

    Ok(())
}

#[derive(Default)]
struct ListTestOptions {
    totals: bool,
    parents: &'static str,
}

/// Run a "list SBOM groups" test
///
/// This takes in an ID-map from the [`create_groups`] function and expected items, which should
/// be the result of the query. Additional [`ListTestOptions`] can be used to request totals and
/// parent chain information.
///
/// *Note:* This function might already panic when assertions fail.
async fn run_list_test(
    app: impl CallService,
    ids: HashMap<Vec<String>, String>,
    q: &str,
    options: ListTestOptions,
    expected_items: impl IntoIterator<Item = Item>,
    expected_referenced: Option<Vec<&'static [&'static str]>>,
) -> anyhow::Result<()> {
    let mut uri = format!("/api/v2/group/sbom?q={}&", urlencoding::encode(q));
    if options.totals {
        uri.push_str("totals=true&");
    }
    if !options.parents.is_empty() {
        uri.push_str(&format!("parents={}&", options.parents));
    }

    let request = TestRequest::get().uri(&uri);

    let response = app.call_service(request.to_request()).await;
    let status = response.status();
    log::info!("status: {status}");

    let body = to_bytes(response.into_body()).await.expect("must decode");
    log::info!("{:?}", str::from_utf8(&body));
    let body: Value = serde_json::from_slice(&body)?;

    assert!(status.is_success());

    log::info!("{body:?}");
    assert!(body["total"].is_number());
    assert!(body["items"].is_array());

    let response: GroupListResult = serde_json::from_value(body)?;

    let expected_items = into_actual(expected_items, &ids);

    assert_eq!(response.result.total, expected_items.len() as u64);
    assert_eq!(response.result.items, expected_items);

    // Assert referenced groups
    match expected_referenced {
        None => assert!(response.referenced.is_none(), "referenced should be absent"),
        Some(expected_refs) => {
            let referenced = response.referenced.expect("referenced should be present");
            let mut actual_names: Vec<&str> = referenced.iter().map(|g| g.name.as_str()).collect();
            actual_names.sort();
            let mut expected_names: Vec<&str> = expected_refs
                .iter()
                .map(|path| path[path.len() - 1])
                .collect();
            expected_names.sort();
            assert_eq!(actual_names, expected_names);
        }
    }

    Ok(())
}

/// Convert expected items into [`GroupDetails`] by resolving the IDs from the provided IDs set.
fn into_actual(
    expected: impl IntoIterator<Item = Item>,
    ids: &HashMap<Vec<String>, String>,
) -> Vec<GroupDetails> {
    expected
        .into_iter()
        .map(|item| {
            // Look up the ID for this item's path
            let id = locate_id(ids, item.id);

            // Determine the parent ID from the path
            let parent = if item.id.len() > 1 {
                Some(locate_id(ids, &item.id[..item.id.len() - 1]))
            } else {
                None
            };

            // Convert parents array to Vec<String> of IDs by looking up each cumulative path
            let parents = item.parents.map(|parent_segments| {
                parent_segments
                    .iter()
                    .enumerate()
                    .map(|(i, _)| locate_id(ids, &parent_segments[..=i]))
                    .collect()
            });

            GroupDetails {
                group: crate::sbom_group::model::Group {
                    id,
                    parent,
                    name: item.name.to_string(),
                    description: item.description.map(ToString::to_string),
                    labels: item.labels.into(),
                },
                number_of_groups: item.total_groups,
                number_of_sboms: item.total_sboms,
                parents,
            }
        })
        .collect()
}

/// Set up the 3-level group fixture with SBOMs ingested and assigned.
///
/// Reuses [`group_fixture_3_levels`] and then ingests four SBOMs, assigning them to leaf groups.
/// One SBOM (`spdx/simple.json`) is intentionally assigned to **two** groups (`A1a` and `B1a`)
/// to verify multi-group assignment is counted correctly per group.
///
/// Assignments:
///   - `zookeeper-3.9.2-cyclonedx.json` → A1a
///   - `spdx/simple.json`               → A1a, B1a  (multi-group)
///   - `spdx/mtv-2.6.json`              → A2a
///   - `spdx/quarkus-bom-3.2.11.Final-redhat-00001.json` → B2b
async fn setup_3_levels_with_sboms(
    ctx: &TrustifyContext,
    app: &impl CallService,
) -> anyhow::Result<HashMap<Vec<String>, String>> {
    let ids = create_groups(app, group_fixture_3_levels()).await?;

    struct SbomAssignment {
        sbom_path: &'static str,
        groups: Vec<&'static [&'static str]>,
    }

    let assignments = vec![
        SbomAssignment {
            sbom_path: "zookeeper-3.9.2-cyclonedx.json",
            groups: vec![&["A", "A1", "A1a"]],
        },
        SbomAssignment {
            sbom_path: "spdx/simple.json",
            groups: vec![&["A", "A1", "A1a"], &["B", "B1", "B1a"]],
        },
        SbomAssignment {
            sbom_path: "spdx/mtv-2.6.json",
            groups: vec![&["A", "A2", "A2a"]],
        },
        SbomAssignment {
            sbom_path: "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            groups: vec![&["B", "B2", "B2b"]],
        },
    ];

    for assignment in assignments {
        let sbom_result = ctx.ingest_document(assignment.sbom_path).await?;
        let sbom_id = sbom_result.id.to_string();

        let group_ids: Vec<String> = assignment
            .groups
            .iter()
            .map(|path| locate_id(&ids, *path))
            .collect();

        let current = read_assignments(app, &sbom_id).await?;
        UpdateAssignments::new(&sbom_id)
            .etag(&current.etag)
            .group_ids(group_ids)
            .execute(app)
            .await?;
    }

    Ok(ids)
}

/// Tests for listing groups with SBOM assignments, totals, and parent chains.
///
/// Uses [`setup_3_levels_with_sboms`], which assigns SBOMs to leaf groups with one SBOM
/// (`simple.json`) assigned to two groups (`A1a` and `B1a`) to cover multi-group assignment.
#[test_context(TrustifyContext)]
#[rstest]
// all groups, requesting totals only
#[case::all_with_totals("", ListTestOptions { totals: true, ..Default::default() }, all_results().without_parents(), None)]
// all groups, requesting parent chain only
#[case::all_with_parents("", ListTestOptions { parents: "id", ..Default::default() }, all_results().without_totals(), None)]
// all groups, requesting both totals and parent chains
#[case::all_with_totals_and_parents("", ListTestOptions { totals: true, parents: "id", ..Default::default() }, all_results(), None)]
// filter to the leaf that has the multi-assigned SBOM
#[case::multi_assigned_leaf("name=A1a", ListTestOptions { totals: true, parents: "id", ..Default::default() }, [
    Item::new(&["A", "A1", "A1a"]).total_groups(0).total_sboms(2).parents(&["A", "A1"]),
], None)]
// the other leaf sharing the same SBOM
#[case::multi_assigned_other_leaf("name=B1a", ListTestOptions { totals: true, parents: "id", ..Default::default() }, [
    Item::new(&["B", "B1", "B1a"]).total_groups(0).total_sboms(1).parents(&["B", "B1"]),
], None)]
// root-level groups only, with totals
#[case::root_groups_with_totals("parent=\x00", ListTestOptions { totals: true, ..Default::default() }, [
    Item::new(&["A"]).description("Product A group").label("product", "A").total_groups(2).total_sboms(0),
    Item::new(&["B"]).label("product", "B").total_groups(2).total_sboms(0),
], None)]
// parents=true is an alias for parents=id
#[case::parents_alias_true("", ListTestOptions { parents: "true", ..Default::default() }, all_results().without_totals(), None)]
// parents=false is an alias for parents=skip (no parents returned)
#[case::parents_alias_false("", ListTestOptions { parents: "false", ..Default::default() }, all_results().without_parents().without_totals(), None)]
// parents=skip explicitly (no parents returned)
#[case::parents_skip("", ListTestOptions { parents: "skip", ..Default::default() }, all_results().without_parents().without_totals(), None)]
// parents=resolve returns parents and referenced groups (all groups returned, so referenced is empty)
#[case::parents_resolve_all("", ListTestOptions { parents: "resolve", ..Default::default() },
    all_results().without_totals(),
    Some(vec![])
)]
// parents=resolve with a filter: only leaf A1a returned, referenced should contain A and A1
#[case::parents_resolve_filtered("name=A1a", ListTestOptions { parents: "resolve", ..Default::default() }, [
    Item::new(&["A", "A1", "A1a"]).parents(&["A", "A1"]),
],
Some(vec![
    &["A"] as &[&str],
    &["A", "A1"]
]))]
// parents=resolve with a filter: two A1* returned, referenced should contain A
#[case::parents_resolve_filtered_2("name~A1", ListTestOptions { parents: "resolve", ..Default::default() }, [
    Item::new(&["A", "A1"]).parents(&["A"]),
    Item::new(&["A", "A1", "A1a"]).parents(&["A", "A1"]),
    Item::new(&["A", "A1", "A1b"]).parents(&["A", "A1"]),
],
Some(vec![
    &["A"] as &[&str],
]))]
#[test_log::test(actix_web::test)]
pub async fn list_groups_with_sboms(
    ctx: &TrustifyContext,
    #[case] q: &str,
    #[case] options: ListTestOptions,
    #[case] expected_items: impl IntoIterator<Item = Item>,
    #[case] expected_referenced: Option<Vec<&'static [&'static str]>>,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = setup_3_levels_with_sboms(ctx, &app).await?;

    run_list_test(app, ids, q, options, expected_items, expected_referenced).await?;

    Ok(())
}

fn all_results() -> impl IntoIterator<Item = Item> {
    [
        Item::new(&["A"])
            .description("Product A group")
            .label("product", "A")
            .total_groups(2)
            .total_sboms(0)
            .parents(&[]),
        Item::new(&["A", "A1"])
            .total_groups(2)
            .total_sboms(0)
            .parents(&["A"]),
        Item::new(&["A", "A1", "A1a"])
            .total_groups(0)
            .total_sboms(2)
            .parents(&["A", "A1"]),
        Item::new(&["A", "A1", "A1b"])
            .total_groups(0)
            .total_sboms(0)
            .parents(&["A", "A1"]),
        Item::new(&["A", "A2"])
            .total_groups(2)
            .total_sboms(0)
            .parents(&["A"]),
        Item::new(&["A", "A2", "A2a"])
            .total_groups(0)
            .total_sboms(1)
            .parents(&["A", "A2"]),
        Item::new(&["A", "A2", "A2b"])
            .total_groups(0)
            .total_sboms(0)
            .parents(&["A", "A2"]),
        Item::new(&["B"])
            .label("product", "B")
            .total_groups(2)
            .total_sboms(0)
            .parents(&[]),
        Item::new(&["B", "B1"])
            .total_groups(2)
            .total_sboms(0)
            .parents(&["B"]),
        Item::new(&["B", "B1", "B1a"])
            .total_groups(0)
            .total_sboms(1)
            .parents(&["B", "B1"]),
        Item::new(&["B", "B1", "B1b"])
            .total_groups(0)
            .total_sboms(0)
            .parents(&["B", "B1"]),
        Item::new(&["B", "B2"])
            .total_groups(2)
            .total_sboms(0)
            .parents(&["B"]),
        Item::new(&["B", "B2", "B2a"])
            .total_groups(0)
            .total_sboms(0)
            .parents(&["B", "B2"]),
        Item::new(&["B", "B2", "B2b"])
            .total_groups(0)
            .total_sboms(1)
            .parents(&["B", "B2"]),
    ]
}
