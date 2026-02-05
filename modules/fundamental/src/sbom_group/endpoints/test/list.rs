use crate::{
    sbom_group::{
        endpoints::test::{Create, GroupResponse},
        model::GroupDetails,
    },
    test::caller,
};
use actix_http::body::to_bytes;
use actix_web::test::TestRequest;
use rstest::rstest;
use serde_json::Value;
use std::collections::HashMap;
use test_context::test_context;
use trustify_common::model::PaginatedResults;
use trustify_entity::labels::Labels;
use trustify_test_context::{TrustifyContext, call::CallService};

#[derive(Debug, PartialEq, Eq)]
struct Item {
    id: &'static [&'static str],
    name: &'static str,
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
            total_groups: None,
            total_sboms: None,
            parents: None,
        }
    }

    pub fn label(mut self, key: &'static str, value: &'static str) -> Self {
        self.labels.insert(key, value);
        self
    }
}

/// tests for searching (q style) for folders
#[test_context(TrustifyContext)]
#[rstest]
// with an empty (get all) query filter
#[case::no_filter("", [
    Item::new(&["A"]).label("product", "A"),
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
    Item::new(&["A"]).label("product", "A"),
])]
// search for name equals "A1", level 2 folder
#[case::name_eq_l2("name=A1", [
    Item::new(&["A", "A1"]),
])]
// search for name contains "A"
#[case::name_like("name~A", [
    Item::new(&["A"]).label("product", "A"),
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

    run_list_test(app, ids, &q, expected_items).await?;

    Ok(())
}

/// A simple 3 level group setup
fn group_fixture_3_levels() -> Vec<Group> {
    vec![
        // level 1
        Group::new("A")
            .labels(("product", "A"))
            // level 2
            .add(
                Group::new("A1")
                    // level 3
                    .add("A1a")
                    .add("A1b"),
            )
            .add(
                Group::new("A2")
                    // level 3
                    .add("A2a")
                    .add("A2b"),
            ),
        Group::new("B")
            .labels(("product", "B"))
            // level 2
            .add(
                Group::new("B1")
                    // level 3
                    .add("B1a")
                    .add("B1b"),
            )
            .add(
                Group::new("B2")
                    // level 3
                    .add("B2a")
                    .add("B2b"),
            ),
    ]
}

/// Test query filtering by parent
#[test_context(TrustifyContext)]
#[rstest]
#[case::root_folder([], [
    Item::new(&["A"]).label("product", "A"),
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

    run_list_test(app, ids, &format!("parent={parent}"), expected).await?;

    Ok(())
}

/// Test using an invalid parent ID
#[ignore = "Caused by the q implementation"]
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
pub async fn list_groups_with_invalid_parent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    run_list_test(app, ids, "parent=this-is-wrong", []).await?;

    Ok(())
}

/// Test using a missing parent ID
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
pub async fn list_groups_with_missing_parent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    run_list_test(app, ids, "parent=cc43ae38-d32d-49b8-9863-5e7f4409a133", []).await?;

    Ok(())
}

/// Run a "list SBOM groups" test
///
/// This takes in an ID-map from the [`create_groups`] function and expected items, which should
/// be the result of the query.
///
/// *Note:* This function might already panic when assertions fail.
async fn run_list_test(
    app: impl CallService,
    ids: HashMap<Vec<String>, String>,
    q: &str,
    expected_items: impl IntoIterator<Item = Item>,
) -> anyhow::Result<()> {
    let uri = "/api/v2/group/sbom?".to_string();
    let uri = format!("{uri}q={}&", urlencoding::encode(q));

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

    let response: PaginatedResults<GroupDetails> = serde_json::from_value(body)?;

    let expected_items = into_actual(expected_items, &ids);

    assert_eq!(response.total, expected_items.len() as u64);
    assert_eq!(response.items, expected_items);

    Ok(())
}

/// Locate an ID from the ID set
///
/// *Note:* This function will panic when IDs cannot be found.
fn locate_id(
    ids: &HashMap<Vec<String>, String>,
    id: impl IntoIterator<Item = impl ToString>,
) -> String {
    let path: Vec<String> = id.into_iter().map(|s| s.to_string()).collect();
    ids.get(&path)
        .unwrap_or_else(|| panic!("ID not found for path: {:?}", path))
        .clone()
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

            // Convert parents array to Vec<String> by looking up IDs for each path segment
            let parents = item.parents.map(|parent_segments| {
                parent_segments
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        // Build the cumulative path up to this segment
                        locate_id(ids, &parent_segments[..=i])
                    })
                    .collect()
            });

            GroupDetails {
                group: crate::sbom_group::model::Group {
                    id,
                    parent,
                    name: item.name.to_string(),
                    labels: item.labels.into(),
                },
                number_of_groups: item.total_groups,
                number_of_sboms: item.total_sboms,
                parents,
            }
        })
        .collect()
}

#[derive()]
struct Group {
    name: String,
    labels: Labels,
    children: Vec<Group>,
}

impl Group {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            labels: Default::default(),
            children: Default::default(),
        }
    }

    pub fn add(mut self, group: impl Into<Group>) -> Self {
        self.children.push(group.into());
        self
    }

    /// Replace labels with current
    pub fn labels(mut self, labels: impl Into<Labels>) -> Self {
        self.labels = labels.into();
        self
    }
}

impl From<&str> for Group {
    fn from(value: &str) -> Self {
        Self {
            name: value.to_string(),
            children: vec![],
            labels: Labels::default(),
        }
    }
}

/// Create groups, with the provided structure, returning a map of name hierarchy to the ID.
async fn create_groups(
    app: &impl CallService,
    groups: Vec<Group>,
) -> anyhow::Result<HashMap<Vec<String>, String>> {
    let mut result = HashMap::new();

    for group in groups {
        create_group_recursive(app, group, None, vec![], &mut result).await?;
    }

    Ok(result)
}

/// Helper function to recursively create a group and its children
async fn create_group_recursive(
    app: &impl CallService,
    group: Group,
    parent_id: Option<&str>,
    mut path: Vec<String>,
    result: &mut HashMap<Vec<String>, String>,
) -> anyhow::Result<()> {
    // Add current group name to path
    path.push(group.name.clone());

    // Create the group
    let created: GroupResponse = Create::new(&group.name)
        .parent(parent_id)
        .labels(group.labels)
        .execute(app)
        .await?;

    // Store in result map (path -> ID)
    result.insert(path.clone(), created.id.clone());

    // Recursively create children
    for child in group.children {
        Box::pin(async {
            create_group_recursive(app, child, Some(&created.id), path.clone(), result).await
        })
        .await?;
    }

    Ok(())
}
