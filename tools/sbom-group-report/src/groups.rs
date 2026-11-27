//! Resolving an SBOM group's subtree from the flat group list.

use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::bail;

/// A group as returned by `GET /api/v3/group/sbom`, reduced to what the walk needs.
#[derive(Debug, Clone)]
pub struct GroupNode {
    pub id: String,
    pub name: String,
    pub parent: Option<String>,
}

/// Find the group a user named, by exact ID or exact name.
///
/// IDs are checked first, so a group whose name happens to be another group's
/// ID still resolves predictably. A name is only unique within its parent, so
/// an ambiguous name is rejected instead of picked arbitrarily.
pub fn resolve<'a>(selector: &str, groups: &'a [GroupNode]) -> anyhow::Result<&'a GroupNode> {
    if let Some(group) = groups.iter().find(|group| group.id == selector) {
        return Ok(group);
    }

    let by_name: Vec<&GroupNode> = groups
        .iter()
        .filter(|group| group.name == selector)
        .collect();

    match by_name.as_slice() {
        [group] => Ok(group),
        [] => bail!("no SBOM group with the ID or name {selector:?}"),
        matches => bail!(
            "{} SBOM groups are named {selector:?}; use one of these IDs: {}",
            matches.len(),
            matches
                .iter()
                .map(|group| group.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The IDs of `root` and every group below it, breadth-first.
///
/// The visited set breaks cycles. Exceeding `max_depth` fails instead of
/// returning an incomplete subtree.
pub fn subtree(root: &str, groups: &[GroupNode], max_depth: usize) -> anyhow::Result<Vec<String>> {
    if !groups.iter().any(|group| group.id == root) {
        bail!("no SBOM group with ID {root:?}");
    }

    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for group in groups {
        if let Some(parent) = &group.parent {
            children.entry(parent.as_str()).or_default().push(&group.id);
        }
    }

    let mut visited = HashSet::from([root]);
    let mut resolved = vec![root.to_string()];
    let mut queue = VecDeque::from([(root, 0_usize)]);

    while let Some((id, depth)) = queue.pop_front() {
        for child in children.get(id).into_iter().flatten() {
            if visited.insert(child) {
                if depth == max_depth {
                    bail!(
                        "group subtree exceeds --max-depth {max_depth}; increase the limit to include all descendants"
                    );
                }
                resolved.push((*child).to_string());
                queue.push_back((child, depth + 1));
            }
        }
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::{GroupNode, resolve, subtree};

    fn node(id: &str, parent: Option<&str>) -> GroupNode {
        named(id, id, parent)
    }

    fn named(id: &str, name: &str, parent: Option<&str>) -> GroupNode {
        GroupNode {
            id: id.to_owned(),
            name: name.to_owned(),
            parent: parent.map(str::to_owned),
        }
    }

    #[test]
    fn collects_nested_children_but_not_siblings_of_the_root() {
        let groups = [
            node("root", None),
            node("child", Some("root")),
            node("grandchild", Some("child")),
            node("elsewhere", None),
            node("elsewhere-child", Some("elsewhere")),
        ];

        let mut found = subtree("root", &groups, 16).expect("root exists");
        found.sort();
        assert_eq!(found, ["child", "grandchild", "root"]);
    }

    #[test]
    fn terminates_on_a_cycle() {
        // root -> a -> b -> root
        let groups = [
            node("root", Some("b")),
            node("a", Some("root")),
            node("b", Some("a")),
        ];

        let found = subtree("root", &groups, 2).expect("cycle closes within the depth limit");
        assert_eq!(found, ["root", "a", "b"]);
    }

    #[test]
    fn self_referencing_group_does_not_loop() {
        let groups = [node("root", Some("root"))];
        assert_eq!(subtree("root", &groups, 0).unwrap(), ["root"]);
    }

    #[test]
    fn rejects_an_incomplete_subtree_at_max_depth() {
        let groups = [
            node("root", None),
            node("a", Some("root")),
            node("b", Some("a")),
            node("c", Some("b")),
        ];
        assert!(
            subtree("root", &groups, 2)
                .unwrap_err()
                .to_string()
                .contains("--max-depth 2")
        );
        assert_eq!(
            subtree("root", &groups, 3).unwrap(),
            ["root", "a", "b", "c"]
        );
    }

    #[test]
    fn unknown_root_is_rejected() {
        assert!(subtree("nope", &[node("root", None)], 16).is_err());
    }

    #[test]
    fn resolves_by_id_or_by_name() {
        let groups = [named("g-1", "acme", None), named("g-2", "beta", None)];

        assert_eq!(resolve("g-2", &groups).unwrap().id, "g-2");
        assert_eq!(resolve("acme", &groups).unwrap().id, "g-1");
    }

    #[test]
    fn an_id_wins_over_a_name_that_looks_like_one() {
        let groups = [named("g-1", "g-2", None), named("g-2", "beta", None)];
        assert_eq!(resolve("g-2", &groups).unwrap().name, "beta");
    }

    #[test]
    fn a_repeated_name_is_rejected_with_the_candidate_ids() {
        let groups = [
            named("g-1", "prod", Some("eu")),
            named("g-2", "prod", Some("us")),
        ];

        let err = resolve("prod", &groups).unwrap_err().to_string();
        assert!(err.contains("g-1") && err.contains("g-2"), "{err}");
    }

    #[test]
    fn an_unknown_selector_is_rejected() {
        let err = resolve("nope", &[named("g-1", "acme", None)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("nope"), "{err}");
    }
}
