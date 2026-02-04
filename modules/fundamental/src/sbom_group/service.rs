use crate::{
    Error,
    sbom_group::model::{Group, GroupDetails, GroupRequest},
};
use itertools::izip;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QuerySelect,
    SelectGetableTuple, Selector, Set, Statement, query::QueryFilter,
};
use sea_query::{ArrayType, Expr, SimpleExpr, Value};
use std::collections::HashMap;
use std::{borrow::Cow, iter::repeat};
use trustify_common::{
    db::{
        DatabaseErrors,
        limiter::LimiterTrait,
        query::{Filtering, Query},
    },
    model::{Paginated, PaginatedResults, Revisioned},
};
use trustify_entity::{sbom_group, sbom_group_assignment};
use utoipa::IntoParams;
use uuid::Uuid;

/// Additional list options
#[derive(
    IntoParams, Copy, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct ListOptions {
    /// return the total number of children
    #[serde(default)]
    totals: bool,
    /// return the parent chain
    #[serde(default)]
    parents: bool,
}

pub struct SbomGroupService {
    max_group_name_length: usize,
}

impl SbomGroupService {
    pub fn new(max_group_name_length: usize) -> Self {
        Self {
            max_group_name_length,
        }
    }

    pub async fn list(
        &self,
        options: ListOptions,
        paginated: Paginated,
        query: Query,
        db: &impl ConnectionTrait,
    ) -> Result<PaginatedResults<GroupDetails>, Error> {
        let ListOptions { totals, parents } = options;

        let query = sbom_group::Entity::find().filtering(query)?;

        let limiter = query.limiting_pagination(db, paginated);

        let result = PaginatedResults::<sbom_group::Model>::new(limiter).await?;

        let mut items = Vec::with_capacity(result.items.len());
        let total = result.total;

        let ids: Vec<_> = result.items.iter().map(|group| group.id).collect();

        let (total_groups, total_sboms) = if totals {
            (
                self.resolve_total_groups(&ids, db).await?,
                self.resolve_total_sboms(&ids, db).await?,
            )
        } else {
            (Vec::with_capacity(0), Vec::with_capacity(0))
        };

        let parents = if parents {
            self.resolve_parents(&ids, db).await?
        } else {
            Vec::with_capacity(0)
        };

        for (group, number_of_groups, number_of_sboms, parents) in izip!(
            result.items,
            total_groups.into_iter().map(Some).chain(repeat(None)),
            total_sboms.into_iter().map(Some).chain(repeat(None)),
            parents.into_iter().map(Some).chain(repeat(None))
        ) {
            items.push(GroupDetails {
                group: group.into(),
                parents,
                number_of_groups,
                number_of_sboms,
            })
        }

        Ok(PaginatedResults { items, total })
    }

    async fn resolve_totals(
        &self,
        ids: &[Uuid],
        db: &impl ConnectionTrait,
        query: Selector<SelectGetableTuple<(Uuid, i64)>>,
    ) -> Result<Vec<u64>, Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        // execute query
        let rows = query.all(db).await?;

        // build lookup: parent_id -> count
        let mut counts: HashMap<Uuid, u64> = HashMap::with_capacity(rows.len());
        for row in rows {
            counts.insert(row.0, row.1.max(0) as u64);
        }

        // return counts, aligned with `ids` order
        Ok(ids
            .iter()
            .map(|id| counts.get(id).copied().unwrap_or(0))
            .collect())
    }

    async fn resolve_total_groups(
        &self,
        ids: &[Uuid],
        db: &impl ConnectionTrait,
    ) -> Result<Vec<u64>, Error> {
        self.resolve_totals(
            ids,
            db,
            sbom_group::Entity::find()
                .select_only()
                .column(sbom_group::Column::Parent)
                .expr(Expr::col(sbom_group::Column::Id).count())
                .filter(sbom_group::Column::Parent.is_in(ids.to_vec()))
                .group_by(sbom_group::Column::Parent)
                .into_tuple(),
        )
        .await
    }

    async fn resolve_total_sboms(
        &self,
        ids: &[Uuid],
        db: &impl ConnectionTrait,
    ) -> Result<Vec<u64>, Error> {
        self.resolve_totals(
            ids,
            db,
            sbom_group_assignment::Entity::find()
                .select_only()
                .column(sbom_group_assignment::Column::GroupId)
                .expr(Expr::col(sbom_group_assignment::Column::SbomId).count())
                .filter(sbom_group_assignment::Column::GroupId.is_in(ids.to_vec()))
                .group_by(sbom_group_assignment::Column::GroupId)
                .into_tuple::<(Uuid, i64)>(),
        )
        .await
    }

    async fn resolve_parents(
        &self,
        ids: &[Uuid],
        db: &impl ConnectionTrait,
    ) -> Result<Vec<Vec<String>>, Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let sql = r#"
WITH RECURSIVE parents AS (
    -- anchor: start at requested groups
    SELECT
        g.id AS root_id,
        g.parent,
        ARRAY[]::text[] AS names,
        ARRAY[g.id]::uuid[] AS path
    FROM sbom_group g
    WHERE g.id = ANY($1::uuid[])

    UNION ALL

    -- recursive: follow parent pointer upwards, prepend parent's name,
    -- and extend path; stop if we'd revisit a node (cycle protection)
    SELECT
        p.root_id,
        g.parent,
        g.name || p.names AS names,
        p.path || p.parent AS path
    FROM parents p
    JOIN sbom_group g ON g.id = p.parent
    WHERE p.parent IS NOT NULL
      AND NOT (p.parent = ANY(p.path))
)
SELECT root_id, names
FROM parents
WHERE parent IS NULL
   OR (parent IS NOT NULL AND parent = ANY(path))  -- ended due to cycle
"#;

        let ids_param: Vec<Value> = ids
            .iter()
            .copied()
            .map(|id| Value::Uuid(Some(Box::new(id))))
            .collect();

        let stmt = Statement::from_sql_and_values(
            db.get_database_backend(),
            sql,
            vec![Value::Array(ArrayType::Uuid, Some(Box::new(ids_param)))],
        );

        let rows = db.query_all(stmt).await?;

        let mut map = HashMap::with_capacity(ids.len());
        for row in rows {
            let root_id: Uuid = row.try_get("", "root_id")?;
            let names: Vec<String> = row.try_get("", "names")?;
            map.insert(root_id, names);
        }

        Ok(ids
            .iter()
            .map(|id| map.get(id).cloned().unwrap_or_default())
            .collect())
    }

    pub async fn create(
        &self,
        group: GroupRequest,
        db: &impl ConnectionTrait,
    ) -> Result<Revisioned<String>, Error> {
        self.validate_group_name_or_fail(&group.name)?;

        let parent = parse_parent_group(group.parent.as_deref())?;

        let id = Uuid::now_v7();
        let revision = Uuid::now_v7();

        let group = sbom_group::ActiveModel {
            id: Set(id),
            name: Set(group.name),
            parent: Set(parent),
            revision: Set(revision),
            labels: Set(group.labels.validate()?),
        };

        group.insert(db).await.map_err(|err| {
            if err.is_duplicate() {
                Error::Conflict("A group with this name already exists at this level".into())
            } else {
                err.into()
            }
        })?;

        Ok(Revisioned {
            revision: revision.to_string(),
            value: id.to_string(),
        })
    }

    pub async fn delete(
        &self,
        id: &str,
        expected_revision: Option<&str>,
        db: &impl ConnectionTrait,
    ) -> Result<bool, Error> {
        // Check if the group has any children (just need to know if at least one exists)
        let has_children = sbom_group::Entity::find()
            .filter(sbom_group::Column::Parent.into_expr().cast_as("text").eq(id))
            .limit(1)
            .one(db)
            .await?
            .is_some();

        if has_children {
            return Err(Error::Conflict(
                "Cannot delete a group that has child groups".into(),
            ));
        }

        let delete = query_by_revision(id, expected_revision, sbom_group::Entity::delete_many());
        let result = delete.exec(db).await?;

        if result.rows_affected == 0 && expected_revision.is_some() {
            // check if we had one and the revision did not match
            let has = query_by_revision(id, None, sbom_group::Entity::find())
                .count(db)
                .await?
                > 0;

            if has {
                return Err(Error::RevisionNotFound);
            }
        }

        Ok(result.rows_affected > 0)
    }

    pub async fn update(
        &self,
        id: &str,
        revision: Option<&str>,
        group: GroupRequest,
        db: &impl ConnectionTrait,
    ) -> Result<(), Error> {
        self.validate_group_name_or_fail(&group.name)?;

        let parent = parse_parent_group(group.parent.as_deref())?;

        // Validate that setting this parent won't create a cycle
        if let Some(parent_id) = &group.parent {
            self.validate_no_cycle(id, parent_id, db).await?;
        }

        self.update_columns(
            id,
            revision,
            vec![
                (sbom_group::Column::Name, group.name.into()),
                (sbom_group::Column::Parent, parent.into()),
                (sbom_group::Column::Labels, group.labels.validate()?.into()),
            ],
            db,
        )
        .await
    }

    /// Validates that setting the given parent won't create a cycle in the hierarchy.
    ///
    /// Uses a recursive CTE to walk up the parent chain and detect if the group_id
    /// appears anywhere in the ancestry of the proposed parent.
    async fn validate_no_cycle(
        &self,
        group_id: &str,
        parent_id: &str,
        db: &impl ConnectionTrait,
    ) -> Result<(), Error> {
        // Check if parent is the same as the group (direct self-reference)
        if parent_id == group_id {
            return Err(Error::Conflict(
                "Cannot set a group as its own parent".into(),
            ));
        }

        // Use recursive CTE to check if group_id appears in the parent chain of parent_id
        let sql = r#"
            WITH RECURSIVE parent_chain AS (
                SELECT id, parent
                FROM sbom_group
                WHERE id::text = $1

                UNION ALL

                SELECT g.id, g.parent
                FROM sbom_group g
                INNER JOIN parent_chain pc ON g.id = pc.parent
            )
            SELECT EXISTS(
                SELECT 1 FROM parent_chain WHERE id::text = $2
            ) AS has_cycle
        "#;

        use sea_orm::FromQueryResult;

        #[derive(FromQueryResult)]
        struct CycleCheck {
            has_cycle: bool,
        }

        let result = CycleCheck::find_by_statement(sea_orm::Statement::from_sql_and_values(
            sea_orm::DatabaseBackend::Postgres,
            sql,
            vec![parent_id.into(), group_id.into()],
        ))
        .one(db)
        .await?
        .ok_or_else(|| Error::BadRequest("Failed to check for cycles".into(), None))?;

        if result.has_cycle {
            Err(Error::Conflict(
                "Setting this parent would create a cycle in the hierarchy".into(),
            ))
        } else {
            Ok(())
        }
    }

    async fn update_columns(
        &self,
        id: &str,
        revision: Option<&str>,
        updates: Vec<(sbom_group::Column, SimpleExpr)>,
        db: &impl ConnectionTrait,
    ) -> Result<(), Error> {
        // target update
        let mut update = query_by_revision(id, revision, sbom_group::Entity::update_many())
            .col_expr(sbom_group::Column::Revision, Expr::value(Uuid::now_v7()));

        // apply changes
        for (col, expr) in updates {
            update = update.col_expr(col, expr);
        }

        // execute update
        let result = update.exec(db).await.map_err(|err| {
            if err.is_duplicate() {
                Error::Conflict("A group with this name already exists at this level".into())
            } else {
                err.into()
            }
        })?;

        // evaluate result
        if result.rows_affected == 0 {
            // now we need to figure out if the item wasn't there or if it was modified
            if query_by_revision(id, None, sbom_group::Entity::find())
                .count(db)
                .await?
                == 0
            {
                Err(Error::NotFound(id.to_string()))
            } else {
                Err(Error::RevisionNotFound)
            }
        } else {
            Ok(())
        }
    }

    pub async fn read(
        &self,
        id: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<Revisioned<Group>>, Error> {
        let Some(group) = sbom_group::Entity::find()
            .filter(sbom_group::Column::Id.into_expr().cast_as("text").eq(id))
            .one(db)
            .await?
        else {
            return Ok(None);
        };

        let value = Group {
            id: group.id.to_string(),
            name: group.name,
            parent: group.parent.map(|id| id.to_string()),
            labels: group.labels,
        };

        Ok(Some(Revisioned {
            value,
            revision: group.revision.to_string(),
        }))
    }

    /// Ensure a group name is valid
    ///
    /// This does not check uniqueness in the context of the parent.
    fn validate_group_name(&self, name: &str) -> Vec<Cow<'static, str>> {
        let mut result = vec![];

        if name.is_empty() {
            result.push("name must not be empty".into());
        }

        if self.max_group_name_length > 0 && name.len() > self.max_group_name_length {
            result.push(
                format!(
                    "name must be less than {} characters",
                    self.max_group_name_length
                )
                .into(),
            );
        }

        if name.starts_with(char::is_whitespace) {
            result.push("name must not start with whitespace".into())
        }
        if name.ends_with(char::is_whitespace) {
            result.push("name must not end with whitespace".into())
        }

        if name.chars().any(|c| {
            !(c.is_whitespace() || c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '(' | ')'))
        }) {
            result.push("name contains invalid characters, ".into())
        }

        result
    }

    fn validate_group_name_or_fail(&self, name: &str) -> Result<(), Error> {
        let violations = self.validate_group_name(name);
        if !violations.is_empty() {
            let details = violations
                .iter()
                .map(|s| format!("* {s}"))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(Error::bad_request("Invalid group name", Some(details)));
        }

        Ok(())
    }
}

/// Parse parent group string into UUID.
///
/// If the format is invalid, we claim it was not found, what is actually true.
fn parse_parent_group(parent: Option<&str>) -> Result<Option<Uuid>, Error> {
    parent
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| Error::BadRequest("Parent group not found".into(), None))
}

/// Take a query and apply filters to target the entity, with an optional revision.
fn query_by_revision<Q: QueryFilter>(id: &str, revision: Option<&str>, query: Q) -> Q {
    let mut query = query.filter(sbom_group::Column::Id.into_expr().cast_as("text").eq(id));

    if let Some(revision) = revision {
        query = query.filter(
            sbom_group::Column::Revision
                .into_expr()
                .cast_as("text")
                .eq(revision),
        );
    }

    query
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    /// Ensure that we validate grounames
    #[rstest]
    #[case::empty("", 1)]
    #[case::one_whitespace(" ", 2)]
    #[case::start_end_whitespace(" foo ", 2)]
    #[case::end_whitespace("foo ", 1)]
    #[case::start_whitespace(" foo", 1)]
    #[case::too_long("0123456789012345678901234567890123456789", 1)]
    #[case::wrong_chars("foo:bar", 1)]
    #[case("Foo Bar 1.2", 0)]
    #[test_log::test]
    fn ensure_valid_names(#[case] input: &str, #[case] violations: usize) {
        let service = SbomGroupService::new(32);
        let result = service.validate_group_name(input);
        assert_eq!(result.len(), violations);
    }

    /// Ensure that the default configuration works
    #[test_log::test]
    fn ensure_default_works() {
        let service = SbomGroupService::new(Default::default());
        let result = service.validate_group_name("foo bar");
        assert!(result.is_empty());
    }
}
