use crate::{
    Error,
    sbom_group::model::{Group, GroupRequest},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, Set,
    query::QueryFilter,
};
use sea_query::{Expr, SimpleExpr};
use std::borrow::Cow;
use trustify_common::model::Revisioned;
use trustify_entity::{importer, sbom_group};
use uuid::Uuid;

pub struct SbomGroupService {
    max_group_name_length: usize,
}

impl SbomGroupService {
    pub fn new(max_group_name_length: usize) -> Self {
        Self {
            max_group_name_length,
        }
    }

    pub async fn create(
        &self,
        group: GroupRequest,
        db: &impl ConnectionTrait,
    ) -> Result<Revisioned<String>, Error> {
        self.validate_group_name_or_fail(&group.name)?;

        let id = Uuid::now_v7();
        let revision = Uuid::now_v7();

        let group = sbom_group::ActiveModel {
            id: Set(id),
            name: Set(group.name),
            parent: Set(group.parent),
            revision: Set(revision),
            labels: Set(group.labels),
        };

        group.insert(db).await?;

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

        self.update_columns(
            id,
            revision,
            vec![
                (sbom_group::Column::Name, group.name.into()),
                (sbom_group::Column::Labels, group.labels.into()),
            ],
            db,
        )
        .await
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
        let result = update.exec(db).await?;

        // evaluate result
        if result.rows_affected == 0 {
            // now we need to figure out if the item wasn't there or if it was modified
            if importer::Entity::find_by_id(id).count(db).await? == 0 {
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
