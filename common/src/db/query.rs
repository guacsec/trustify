mod columns;
mod filter;
mod filtering;
mod sort;
mod value;

pub use columns::{Columns, IntoColumns};
pub use filtering::Filtering;
use std::fmt;
use value::Context;
pub use value::{Valuable, Value, ValueContext};

use filter::{Filter, Operator};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sort::Sort;
use std::str::FromStr;
use std::sync::OnceLock;
use utoipa::{IntoParams, ToSchema};

/// Convenience function for creating a search Query
///
/// ```
/// use trustify_common::db::query::q;
///
/// let query = q("foo&bar>100").sort("bar:desc,baz");
///
/// ```
pub fn q(s: &str) -> Query {
    Query::q(s)
}

impl Query {
    /// Construct a Query from a properly-formatted string denoting
    /// full text searches and/or filters
    pub fn q(s: &str) -> Self {
        Self {
            q: s.into(),
            sort: String::default(),
        }
    }

    /// Sort the results of a Query per a comma-delimited string of
    /// field names.
    pub fn sort(self, s: &str) -> Self {
        Self {
            q: self.q,
            sort: s.into(),
        }
    }

    /// Apply the query to a mapping of field names to values,
    /// returning true if the context is successfully matched by the
    /// query, by either a filter or a full-text search of all the
    /// values.
    pub fn apply(&self, context: impl Context) -> bool {
        use Operator::*;
        self.parse().iter().all(|c| match c {
            Constraint {
                field: Some(f),
                op: Some(o),
                value: vs,
            } => context.get(f).is_some_and(|field| match o {
                Equal => vs.iter().any(|v| field.eq(v)),
                NotEqual => vs.iter().all(|v| field.ne(v)),
                Like => vs.iter().any(|v| field.like(v)),
                NotLike => vs.iter().all(|v| !field.like(v)),
                GreaterThan => vs.iter().all(|v| field.gt(v)),
                GreaterThanOrEqual => vs.iter().all(|v| field.ge(v)),
                LessThan => vs.iter().all(|v| field.lt(v)),
                LessThanOrEqual => vs.iter().all(|v| field.le(v)),
                _ => false,
            }),
            Constraint {
                field: None,
                value: vs,
                ..
            } => context
                .values()
                .any(|field| vs.iter().any(|v| field.like(v))),
            _ => false,
        })
    }

    fn parse(&self) -> Vec<Constraint> {
        // regex for filters: {field}{op}{value}
        const RE: &str = r"^(?<field>[^\\]+?)(?<op>=|!=|~|!~|>=|>|<=|<)(?<value>.*)$";
        static LOCK: OnceLock<Regex> = OnceLock::new();
        #[allow(clippy::unwrap_used)]
        let regex = LOCK.get_or_init(|| Regex::new(RE).unwrap());

        fn encode(s: &str) -> String {
            s.replace(r"\&", "\x07").replace(r"\|", "\x08")
        }
        fn decode(s: &str) -> String {
            s.replace('\x07', "&")
                .replace('\x08', "|")
                .replace(r"\\", "\x08")
                .replace('\\', "")
                .replace('\x08', r"\")
        }
        encode(&self.q)
            .split_terminator('&')
            .map(|s| {
                if let Some(capture) = regex.captures(s) {
                    // We have a filter: {field}{op}{value}
                    let field = Some(capture["field"].into());
                    #[allow(clippy::unwrap_used)] // regex ensures we won't panic
                    let op = Some(Operator::from_str(&capture["op"]).unwrap());
                    let value = capture["value"].split('|').map(decode).collect();
                    Constraint { field, op, value }
                } else {
                    // We have a full-text search
                    Constraint {
                        field: None,
                        op: None,
                        value: s.split('|').map(decode).collect(),
                    }
                }
            })
            .collect()
    }

    fn filter_for(&self, columns: &Columns) -> Result<Filter, Error> {
        let constraints = self.parse();
        Ok(match constraints.len() {
            1 => constraints[0].filter_for(columns)?,
            _ => Filter::all(
                constraints
                    .iter()
                    .map(|constraint| constraint.filter_for(columns))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        })
    }

    pub fn get_constraint_for_field(&self, field: &str) -> Option<Constraint> {
        self.parse()
            .into_iter()
            .find(|constraint| constraint.has_field(field))
    }
}

/// A Query is comprised of full text searches and/or filters with optional sorting rules.
///
#[derive(Clone, Default, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct Query {
    /// EBNF grammar for the _q_ parameter:
    /// ```text
    ///     q = ( values | filter ) { '&' q }
    ///     values = value { '|', values }
    ///     filter = field, operator, values
    ///     operator = "=" | "!=" | "~" | "!~" | ">=" | ">" | "<=" | "<"
    ///     value = (* any text but escape special characters with '\' *)
    ///     field = (* must match an entity attribute name *)
    /// ```
    /// Any values in a _q_ will result in a case-insensitive "full
    /// text search", effectively producing an OR clause of LIKE
    /// clauses for every string-ish field in the resource being
    /// queried.
    ///
    /// Examples:
    /// - `foo` - any field containing 'foo'
    /// - `foo|bar` - any field containing either 'foo' OR 'bar'
    /// - `foo&bar` - some field contains 'foo' AND some field contains 'bar'
    ///
    /// A _filter_ may also be used to constrain the results. The
    /// filter's field name must correspond to one of the resource's
    /// attributes. If it doesn't, an error will be returned
    /// containing a list of the valid fields for that resource.
    ///
    /// An ASCII value of `NUL`, percent-encoded as `%00`, may be used
    /// to find resources on which a particular field isn't set. For
    /// example, `name=%00` and `name!=%00` yield the WHERE clauses,
    /// 'NAME IS NULL' and 'NAME IS NOT NULL', respectively.
    ///
    /// Examples:
    /// - `name=foo` - entity's _name_ matches 'foo' exactly
    /// - `name~foo` - entity's _name_ contains 'foo', case-insensitive
    /// - `name~foo|bar` - entity's _name_ contains either 'foo' OR 'bar', case-insensitive
    /// - `name=` - entity's _name_ is the empty string, ''
    /// - `name=%00` - entity's _name_ isn't set
    /// - `published>3 days ago` - date values can be "human time"
    ///
    /// Multiple full text searches and/or filters should be
    /// '&'-delimited -- they are logically AND'd together.
    ///
    /// - `red hat|fedora&labels:type=cve|osv&published>last wednesday 17:00`
    ///
    /// Fields corresponding to JSON objects in the database may use a
    /// ':' to delimit the column name and the object key,
    /// e.g. `purl:qualifiers:type=pom`
    ///
    /// Any operator or special character, e.g. '|', '&', within a
    /// value should be escaped by prefixing it with a backslash.
    ///
    #[serde(default)]
    pub q: String,

    /// EBNF grammar for the _sort_ parameter:
    /// ```text
    ///     sort = field [ ':', order ] { ',' sort }
    ///     order = ( "asc" | "desc" )
    ///     field = (* must match the name of entity's attributes *)
    /// ```
    /// The optional _order_ should be one of "asc" or "desc". If
    /// omitted, the order defaults to "asc".
    ///
    /// Each _field_ name must correspond to one of the columns of the
    /// table holding the entities being queried. Those corresponding
    /// to JSON objects in the database may use a ':' to delimit the
    /// column name and the object key,
    /// e.g. `purl:qualifiers:type:desc`
    ///
    #[serde(default)]
    pub sort: String,
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("Query syntax error: {0}")]
    SearchSyntax(String),
}

#[derive(Debug)]
pub struct Constraint {
    field: Option<String>, // None for full-text searches
    op: Option<Operator>,  // None for full-text searches
    value: Vec<String>,    // to account for '|'-delimited values
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.value.join("|");
        match (&self.field, &self.op) {
            (Some(field), Some(op)) => write!(f, "{field}{op}{value}"),
            (None, None) => write!(f, "{value}"),
            _ => write!(f, "<invalid constraint>"),
        }
    }
}

impl Constraint {
    fn filter_for(&self, columns: &Columns) -> Result<Filter, Error> {
        match (&self.field, self.op) {
            // We have a filter of the form, {field}{op}{value}
            (Some(field), Some(operator)) => {
                Filter::try_from((field.as_str(), operator, &self.value, columns))
            }
            // We have a full-text search query
            (None, _) => Filter::try_from((&self.value, columns)),
            _ => Err(Error::SearchSyntax(format!("Invalid query: '{self:?}'"))),
        }
    }

    fn has_field(&self, field: &str) -> bool {
        self.field.as_ref().is_some_and(|f| f == field)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sea_orm::{EntityTrait, QueryOrder, QuerySelect, QueryTrait};

    #[test_log::test(tokio::test)]
    async fn happy_path() -> Result<(), anyhow::Error> {
        let stmt = advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filtering(q("foo&published>2024-04-20").sort("location,title:desc"))?
            .order_by_desc(advisory::Column::Id)
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        assert_eq!(
            stmt,
            r#"SELECT "advisory"."id" FROM "advisory" WHERE (("advisory"."location" ILIKE '%foo%') OR ("advisory"."title" ILIKE '%foo%') OR (array_to_string("advisory"."authors", '|') ILIKE '%foo%')) AND "advisory"."published" > '2024-04-20' ORDER BY "advisory"."location" ASC, "advisory"."title" DESC, "advisory"."id" DESC"#
        );
        Ok(())
    }

    #[test_log::test(rstest::rstest)]
    #[case("f=x", vec!["f=x"])]
    #[case("f=x|y", vec!["f=x|y"])]
    #[case("x", vec!["x"])]
    #[case("x|y", vec!["x|y"])]
    #[case("x|y&f>x", vec!["x|y", "f>x"])]
    #[case("x!=\0&foo", vec!["x!=\0", "foo"])]
    fn parsing(#[case] input: &str, #[case] expected: Vec<&str>) {
        let constraints: Vec<_> = q(input).parse().iter().map(ToString::to_string).collect();
        assert_eq!(expected, constraints)
    }

    /////////////////////////////////////////////////////////////////////////
    // Dummy Entity used for multiple tests in the crate
    /////////////////////////////////////////////////////////////////////////

    pub(crate) mod advisory {
        use std::collections::HashMap;

        use sea_orm::{FromJsonQueryResult, entity::prelude::*};
        use serde::{Deserialize, Serialize};
        use time::OffsetDateTime;

        #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
        #[sea_orm(table_name = "advisory")]
        pub struct Model {
            #[sea_orm(primary_key)]
            pub id: Uuid,
            pub location: String,
            pub title: String,
            pub published: Option<OffsetDateTime>,
            pub severity: Severity,
            pub score: f64,
            pub authors: Option<Vec<String>>,
            #[sea_orm(column_type = "JsonBinary")]
            pub purl: CanonicalPurl,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}

        #[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
        #[sea_orm(rs_type = "String", db_type = "Enum")]
        pub enum Severity {
            #[sea_orm(string_value = "low")]
            Low,
            #[sea_orm(string_value = "medium")]
            Medium,
            #[sea_orm(string_value = "high")]
            High,
        }

        #[derive(Clone, Debug, PartialEq, Serialize, Deserialize, FromJsonQueryResult)]
        pub struct CanonicalPurl(pub HashMap<String, String>);
    }
}
