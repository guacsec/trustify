use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

use chrono::Local;
use human_date_parser::{ParseResult, from_human_time};
use sea_orm::{
    ColumnTrait, ColumnType, EntityTrait, IntoIdentity, Iterable, Value as SeaValue, sea_query,
};
use sea_query::{
    Alias, ColumnRef, Expr, ExprTrait, Func, IntoColumnRef, IntoIden, SimpleExpr,
    extension::postgres::PgExpr,
};
use time::{
    Date, OffsetDateTime, format_description::well_known::Rfc3339, macros::format_description,
};
use uuid::Uuid;

use super::{Error, Operator};

/// Context of columns which can be used for filtering and sorting.
#[derive(Default, Debug, Clone)]
pub struct Columns {
    columns: Vec<(ColumnRef, ColumnType)>,
    translator: Option<Translator>,
    json_keys: BTreeMap<&'static str, ColumnRef>,
    exprs: BTreeMap<&'static str, (SimpleExpr, ColumnType)>,
}

pub trait IntoColumns {
    fn columns(self) -> Columns;
}

impl IntoColumns for Columns {
    fn columns(self) -> Columns {
        self
    }
}

impl<E: EntityTrait> IntoColumns for E {
    fn columns(self) -> Columns {
        Columns::from_entity::<E>()
    }
}

pub type Translator = fn(&str, &str, &str) -> Option<String>;

impl Columns {
    /// Construct a new columns context from an entity type.
    pub fn from_entity<E: EntityTrait>() -> Self {
        let columns = E::Column::iter()
            .map(|c| {
                let (t, u) = c.as_column_ref();
                let column_ref = ColumnRef::TableColumn(t, u);
                let column_type = c.def().get_column_type().clone();
                (column_ref, column_type)
            })
            .collect();
        Self {
            columns,
            translator: None,
            json_keys: BTreeMap::new(),
            exprs: BTreeMap::new(),
        }
    }

    /// Add an arbitrary column into the context.
    pub fn add_column<I: IntoIdentity>(mut self, name: I, ty: ColumnType) -> Self {
        self.columns
            .push((name.into_identity().into_column_ref(), ty));
        self
    }

    /// Add columns from another column context.
    ///
    /// Any columns already existing within this context will *not* be replaced
    /// by columns from the argument.
    pub fn add_columns<C: IntoColumns>(mut self, columns: C) -> Self {
        let columns = columns.columns();

        for (col_ref, col_def) in columns.columns {
            if !self
                .columns
                .iter()
                .any(|(existing_col_ref, _)| *existing_col_ref == col_ref)
            {
                self.columns.push((col_ref, col_def))
            }
        }

        self
    }

    /// Add an arbitrary expression into the context.
    pub fn add_expr(mut self, name: &'static str, expr: SimpleExpr, ty: ColumnType) -> Self {
        self.exprs.insert(name, (expr, ty));
        self
    }

    /// Add a translator to the context
    pub fn translator(mut self, f: Translator) -> Self {
        self.translator = Some(f);
        self
    }

    /// Alias a table name
    pub fn alias(mut self, from: &str, to: &str) -> Self {
        self.columns = self
            .columns
            .into_iter()
            .map(|(r, d)| match r {
                ColumnRef::TableColumn(t, c) if t.to_string().eq_ignore_ascii_case(from) => {
                    (ColumnRef::TableColumn(Alias::new(to).into_iden(), c), d)
                }
                _ => (r, d),
            })
            .collect();
        self
    }

    /// Declare which query fields are the nested keys of a JSON column
    pub fn json_keys(mut self, column: &'static str, fields: &[&'static str]) -> Self {
        if let Some((col_ref, ColumnType::Json | ColumnType::JsonBinary)) = self.find(column) {
            for field in fields {
                self.json_keys.insert(field, col_ref.clone());
            }
        } else {
            log::warn!("No JSON column found named {column}");
        }
        self
    }

    /// Return corresponding expressions for each of the string-ish columns
    pub(crate) fn strings<'a>(&'a self, v: &'a str) -> impl Iterator<Item = SimpleExpr> + 'a {
        self.columns
            .iter()
            .filter_map(move |(col_ref, col_type)| match col_type {
                ColumnType::String(_) | ColumnType::Text => {
                    Some(Expr::col(col_ref.clone()).ilike(like(v)))
                }
                ColumnType::Array(_) => {
                    Some(array_to_string(SimpleExpr::Column(col_ref.clone())).ilike(like(v)))
                }
                _ => None,
            })
            .chain(self.exprs.iter().filter_map(|(_, (ex, ty))| match ty {
                ColumnType::String(_) | ColumnType::Text => Some(ex.clone().ilike(like(v))),
                _ => None,
            }))
            .chain(self.json_keys.iter().map(|(field, column)| {
                Expr::col(column.clone())
                    .cast_json_field(*field)
                    .ilike(like(v))
            }))
    }

    /// Return an expression representing a filter: "{field}{operator}{value}"
    pub(crate) fn expression(
        &self,
        field: &str,
        operator: &Operator,
        value: &str,
    ) -> Result<SimpleExpr, Error> {
        self.for_field(field).and_then(|(lhs, ct)| {
            match (value.to_lowercase().as_str(), operator, &ct) {
                ("null", Operator::Equal, _) => Ok(lhs.is_null()),
                ("null", Operator::NotEqual, _) => Ok(lhs.is_not_null()),
                (v, op, ColumnType::Array(_)) => match op {
                    Operator::Like => Ok(array_to_string(lhs).ilike(like(v))),
                    Operator::NotLike => Ok(array_to_string(lhs).not_ilike(like(v))),
                    Operator::NotEqual => Ok(Expr::val(value).binary(op, all(lhs))),
                    _ => Ok(Expr::val(value).binary(op, any(lhs))),
                },
                (v, Operator::Like, _) => Ok(lhs.ilike(like(v))),
                (v, Operator::NotLike, _) => Ok(lhs.not_ilike(like(v))),
                (_, _, ct) => parse(value, ct).map(|rhs| lhs.binary(operator, rhs)),
            }
        })
    }

    /// Look up the column context for a given simple field name.
    pub(crate) fn for_field(&self, field: &str) -> Result<(SimpleExpr, ColumnType), Error> {
        self.exprs
            .get(field)
            .cloned()
            .or_else(|| {
                self.find(field)
                    .map(|(r, d)| (SimpleExpr::Column(r), d))
                    .or_else(|| {
                        // Compare field to json keys
                        self.json_keys
                            .get(field)
                            .cloned()
                            .map(|col| (Expr::col(col).cast_json_field(field), ColumnType::Text))
                    })
                    .or_else(|| {
                        // Check field for json object syntax, e.g. {column}:{key}:...
                        field.split_once(':').map(|(col, key)| {
                            use ColumnType::*;
                            self.find(col)
                                .filter(|(_, ct)| matches!(ct, Json | JsonBinary))
                                .map(|(col, _)| SimpleExpr::Column(col))
                                .map(|ex| {
                                    (
                                        match key.rsplit_once(':') {
                                            None => ex.cast_json_field(key),
                                            Some((ks, key)) => ks
                                                .split_terminator(':')
                                                .fold(ex, |ex, k| ex.get_json_field(k))
                                                .cast_json_field(key),
                                        },
                                        ColumnType::Text,
                                    )
                                })
                        })?
                    })
            })
            .ok_or(Error::SearchSyntax(format!(
                "'{field}' is an invalid field. Try [{}]",
                self.fields().join(", ")
            )))
    }

    pub(crate) fn translate(&self, field: &str, op: &str, value: &str) -> Option<String> {
        match self.translator {
            None => None,
            Some(f) => f(field, op, value),
        }
    }

    /// Return the valid field names associated with this collection
    pub(crate) fn fields(&self) -> Vec<String> {
        use ColumnRef::*;
        self.columns
            .iter()
            .filter_map(|(r, t)| match (r, t) {
                (Column(name) | TableColumn(_, name) | SchemaTableColumn(_, _, name), _) => {
                    Some(name.to_string().to_lowercase())
                }
                _ => None,
            })
            .chain(self.exprs.keys().map(|k| k.to_lowercase()))
            .chain(self.json_keys.keys().map(|k| k.to_lowercase()))
            .collect::<BTreeSet<_>>() // uniquify & sort
            .into_iter()
            .collect()
    }

    fn find(&self, field: &str) -> Option<(ColumnRef, ColumnType)> {
        self.columns
            .iter()
            .find(|(col, _)| {
                matches!(col, ColumnRef::Column(name)
                     | ColumnRef::TableColumn(_, name)
                     | ColumnRef::SchemaTableColumn(_, _, name)
                     if name.to_string().eq_ignore_ascii_case(field))
            })
            .cloned()
    }
}

fn like(s: &str) -> String {
    format!("%{}%", s.replace('%', r"\%").replace('_', r"\_"))
}

fn array_to_string(expr: SimpleExpr) -> SimpleExpr {
    SimpleExpr::FunctionCall(
        Func::cust("array_to_string".into_identity())
            .arg(expr)
            .arg("|"),
    )
}
fn any(expr: SimpleExpr) -> SimpleExpr {
    SimpleExpr::FunctionCall(Func::cust("ANY".into_identity()).arg(expr))
}
fn all(expr: SimpleExpr) -> SimpleExpr {
    SimpleExpr::FunctionCall(Func::cust("ALL".into_identity()).arg(expr))
}

fn parse(s: &str, ct: &ColumnType) -> Result<SimpleExpr, Error> {
    fn err(e: impl Display) -> Error {
        Error::SearchSyntax(format!(r#"conversion error: "{e}""#))
    }
    Ok(match ct {
        ColumnType::Uuid => SimpleExpr::Value(SeaValue::from(s.parse::<Uuid>().map_err(err)?)),
        ColumnType::Integer => SimpleExpr::Value(SeaValue::from(s.parse::<i32>().map_err(err)?)),
        ColumnType::Decimal(_) | ColumnType::Float | ColumnType::Double => {
            SimpleExpr::Value(SeaValue::from(s.parse::<f64>().map_err(err)?))
        }
        ColumnType::Enum { name, .. } => SimpleExpr::AsEnum(
            name.clone(),
            Box::new(SimpleExpr::Value(SeaValue::String(Some(Box::new(
                s.to_owned(),
            ))))),
        ),
        ColumnType::TimestampWithTimeZone => {
            if let Ok(odt) = OffsetDateTime::parse(s, &Rfc3339) {
                SimpleExpr::Value(SeaValue::from(odt))
            } else if let Ok(d) = Date::parse(s, &format_description!("[year]-[month]-[day]")) {
                SimpleExpr::Value(SeaValue::from(d))
            } else if let Ok(human) = from_human_time(s, Local::now().naive_local()) {
                match human {
                    ParseResult::DateTime(dt) => SimpleExpr::Value(SeaValue::from(dt)),
                    ParseResult::Date(d) => SimpleExpr::Value(SeaValue::from(d)),
                    ParseResult::Time(t) => SimpleExpr::Value(SeaValue::from(t)),
                }
            } else {
                SimpleExpr::Value(SeaValue::from(s))
            }
        }
        _ => SimpleExpr::Value(SeaValue::from(s)),
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::super::*;
    use super::*;
    use sea_orm::{ColumnType, QuerySelect, QueryTrait};
    use sea_query::{Expr, Func, SimpleExpr};
    use test_log::test;

    #[test(tokio::test)]
    async fn conditions_on_extra_columns() -> Result<(), anyhow::Error> {
        let query = advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .expr_as(
                Func::char_length(Expr::col("location".into_identity())),
                "location_len",
            );

        let sql = query
            .filtering_with(
                q("location_len>10"),
                advisory::Entity
                    .columns()
                    .add_column("location_len", ColumnType::Integer),
            )?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();

        assert_eq!(
            sql,
            r#"SELECT "advisory"."id", CHAR_LENGTH("location") AS "location_len" FROM "advisory" WHERE "location_len" > 10"#
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn filters_extra_columns() -> Result<(), anyhow::Error> {
        let test = |s: &str, expected: &str, ty: ColumnType| {
            let stmt = advisory::Entity::find()
                .select_only()
                .column(advisory::Column::Id)
                .filtering_with(q(s), advisory::Entity.columns().add_column("len", ty))
                .unwrap()
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string()
                .split("WHERE ")
                .last()
                .unwrap()
                .to_string();
            assert_eq!(stmt, expected);
        };

        use ColumnType::*;
        test("len=42", r#""len" = 42"#, Integer);
        test("len!=42", r#""len" <> 42"#, Integer);
        test("len~42", r#""len" ILIKE '%42%'"#, Text);
        test("len!~42", r#""len" NOT ILIKE '%42%'"#, Text);
        test("len>42", r#""len" > 42"#, Integer);
        test("len>=42", r#""len" >= 42"#, Integer);
        test("len<42", r#""len" < 42"#, Integer);
        test("len<=42", r#""len" <= 42"#, Integer);

        Ok(())
    }

    #[test(tokio::test)]
    async fn translation() -> Result<(), anyhow::Error> {
        let clause = |query: Query| -> Result<String, Error> {
            Ok(advisory::Entity::find()
                .select_only()
                .column(advisory::Column::Id)
                .filtering_with(
                    query,
                    advisory::Entity.columns().translator(|f, op, v| {
                        match (f, op, v) {
                            ("severity", "=", "low") => Some("score>=0&score<3"),
                            ("severity", "=", "medium") => Some("score>=3&score<6"),
                            ("severity", "=", "high") => Some("score>=6&score<10"),
                            ("severity", ">", "low") => Some("score>3"),
                            ("severity", ">", "medium") => Some("score>6"),
                            ("severity", ">", "high") => Some("score>10"),
                            ("severity", "<", "low") => Some("score<0"),
                            ("severity", "<", "medium") => Some("score<3"),
                            ("severity", "<", "high") => Some("score<6"),
                            ("painful", "=", "true") => Some("severity>high"),
                            _ => None,
                        }
                        .map(String::from)
                        .or_else(|| match (f, v) {
                            ("severity", "") => Some(format!("score:{op}")),
                            _ => None,
                        })
                    }),
                )?
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string()
                .split("WHERE ")
                .last()
                .unwrap()
                .to_string())
        };

        assert_eq!(
            clause(q("severity>medium").sort("severity:desc"))?,
            r#""advisory"."score" > 6 ORDER BY "advisory"."score" DESC"#,
        );
        assert_eq!(
            clause(q("severity=medium"))?,
            r#""advisory"."score" >= 3 AND "advisory"."score" < 6"#,
        );
        assert_eq!(
            clause(q("severity=low|high"))?,
            r#"("advisory"."score" >= 0 AND "advisory"."score" < 3) OR ("advisory"."score" >= 6 AND "advisory"."score" < 10)"#,
        );
        assert_eq!(clause(q("painful=true"))?, r#""advisory"."score" > 10"#);
        match clause(q("painful=false")) {
            Ok(_) => panic!("won't be translated so invalid"),
            Err(e) => log::error!("{e}"),
        }

        Ok(())
    }

    #[test(tokio::test)]
    async fn table_aliasing() -> Result<(), anyhow::Error> {
        let clause = advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filtering_with(
                q("location=here"),
                advisory::Entity.columns().alias("advisory", "foo"),
            )?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string()
            .split("WHERE ")
            .last()
            .unwrap()
            .to_string();

        assert_eq!(clause, r#""foo"."location" = 'here'"#);

        Ok(())
    }

    #[test(tokio::test)]
    async fn json_key_queries() -> Result<(), anyhow::Error> {
        let clause = |query: Query| -> Result<String, Error> {
            Ok(advisory::Entity::find()
                .filtering_with(
                    query,
                    advisory::Entity
                        .columns()
                        .json_keys("purl", &["name", "type", "version"]),
                )?
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string()
                .split("WHERE ")
                .last()
                .unwrap()
                .to_string())
        };

        assert_eq!(
            clause(q("name~log4j&version>1.0"))?,
            r#"(("advisory"."purl" ->> 'name') ILIKE '%log4j%') AND ("advisory"."purl" ->> 'version') > '1.0'"#
        );
        assert_eq!(
            clause(q("name=log4j").sort("name"))?,
            r#"("advisory"."purl" ->> 'name') = 'log4j' ORDER BY "advisory"."purl" ->> 'name' ASC"#
        );
        assert_eq!(
            clause(q("foo"))?,
            r#"("advisory"."location" ILIKE '%foo%') OR ("advisory"."title" ILIKE '%foo%') OR (array_to_string("advisory"."authors", '|') ILIKE '%foo%') OR (("advisory"."purl" ->> 'name') ILIKE '%foo%') OR (("advisory"."purl" ->> 'type') ILIKE '%foo%') OR (("advisory"."purl" ->> 'version') ILIKE '%foo%')"#
        );
        match clause(q("missing=gone")) {
            Ok(_) => panic!("field should be invalid"),
            Err(e) => log::error!("{e}"),
        }
        assert!(clause(q("").sort("name")).is_ok());
        assert!(clause(q("").sort("nope")).is_err());
        assert!(clause(q("q=x")).is_err());

        Ok(())
    }

    #[test(tokio::test)]
    async fn columns_with_expr() -> Result<(), anyhow::Error> {
        let test = |s: &str, expected: &str, ty: ColumnType| {
            let stmt = advisory::Entity::find()
                .select_only()
                .column(advisory::Column::Id)
                .filtering_with(
                    q(s),
                    advisory::Entity.columns().add_expr(
                        "pearl",
                        SimpleExpr::FunctionCall(
                            Func::cust("get_purl".into_identity())
                                .arg(Expr::col(advisory::Column::Purl)),
                        ),
                        ty,
                    ),
                )
                .unwrap()
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string()
                .split("WHERE ")
                .last()
                .unwrap()
                .to_string();
            assert_eq!(stmt, expected);
        };

        test(
            "pearl=pkg:rpm/redhat/foo",
            r#"get_purl("purl") = 'pkg:rpm/redhat/foo'"#,
            ColumnType::Text,
        );
        test("pearl=42", r#"get_purl("purl") = 42"#, ColumnType::Integer);
        test(
            "pkg:rpm/redhat/foo",
            r#"("advisory"."location" ILIKE '%pkg:rpm/redhat/foo%') OR ("advisory"."title" ILIKE '%pkg:rpm/redhat/foo%') OR (array_to_string("advisory"."authors", '|') ILIKE '%pkg:rpm/redhat/foo%') OR (get_purl("purl") ILIKE '%pkg:rpm/redhat/foo%')"#,
            ColumnType::Text,
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn adhoc_json_queries() -> Result<(), anyhow::Error> {
        let clause = |query: Query| -> Result<String, Error> {
            Ok(advisory::Entity::find()
                .filtering(query)?
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string()
                .split("WHERE ")
                .last()
                .unwrap()
                .to_string())
        };

        assert_eq!(
            clause(q("purl:name:foo:bar~baz"))?,
            r#"((("advisory"."purl" -> 'name') -> 'foo') ->> 'bar') ILIKE '%baz%'"#
        );
        assert_eq!(
            clause(q("purl:name~log4j&purl:version>1.0"))?,
            r#"(("advisory"."purl" ->> 'name') ILIKE '%log4j%') AND ("advisory"."purl" ->> 'version') > '1.0'"#
        );
        assert_eq!(
            clause(q("purl:name=log4j&purl:name=jdk"))?,
            r#"("advisory"."purl" ->> 'name') = 'log4j' AND ("advisory"."purl" ->> 'name') = 'jdk'"#
        );
        assert_eq!(
            clause(q("purl:name=log4j|jdk"))?,
            r#"("advisory"."purl" ->> 'name') = 'log4j' OR ("advisory"."purl" ->> 'name') = 'jdk'"#
        );
        // Note that negating multiple values is essentially shorthand...
        assert_eq!(
            clause(q("purl:name!=log4j|jdk"))?,
            r#"("advisory"."purl" ->> 'name') <> 'log4j' AND ("advisory"."purl" ->> 'name') <> 'jdk'"#
        );
        // ...for this
        assert_eq!(
            clause(q("purl:name!=log4j&purl:name!=jdk"))?,
            r#"("advisory"."purl" ->> 'name') <> 'log4j' AND ("advisory"."purl" ->> 'name') <> 'jdk'"#
        );
        assert_eq!(
            clause(q("purl:name=log4j").sort(r"purl:name"))?,
            r#"("advisory"."purl" ->> 'name') = 'log4j' ORDER BY "advisory"."purl" ->> 'name' ASC"#
        );
        assert_eq!(
            clause(q("purl:pfx/app.first-name=carlos"))?,
            r#"("advisory"."purl" ->> 'pfx/app.first-name') = 'carlos'"#
        );
        assert!(clause(q("missing:name=log4j")).is_err());
        assert!(clause(q("").sort(r"missing:name")).is_err());

        Ok(())
    }

    #[test(tokio::test)]
    async fn array_queries() -> Result<(), anyhow::Error> {
        let clause = |query: Query| -> Result<String, Error> {
            Ok(advisory::Entity::find()
                .filtering(query)?
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string()
                .split("WHERE ")
                .last()
                .unwrap()
                .to_string())
        };

        assert_eq!(
            clause(q("authors=null"))?,
            r#""advisory"."authors" IS NULL"#
        );
        assert_eq!(
            clause(q("authors~foo"))?,
            r#"array_to_string("advisory"."authors", '|') ILIKE '%foo%'"#
        );
        assert_eq!(
            clause(q("authors~foo|bar"))?,
            r#"(array_to_string("advisory"."authors", '|') ILIKE '%foo%') OR (array_to_string("advisory"."authors", '|') ILIKE '%bar%')"#
        );
        assert_eq!(
            clause(q("authors!~foo"))?,
            r#"array_to_string("advisory"."authors", '|') NOT ILIKE '%foo%'"#
        );
        assert_eq!(
            clause(q("authors=Foo"))?,
            r#"'Foo' = ANY("advisory"."authors")"#
        );
        assert_eq!(
            clause(q("authors!=FOO"))?,
            r#"'FOO' <> ALL("advisory"."authors")"#
        );
        assert_eq!(
            clause(q("foo"))?,
            r#"("advisory"."location" ILIKE '%foo%') OR ("advisory"."title" ILIKE '%foo%') OR (array_to_string("advisory"."authors", '|') ILIKE '%foo%')"#
        );

        Ok(())
    }
}
