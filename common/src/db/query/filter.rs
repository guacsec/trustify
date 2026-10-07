use super::{Columns, Error, q};
use sea_orm::{Condition, sea_query::BinOper};
use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

pub struct Filter {
    clause: Condition,
}

impl From<Filter> for Condition {
    fn from(f: Filter) -> Condition {
        f.clause
    }
}

impl Filter {
    pub(crate) fn all(filters: Vec<Filter>) -> Self {
        Self {
            clause: filters
                .into_iter()
                .fold(Condition::all(), |and, f| and.add(f)),
        }
    }
}

// From a filter string of the form {field}{op}{values} where multiple
// values are delimited by '|'
impl TryFrom<(&str, Operator, &Vec<String>, &Columns)> for Filter {
    type Error = Error;
    fn try_from(tuple: (&str, Operator, &Vec<String>, &Columns)) -> Result<Self, Self::Error> {
        let (field, operator, values, columns) = tuple;
        let condition = values
            .iter()
            .map(
                |s| match columns.translate(field, &operator.to_string(), s) {
                    Some(x) => q(&x).filter_for(columns),
                    None => columns.expression(field, &operator, s).map(|expr| Filter {
                        clause: Condition::all().add(expr),
                    }),
                },
            )
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .fold(
                // We AND all the "not" values, otherwise OR
                match operator {
                    Operator::NotLike | Operator::NotEqual => Condition::all(),
                    _ => Condition::any(),
                },
                |cond, f| cond.add(f),
            );

        Ok(Filter { clause: condition })
    }
}

// From a '|'-delimited query string denoting a full-text search
impl TryFrom<(&Vec<String>, &Columns)> for Filter {
    type Error = Error;
    fn try_from(tuple: (&Vec<String>, &Columns)) -> Result<Self, Self::Error> {
        let (values, columns) = tuple;
        let condition = values
            .iter()
            .flat_map(|s| {
                // Create a LIKE filter for all the string-ish columns
                columns.strings(s).map(move |expr| Filter {
                    clause: Condition::all().add(expr),
                })
            })
            .fold(Condition::any(), |cond, f| cond.add(f));

        Ok(Filter { clause: condition })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum Operator {
    Equal,
    NotEqual,
    Like,
    NotLike,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    And,
    Or,
}

impl Display for Operator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use Operator::*;
        match self {
            Equal => write!(f, "="),
            NotEqual => write!(f, "!="),
            Like => write!(f, "~"),
            NotLike => write!(f, "!~"),
            GreaterThan => write!(f, ">"),
            GreaterThanOrEqual => write!(f, ">="),
            LessThan => write!(f, "<"),
            LessThanOrEqual => write!(f, "<="),
            And => write!(f, "&"),
            Or => write!(f, "|"),
        }
    }
}
impl FromStr for Operator {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use Operator::*;
        match s {
            "=" => Ok(Equal),
            "!=" => Ok(NotEqual),
            "~" => Ok(Like),
            "!~" => Ok(NotLike),
            ">" => Ok(GreaterThan),
            ">=" => Ok(GreaterThanOrEqual),
            "<" => Ok(LessThan),
            "<=" => Ok(LessThanOrEqual),
            "|" => Ok(Or),
            "&" => Ok(And),
            _ => unreachable!("All operators should be matched by Query parser"),
        }
    }
}
impl From<&Operator> for BinOper {
    fn from(this: &Operator) -> BinOper {
        use Operator::*;
        match this {
            Equal => BinOper::Equal,
            NotEqual => BinOper::NotEqual,
            Like => BinOper::Like,
            NotLike => BinOper::NotLike,
            GreaterThan => BinOper::GreaterThan,
            GreaterThanOrEqual => BinOper::GreaterThanOrEqual,
            LessThan => BinOper::SmallerThan,
            LessThanOrEqual => BinOper::SmallerThanOrEqual,
            And => BinOper::And,
            Or => BinOper::Or,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests::*;
    use super::super::*;
    use chrono::{Local, TimeDelta};
    use sea_orm::{QuerySelect, QueryTrait};
    use test_log::test;

    fn where_clause(query: &str) -> Result<String, anyhow::Error> {
        use crate::db::query::Filtering;
        use sea_orm::EntityTrait;
        Ok(advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filtering(q(query))?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string()
            .split("WHERE ")
            .last()
            .unwrap()
            .to_string())
    }

    #[test(tokio::test)]
    async fn conditions() -> Result<(), anyhow::Error> {
        // If a query matches the '{field}{op}{value}' regex, then the
        // first operand must resolve to a field on the Entity
        match where_clause("foo=bar") {
            Ok(_) => panic!("invalid field"),
            Err(e) => log::error!("{e}"),
        }
        match where_clause("location>=\x00") {
            Ok(_) => panic!("invalid operator"),
            Err(e) => log::error!("{e}"),
        }
        assert_eq!(
            where_clause("location=foo")?,
            r#""advisory"."location" = 'foo'"#
        );
        assert_eq!(
            where_clause(r"location=foo\=bar")?,
            r#""advisory"."location" = 'foo=bar'"#
        );
        assert_eq!(
            where_clause(r"location~foo\~bar")?,
            r#""advisory"."location" ILIKE '%foo~bar%'"#
        );
        assert_eq!(
            where_clause(r"location=foo\\bar")?,
            r#""advisory"."location" = E'foo\\bar'"#
        );
        assert_eq!(
            where_clause("location!=foo")?,
            r#""advisory"."location" <> 'foo'"#
        );
        assert_eq!(
            where_clause("location~foo")?,
            r#""advisory"."location" ILIKE '%foo%'"#
        );
        assert_eq!(
            where_clause("location~f_o%o")?,
            r#""advisory"."location" ILIKE E'%f\\_o\\%o%'"#
        );
        assert_eq!(
            where_clause("location!~foo")?,
            r#""advisory"."location" NOT ILIKE '%foo%'"#
        );
        assert_eq!(
            where_clause("location!~f_o%o")?,
            r#""advisory"."location" NOT ILIKE E'%f\\_o\\%o%'"#
        );
        assert_eq!(
            where_clause("location>foo")?,
            r#""advisory"."location" > 'foo'"#
        );
        assert_eq!(
            where_clause("location>=foo")?,
            r#""advisory"."location" >= 'foo'"#
        );
        assert_eq!(
            where_clause("location<foo")?,
            r#""advisory"."location" < 'foo'"#
        );
        assert_eq!(
            where_clause("location<=foo")?,
            r#""advisory"."location" <= 'foo'"#
        );
        assert_eq!(
            where_clause("location=a|b|c")?,
            r#""advisory"."location" = 'a' OR "advisory"."location" = 'b' OR "advisory"."location" = 'c'"#
        );
        assert_eq!(
            where_clause("location!=a|b|c")?,
            r#""advisory"."location" <> 'a' AND "advisory"."location" <> 'b' AND "advisory"."location" <> 'c'"#
        );
        assert_eq!(
            where_clause(r"location=foo|\&\|")?,
            r#""advisory"."location" = 'foo' OR "advisory"."location" = '&|'"#
        );
        assert_eq!(
            where_clause("published>2023-11-03T23:20:50.52Z")?,
            r#""advisory"."published" > '2023-11-03 23:20:50.520000 +00:00'"#
        );
        assert_eq!(
            where_clause("published>2023-11-03T23:20:51-04:00")?,
            r#""advisory"."published" > '2023-11-03 23:20:51.000000 -04:00'"#
        );
        assert_eq!(
            where_clause("published>2023-11-03")?,
            r#""advisory"."published" > '2023-11-03'"#
        );
        assert_eq!(
            where_clause("published=\x00")?,
            r#""advisory"."published" IS NULL"#
        );
        assert_eq!(
            where_clause("published=null")?,
            r#""advisory"."published" = 'null'"#
        );
        assert_eq!(
            where_clause("published!=\x00")?,
            r#""advisory"."published" IS NOT NULL"#
        );
        assert_eq!(
            where_clause("published!=null")?,
            r#""advisory"."published" <> 'null'"#
        );
        assert_eq!(
            where_clause("severity=high")?,
            r#""advisory"."severity" = (CAST('high' AS "Severity"))"#
        );
        assert_eq!(
            where_clause("severity>low")?,
            r#""advisory"."severity" > (CAST('low' AS "Severity"))"#
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn complex_ilikes() -> Result<(), anyhow::Error> {
        //
        // I broke these assertions out into their own test as they
        // resulted in very conservative parentheses when moving from
        // LIKE to ILIKE. I think the extra parens are harmless, but I
        // suspect it may be a bug that LIKE and ILIKE operators are
        // treated differently, as their precedence should be the same
        // on PostgreSQL.
        //
        // Upstream issue: https://github.com/SeaQL/sea-query/issues/776
        // See also https://github.com/SeaQL/sea-query/pull/675

        assert_eq!(
            where_clause("foo")?,
            r#"("advisory"."location" ILIKE '%foo%') OR ("advisory"."title" ILIKE '%foo%') OR (array_to_string("advisory"."authors", '|') ILIKE '%foo%')"#
        );
        assert_eq!(
            where_clause(r"type\=jar")?,
            r#"("advisory"."location" ILIKE '%type=jar%') OR ("advisory"."title" ILIKE '%type=jar%') OR (array_to_string("advisory"."authors", '|') ILIKE '%type=jar%')"#
        );
        assert_eq!(
            where_clause(r"type\~\=\!\>\<jar")?,
            r#"("advisory"."location" ILIKE '%type~=!><jar%') OR ("advisory"."title" ILIKE '%type~=!><jar%') OR (array_to_string("advisory"."authors", '|') ILIKE '%type~=!><jar%')"#
        );
        assert_eq!(
            where_clause("foo&location=bar")?,
            r#"(("advisory"."location" ILIKE '%foo%') OR ("advisory"."title" ILIKE '%foo%') OR (array_to_string("advisory"."authors", '|') ILIKE '%foo%')) AND "advisory"."location" = 'bar'"#
        );
        assert_eq!(
            where_clause(r"m\&m's&location=f\&oo&id=0e840505-e29b-41d4-a716-665544004400")?,
            r#"(("advisory"."location" ILIKE E'%m&m\'s%') OR ("advisory"."title" ILIKE E'%m&m\'s%') OR (array_to_string("advisory"."authors", '|') ILIKE E'%m&m\'s%')) AND "advisory"."location" = 'f&oo' AND "advisory"."id" = '0e840505-e29b-41d4-a716-665544004400'"#
        );
        assert_eq!(
            where_clause("a|b|c")?,
            r#"("advisory"."location" ILIKE '%a%') OR ("advisory"."title" ILIKE '%a%') OR (array_to_string("advisory"."authors", '|') ILIKE '%a%') OR ("advisory"."location" ILIKE '%b%') OR ("advisory"."title" ILIKE '%b%') OR (array_to_string("advisory"."authors", '|') ILIKE '%b%') OR ("advisory"."location" ILIKE '%c%') OR ("advisory"."title" ILIKE '%c%') OR (array_to_string("advisory"."authors", '|') ILIKE '%c%')"#
        );
        assert_eq!(
            where_clause("a|b&id=0e840505-e29b-41d4-a716-665544004400")?,
            r#"(("advisory"."location" ILIKE '%a%') OR ("advisory"."title" ILIKE '%a%') OR (array_to_string("advisory"."authors", '|') ILIKE '%a%') OR ("advisory"."location" ILIKE '%b%') OR ("advisory"."title" ILIKE '%b%') OR (array_to_string("advisory"."authors", '|') ILIKE '%b%')) AND "advisory"."id" = '0e840505-e29b-41d4-a716-665544004400'"#
        );
        assert_eq!(
            where_clause("a&b")?,
            r#"(("advisory"."location" ILIKE '%a%') OR ("advisory"."title" ILIKE '%a%') OR (array_to_string("advisory"."authors", '|') ILIKE '%a%')) AND (("advisory"."location" ILIKE '%b%') OR ("advisory"."title" ILIKE '%b%') OR (array_to_string("advisory"."authors", '|') ILIKE '%b%'))"#
        );
        assert_eq!(
            where_clause("here&location!~there|hereford")?,
            r#"(("advisory"."location" ILIKE '%here%') OR ("advisory"."title" ILIKE '%here%') OR (array_to_string("advisory"."authors", '|') ILIKE '%here%')) AND (("advisory"."location" NOT ILIKE '%there%') AND ("advisory"."location" NOT ILIKE '%hereford%'))"#
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn empty_values() -> Result<(), anyhow::Error> {
        assert_eq!(where_clause("location=")?, r#""advisory"."location" = ''"#);
        assert_eq!(
            where_clause("location=|foo")?,
            r#""advisory"."location" = '' OR "advisory"."location" = 'foo'"#
        );
        assert_eq!(
            where_clause("location=foo|")?,
            r#""advisory"."location" = 'foo' OR "advisory"."location" = ''"#
        );
        assert_eq!(
            where_clause("location=&authors=&purl:namespace=")?,
            r#""advisory"."location" = '' AND '' = ANY("advisory"."authors") AND ("advisory"."purl" ->> 'namespace') = ''"#
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn human_time() -> Result<(), anyhow::Error> {
        let now = Local::now();
        let yesterday = (now - TimeDelta::try_days(1).unwrap()).format("%Y-%m-%d");
        let last_week = (now - TimeDelta::try_days(7).unwrap()).format("%Y-%m-%d");
        let three_days_ago = (now - TimeDelta::try_days(3).unwrap()).format("%Y-%m-%d");
        assert_eq!(
            where_clause("published<yesterday")?,
            format!(r#""advisory"."published" < '{yesterday}'"#)
        );
        assert_eq!(
            where_clause("published>last week")?,
            format!(r#""advisory"."published" > '{last_week}'"#)
        );
        let wc = where_clause("published=3 days ago")?;
        let expected = &format!(r#""advisory"."published" = '{three_days_ago} "#);
        assert!(
            wc.starts_with(expected),
            "expected '{wc}' to start with '{expected}'"
        );

        // Other possibilities, assuming it's New Year's day, 2010
        //
        // "Today 18:30" = "2010-01-01 18:30:00",
        // "Yesterday 18:30" = "2009-12-31 18:30:00",
        // "Tomorrow 18:30" = "2010-01-02 18:30:00",
        // "Overmorrow 18:30" = "2010-01-03 18:30:00",
        // "2022-11-07 13:25:30" = "2022-11-07 13:25:30",
        // "15:20 Friday" = "2010-01-08 15:20:00",
        // "This Friday 17:00" = "2010-01-08 17:00:00",
        // "13:25, Next Tuesday" = "2010-01-12 13:25:00",
        // "Last Friday at 19:45" = "2009-12-25 19:45:00",
        // "Next week" = "2010-01-08 00:00:00",
        // "This week" = "2010-01-01 00:00:00",
        // "Last week" = "2009-12-25 00:00:00",
        // "Next week Monday" = "2010-01-04 00:00:00",
        // "This week Friday" = "2010-01-01 00:00:00",
        // "This week Monday" = "2009-12-28 00:00:00",
        // "Last week Tuesday" = "2009-12-22 00:00:00",
        // "In 3 days" = "2010-01-04 00:00:00",
        // "In 2 hours" = "2010-01-01 02:00:00",
        // "In 5 minutes and 30 seconds" = "2010-01-01 00:05:30",
        // "10 seconds ago" = "2009-12-31 23:59:50",
        // "10 hours and 5 minutes ago" = "2009-12-31 13:55:00",
        // "2 hours, 32 minutes and 7 seconds ago" = "2009-12-31 21:27:53",
        // "1 years, 2 months, 3 weeks, 5 days, 8 hours, 17 minutes and 45 seconds ago" =
        //     "2008-10-07 16:42:15",
        // "1 year, 1 month, 1 week, 1 day, 1 hour, 1 minute and 1 second ago" = "2008-11-23 22:58:59",
        // "A year ago" = "2009-01-01 00:00:00",
        // "A month ago" = "2009-12-01 00:00:00",
        // "A week ago" = "2009-12-25 00:00:00",
        // "A day ago" = "2009-12-31 00:00:00",
        // "An hour ago" = "2009-12-31 23:00:00",
        // "A minute ago" = "2009-12-31 23:59:00",
        // "A second ago" = "2009-12-31 23:59:59",
        // "now" = "2010-01-01 00:00:00",
        // "Overmorrow" = "2010-01-03 00:00:00"

        Ok(())
    }
}
