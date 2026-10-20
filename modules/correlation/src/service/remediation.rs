//! Read remediations through source assertions which already passed correlation's matching.

use crate::{error::Error, extractor::SourceAssertionRef, model::EvidenceRemediation};
use sea_orm::{ConnectionTrait, DbBackend, FromQueryResult, Statement};
use std::collections::{BTreeSet, HashMap};
use trustify_entity::remediation::RemediationCategory;
use uuid::Uuid;

#[derive(Default)]
pub(super) struct Remediations(
    HashMap<(Uuid, String, SourceAssertionRef), Vec<EvidenceRemediation>>,
);

#[derive(FromQueryResult)]
struct Row {
    kind: String,
    id: Uuid,
    advisory_id: Uuid,
    vulnerability_id: String,
    category: String,
    details: Option<String>,
    url: Option<String>,
}

impl Remediations {
    pub async fn load(
        sources: impl IntoIterator<Item = SourceAssertionRef>,
        connection: &impl ConnectionTrait,
    ) -> Result<Self, Error> {
        let sources = sources.into_iter().collect::<BTreeSet<_>>();
        if sources.is_empty() {
            return Ok(Self::default());
        }
        let rows = Row::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"
WITH requested AS (
    SELECT * FROM jsonb_to_recordset($1) AS source(kind text, id uuid)
), links AS (
    SELECT q.kind, q.id, l.remediation_id FROM requested q
    JOIN remediation_purl_status l ON q.kind = 'purl' AND l.purl_status_id = q.id
    UNION ALL
    SELECT q.kind, q.id, l.remediation_id FROM requested q
    JOIN remediation_cpe_assertion l ON q.kind = 'cpe' AND l.assertion_id = q.id
    UNION ALL
    SELECT q.kind, q.id, l.remediation_id FROM requested q
    JOIN remediation_hash_assertion l ON q.kind = 'digest' AND l.assertion_id = q.id
    UNION ALL
    SELECT q.kind, q.id, l.remediation_id FROM requested q
    JOIN remediation_product_identifier_assertion l
        ON q.kind = 'product_identifier' AND l.assertion_id = q.id
)
SELECT DISTINCT links.kind, links.id, r.advisory_id, r.vulnerability_id,
       r.category::text AS category, r.details, r.url
FROM links JOIN remediation r ON r.id = links.remediation_id
ORDER BY category, details, url, kind, id
"#,
            [serde_json::to_value(sources)
                .map_err(Error::MatchedValue)?
                .into()],
        ))
        .all(connection)
        .await?;
        let mut result = Self::default();
        for row in rows {
            let source = match row.kind.as_str() {
                "purl" => SourceAssertionRef::Purl(row.id),
                "cpe" => SourceAssertionRef::Cpe(row.id),
                "digest" => SourceAssertionRef::Digest(row.id),
                "product_identifier" => SourceAssertionRef::ProductIdentifier(row.id),
                _ => unreachable!("only known source kinds are selected"),
            };
            use sea_orm::ActiveEnum;
            let category = RemediationCategory::try_from_value(&row.category)?;
            result
                .0
                .entry((row.advisory_id, row.vulnerability_id, source))
                .or_default()
                .push(EvidenceRemediation {
                    category: category.into(),
                    details: row.details,
                    url: row.url,
                });
        }
        Ok(result)
    }

    pub fn for_sources(
        &self,
        advisory_id: Uuid,
        vulnerability_id: &str,
        sources: &BTreeSet<SourceAssertionRef>,
    ) -> Vec<EvidenceRemediation> {
        let mut result = Vec::new();
        for source in sources {
            for remediation in self
                .0
                .get(&(advisory_id, vulnerability_id.to_owned(), *source))
                .into_iter()
                .flatten()
            {
                if !result.contains(remediation) {
                    result.push(remediation.clone());
                }
            }
        }
        // Source order must not affect API order or SBOM/query equivalence.
        result.sort_by_cached_key(|remediation| {
            (
                format!("{:?}", remediation.category),
                remediation.details.clone(),
                remediation.url.clone(),
            )
        });
        result
    }
}

#[cfg(test)]
mod tests;
