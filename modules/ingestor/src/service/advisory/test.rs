use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};
use trustify_entity::advisory_vulnerability_score;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AssertScore<'a> {
    pub vulnerability_id: &'a str,
    pub r#type: advisory_vulnerability_score::ScoreType,
    pub severity: advisory_vulnerability_score::Severity,
    pub vector: &'a str,
    pub score: f32,
}

impl PartialEq for AssertScore<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.vulnerability_id == other.vulnerability_id
            && self.r#type == other.r#type
            && self.severity == other.severity
            && self.vector == other.vector
            && (self.score - other.score) < 0.1
    }
}

impl Eq for AssertScore<'_> {}

/// Verify the advisory_vulnerability_score table has the expected score
///
/// **NOTE:** The function will panic if the result doesn't match expectations.
pub async fn assert_scores(
    db: &impl ConnectionTrait,
    advisory_id: Uuid,
    scores: impl IntoIterator<Item = AssertScore<'_>>,
) -> Result<(), DbErr> {
    let new_scores = advisory_vulnerability_score::Entity::find()
        .filter(advisory_vulnerability_score::Column::AdvisoryId.eq(advisory_id))
        .all(db)
        .await?;

    let expected = Vec::from_iter(scores);
    let actual = Vec::from_iter(new_scores.iter().map(
        |advisory_vulnerability_score::Model {
             id: _,
             advisory_id: _,
             vulnerability_id,
             r#type,
             vector,
             score,
             severity,
         }| AssertScore {
            vulnerability_id,
            r#type: *r#type,
            severity: *severity,
            vector,
            score: *score,
        },
    ));

    assert_eq!(expected, actual);

    Ok(())
}
