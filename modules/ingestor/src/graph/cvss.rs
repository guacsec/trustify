use cvss::version::{VersionV2, VersionV3, VersionV4};
use cvss::{Cvss, v2_0, v3, v4_0};
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, Set};
use trustify_entity::advisory_vulnerability_score::{self, ScoreType, Severity};
use uuid::Uuid;

#[derive(Debug)]
pub struct ScoreCreator {
    advisory_id: Uuid,
    scores: Vec<ScoreInformation>,
}

/// Information required to create a new
#[derive(Clone, Debug)]
pub struct ScoreInformation {
    pub vulnerability_id: String,
    pub r#type: ScoreType,
    pub vector: String,
    pub score: f64,
    pub severity: Severity,
}

impl From<ScoreInformation> for advisory_vulnerability_score::ActiveModel {
    fn from(value: ScoreInformation) -> Self {
        let ScoreInformation {
            vulnerability_id,
            r#type,
            vector,
            score,
            severity,
        } = value;

        Self {
            vulnerability_id: Set(vulnerability_id),
            r#type: Set(r#type),
            vector: Set(vector),
            score: Set(score),
            severity: Set(severity),
            ..Default::default()
        }
    }
}

impl From<(String, v2_0::CvssV2)> for ScoreInformation {
    fn from((vulnerability_id, score): (String, v2_0::CvssV2)) -> Self {
        let v2_0::CvssV2 {
            version,
            vector_string,
            severity,
            base_score,
            ..
        } = score;

        Self {
            vulnerability_id,
            r#type: match version {
                VersionV2::V2_0 => ScoreType::V2_0,
            },
            vector: vector_string,
            score: base_score,
            severity: match severity {
                None => Severity::None,
                Some(v2_0::Severity::Low) => Severity::Low,
                Some(v2_0::Severity::Medium) => Severity::Medium,
                Some(v2_0::Severity::High) => Severity::High,
            },
        }
    }
}

impl From<(String, v3::CvssV3)> for ScoreInformation {
    fn from((vulnerability_id, score): (String, v3::CvssV3)) -> Self {
        let v3::CvssV3 {
            version,
            vector_string,
            base_severity,
            base_score,
            ..
        } = score;

        Self {
            vulnerability_id,
            r#type: match version {
                VersionV3::V3_0 => ScoreType::V3_0,
                VersionV3::V3_1 => ScoreType::V3_1,
            },
            vector: vector_string,
            score: base_score,
            severity: base_severity.into(),
        }
    }
}

impl From<(String, v4_0::CvssV4)> for ScoreInformation {
    fn from((vulnerability_id, score): (String, v4_0::CvssV4)) -> Self {
        let v4_0::CvssV4 {
            version,
            vector_string,
            base_severity,
            base_score,
            ..
        } = score;

        Self {
            vulnerability_id,
            r#type: match version {
                VersionV4::V4_0 => ScoreType::V4_0,
            },
            vector: vector_string,
            score: base_score,
            severity: base_severity.into(),
        }
    }
}

impl From<(String, Cvss)> for ScoreInformation {
    fn from((vulnerability_id, score): (String, Cvss)) -> Self {
        match score {
            Cvss::V2(score) => (vulnerability_id, score).into(),
            Cvss::V3_0(score) => (vulnerability_id, score).into(),
            Cvss::V3_1(score) => (vulnerability_id, score).into(),
            Cvss::V4(score) => (vulnerability_id, score).into(),
        }
    }
}

impl ScoreCreator {
    pub fn new(advisory_id: Uuid) -> Self {
        Self {
            advisory_id,
            scores: Vec::new(),
        }
    }

    pub fn add(&mut self, model: impl Into<ScoreInformation>) {
        self.scores.push(model.into());
    }

    pub fn extend(&mut self, items: impl IntoIterator<Item = impl Into<ScoreInformation>>) {
        self.scores.extend(items.into_iter().map(Into::into));
    }

    pub async fn create<C>(self, db: &C) -> Result<(), DbErr>
    where
        C: ConnectionTrait,
    {
        let Self {
            advisory_id,
            scores,
        } = self;

        // delete existing entries

        advisory_vulnerability_score::Entity::delete_many()
            .filter(advisory_vulnerability_score::Column::AdvisoryId.eq(advisory_id))
            .exec(db)
            .await?;

        // transform and set advisory

        let scores = scores.into_iter().map(|score| {
            let ScoreInformation {
                vulnerability_id,
                r#type,
                vector,
                score,
                severity,
            } = score;

            advisory_vulnerability_score::ActiveModel {
                id: Set(Uuid::now_v7()),
                advisory_id: Set(advisory_id),
                vulnerability_id: Set(vulnerability_id),
                r#type: Set(r#type),
                vector: Set(vector),
                score: Set(score),
                severity: Set(severity),
            }
        });

        // insert chunked

        advisory_vulnerability_score::Entity::insert_many(scores)
            .exec(db)
            .await?;

        // done

        Ok(())
    }
}
