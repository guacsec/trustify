use cvss::version::VersionV3;
use cvss::{Cvss, v2_0, v3, v4_0};
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, Set};
use trustify_cvss::cvss3::severity::Severity as CvssSeverity;
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
    pub score: f32,
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
    fn from((vulnerability_id, cvss): (String, v2_0::CvssV2)) -> Self {
        // Use calculated_base_score() to compute the actual score from metrics
        let base_score = cvss.calculated_base_score().unwrap_or(0.0);
        // Derive severity from calculated score using CVSS v2 scale (no "None" or "Critical")
        let severity = match base_score {
            x if x < 4.0 => Severity::Low,
            x if x < 7.0 => Severity::Medium,
            _ => Severity::High,
        };

        Self {
            vulnerability_id,
            r#type: ScoreType::V2_0,
            vector: cvss.vector_string,
            score: base_score as f32,
            severity,
        }
    }
}

impl From<(String, v3::CvssV3)> for ScoreInformation {
    fn from((vulnerability_id, cvss): (String, v3::CvssV3)) -> Self {
        // Use calculated_base_score() to compute the actual score from metrics
        let base_score = cvss.calculated_base_score().unwrap_or(0.0);
        // Derive severity from calculated score using CVSS v3 scale
        let severity = match CvssSeverity::from_f64(base_score) {
            CvssSeverity::None => Severity::None,
            CvssSeverity::Low => Severity::Low,
            CvssSeverity::Medium => Severity::Medium,
            CvssSeverity::High => Severity::High,
            CvssSeverity::Critical => Severity::Critical,
        };

        Self {
            vulnerability_id,
            r#type: match cvss.version {
                Some(VersionV3::V3_0) => ScoreType::V3_0,
                Some(VersionV3::V3_1) => ScoreType::V3_1,
                None => ScoreType::V3_0, // Default to V3_0 if version is not specified
            },
            vector: cvss.vector_string,
            score: base_score as f32,
            severity,
        }
    }
}

impl From<(String, v4_0::CvssV4)> for ScoreInformation {
    fn from((vulnerability_id, cvss): (String, v4_0::CvssV4)) -> Self {
        // Use calculated_base_score() to compute the actual score from metrics
        let base_score = cvss.calculated_base_score().unwrap_or(0.0);
        // Derive severity from calculated score using CVSS v4 scale (same as v3)
        let severity = match CvssSeverity::from_f64(base_score) {
            CvssSeverity::None => Severity::None,
            CvssSeverity::Low => Severity::Low,
            CvssSeverity::Medium => Severity::Medium,
            CvssSeverity::High => Severity::High,
            CvssSeverity::Critical => Severity::Critical,
        };

        Self {
            vulnerability_id,
            r#type: ScoreType::V4_0,
            vector: cvss.vector_string,
            score: base_score as f32,
            severity,
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

        // if we have none, return now

        if scores.is_empty() {
            return Ok(());
        }

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
