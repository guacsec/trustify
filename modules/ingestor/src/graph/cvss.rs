use crate::graph::vulnerability::BaseScore;
use cvss::{Cvss, v2_0, v3, v4_0, version::VersionV3};
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, Set};
use std::str::FromStr;
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
        // Prefer the score computed from the vector string over the CNA-provided base_score,
        // which is only used as a fallback when the vector cannot be parsed or scored.
        let base_score = cvss
            .calculated_base_score()
            .or_else(|| {
                v2_0::CvssV2::from_str(&cvss.vector_string)
                    .ok()
                    .and_then(|p| p.calculated_base_score())
            })
            .unwrap_or(cvss.base_score);

        Self {
            vulnerability_id,
            r#type: ScoreType::V2_0,
            vector: cvss.vector_string,
            score: base_score as f32,
            severity: (base_score, ScoreType::V2_0).into(),
        }
    }
}

impl From<(String, v3::CvssV3)> for ScoreInformation {
    fn from((vulnerability_id, cvss): (String, v3::CvssV3)) -> Self {
        let base_score = cvss
            .calculated_base_score()
            .or_else(|| {
                v3::CvssV3::from_str(&cvss.vector_string)
                    .ok()
                    .and_then(|p| p.calculated_base_score())
            })
            .unwrap_or(cvss.base_score);
        let score_type = match cvss.version {
            Some(VersionV3::V3_0) => ScoreType::V3_0,
            Some(VersionV3::V3_1) => ScoreType::V3_1,
            None => ScoreType::V3_0,
        };
        Self {
            vulnerability_id,
            r#type: score_type,
            vector: cvss.vector_string,
            score: base_score as f32,
            severity: (base_score, score_type).into(),
        }
    }
}

impl From<(String, v4_0::CvssV4)> for ScoreInformation {
    fn from((vulnerability_id, cvss): (String, v4_0::CvssV4)) -> Self {
        let base_score = cvss
            .calculated_full_score()
            .or_else(|| {
                v4_0::CvssV4::from_str(&cvss.vector_string)
                    .ok()
                    .and_then(|p| p.calculated_full_score())
            })
            .unwrap_or(cvss.base_score);
        Self {
            vulnerability_id,
            r#type: ScoreType::V4_0,
            vector: cvss.vector_string,
            score: base_score as f32,
            severity: (base_score, ScoreType::V4_0).into(),
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

/// Picks the "best" base score: highest CVSS version first, then highest numeric score.
pub fn best_base_score(scores: &[ScoreInformation]) -> Option<BaseScore> {
    scores
        .iter()
        .max_by(|a, b| {
            a.r#type.cmp(&b.r#type).then(
                a.score
                    .partial_cmp(&b.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        })
        .map(|s| BaseScore {
            r#type: s.r#type,
            score: (s.score as f64 * 10.0).round() / 10.0,
            severity: s.severity,
        })
}

impl ScoreCreator {
    pub fn new(advisory_id: Uuid) -> Self {
        Self {
            advisory_id,
            scores: Vec::new(),
        }
    }

    pub fn scores(&self) -> &[ScoreInformation] {
        &self.scores
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

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use trustify_entity::advisory_vulnerability_score::{ScoreType, Severity};
    use uuid::Uuid;

    #[test]
    fn score_information_into_active_model() {
        // Exercises the From<ScoreInformation> for advisory_vulnerability_score::ActiveModel path.
        let info = ScoreInformation {
            vulnerability_id: "CVE-2021-1234".to_string(),
            r#type: ScoreType::V3_1,
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            score: 9.8,
            severity: Severity::Critical,
        };
        let model: advisory_vulnerability_score::ActiveModel = info.into();
        assert_eq!(model.vulnerability_id.unwrap(), "CVE-2021-1234");
        assert_eq!(model.r#type.unwrap(), ScoreType::V3_1);
        assert_eq!(model.score.unwrap(), 9.8f32);
        assert_eq!(model.severity.unwrap(), Severity::Critical);
    }

    #[test]
    fn score_information_from_v2_high() {
        // Exercises the High severity branch (score >= 7.0) in From<(String, v2_0::CvssV2)>.
        // AV:N/AC:L/Au:N/C:C/I:C/A:C is a CVSS v2 vector with score 10.0 (High).
        let cvss =
            v2_0::CvssV2::from_str("AV:N/AC:L/Au:N/C:C/I:C/A:C").expect("valid CVSS v2 vector");
        let info: ScoreInformation = ("CVE-2021-9999".to_string(), cvss).into();
        assert_eq!(info.r#type, ScoreType::V2_0);
        assert_eq!(info.severity, Severity::High);
        assert!(info.score >= 7.0);
    }

    #[test]
    fn score_information_from_v3_no_version() {
        // Exercises the None version branch in From<(String, v3::CvssV3)>, which defaults to V3_0.
        // Deserialising without a "version" field leaves CvssV3::version as None.
        let cvss: v3::CvssV3 = serde_json::from_value(serde_json::json!({
            "vectorString": "",
            "baseScore": 0.0,
            "baseSeverity": "NONE"
        }))
        .expect("valid minimal CvssV3 JSON");
        assert!(cvss.version.is_none(), "precondition: version must be None");
        let info: ScoreInformation = ("CVE-2021-0000".to_string(), cvss).into();
        assert_eq!(info.r#type, ScoreType::V3_0);
    }

    #[test]
    fn score_information_from_v4_none_severity() {
        // Exercises the CvssSeverity::None branch in From<(String, v4_0::CvssV4)>.
        // With no metric fields populated calculated_base_score() returns None,
        // so unwrap_or(0.0) yields 0.0 which maps to Severity::None.
        let cvss: v4_0::CvssV4 = serde_json::from_value(serde_json::json!({
            "vectorString": "",
            "baseScore": 0.0,
            "baseSeverity": "NONE"
        }))
        .expect("valid minimal CvssV4 JSON");
        let info: ScoreInformation = ("CVE-2021-0000".to_string(), cvss).into();
        assert_eq!(info.severity, Severity::None);
    }

    /// Verifies that CVSS v4.0 with E:P (ProofOfConcept) produces score 9.3, not 10.0.
    #[test]
    fn score_information_from_v4_exploit_maturity_proof_of_concept() {
        // Given a CVSS v4.0 vector with all-high metrics and E:P
        let cvss = v4_0::CvssV4::from_str(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P",
        )
        .expect("valid CVSS v4 vector");

        // When converting to ScoreInformation
        let info: ScoreInformation = ("CVE-2026-18236".to_string(), cvss).into();

        // Then the score includes the E:P threat metric (CVSS-BT = 9.3)
        assert_eq!(info.r#type, ScoreType::V4_0);
        assert_eq!(info.score, 9.3_f32);
        assert_eq!(info.severity, Severity::Critical);
    }

    /// Verifies that CVSS v4.0 without an E metric still produces 10.0 (no regression).
    #[test]
    fn score_information_from_v4_no_exploit_maturity() {
        // Given a CVSS v4.0 vector with all-high metrics and no E metric
        let cvss = v4_0::CvssV4::from_str(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        )
        .expect("valid CVSS v4 vector");

        // When converting to ScoreInformation
        let info: ScoreInformation = ("CVE-2024-99999".to_string(), cvss).into();

        // Then the score defaults E to Attacked, giving 10.0 (unchanged behavior)
        assert_eq!(info.score, 10.0_f32);
    }

    /// Verifies that CVSS v4.0 with E:U (Unreported) lowers the score below 10.0.
    #[test]
    fn score_information_from_v4_exploit_maturity_unreported() {
        // Given a CVSS v4.0 vector with all-high metrics and E:U
        let cvss = v4_0::CvssV4::from_str(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U",
        )
        .expect("valid CVSS v4 vector");

        // When converting to ScoreInformation
        let info: ScoreInformation = ("CVE-2024-99998".to_string(), cvss).into();

        // Then the score is lower than 10.0 (E:U → EQ5=2, lookup (0,0,0,1,2,0) → 9.1)
        assert_eq!(info.score, 9.1_f32);
    }

    #[test]
    fn score_creator_extend() {
        // Exercises ScoreCreator::extend() by verifying items are appended to the internal list.
        let advisory_id = Uuid::nil();
        let mut creator = ScoreCreator::new(advisory_id);
        let items = vec![
            ScoreInformation {
                vulnerability_id: "CVE-2021-0001".to_string(),
                r#type: ScoreType::V3_1,
                vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                score: 9.8,
                severity: Severity::Critical,
            },
            ScoreInformation {
                vulnerability_id: "CVE-2021-0002".to_string(),
                r#type: ScoreType::V4_0,
                vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    .to_string(),
                score: 7.5,
                severity: Severity::High,
            },
        ];
        creator.extend(items);
        assert_eq!(creator.scores.len(), 2);
    }
}
