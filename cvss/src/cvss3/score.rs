use crate::cvss3::severity::Severity;

use super::Cvss3Base;

/// CVSS V3.1 scores.
///
/// Formula described in CVSS v3.1 Specification: Section 5:
/// <https://www.first.org/cvss/specification-document#t20>
#[derive(Copy, Clone, Debug, Default, PartialEq, PartialOrd)]
pub struct Score(f64);

impl Score {
    /// Create a new score object
    pub fn new(score: f64) -> Score {
        Score(score)
    }

    /// Get the score as a floating point value
    pub fn value(self) -> f64 {
        self.0
    }

    /// Round the score up to the algorithm described in
    /// CVSS v3.1: Appendix A - Floating Point Rounding.
    ///
    /// <https://www.first.org/cvss/specification-document#t25>
    pub fn roundup(self) -> Score {
        let score_int = (self.0 * 100_000.0) as u64;

        if score_int.is_multiple_of(10000) {
            Score((score_int as f64) / 100_000.0)
        } else {
            let score_floor = ((score_int as f64) / 10_000.0).floor();
            Score((score_floor + 1.0) / 10.0)
        }
    }

    /// Convert the numeric score into a `Severity`
    pub fn severity(self) -> Severity {
        Severity::from(self.0)
    }
}

impl From<f64> for Score {
    fn from(score: f64) -> Score {
        Score(score)
    }
}

impl From<Score> for f64 {
    fn from(score: Score) -> f64 {
        score.value()
    }
}

impl From<Score> for Severity {
    fn from(score: Score) -> Severity {
        score.severity()
    }
}

impl FromIterator<Cvss3Base> for Score {
    fn from_iter<I: IntoIterator<Item = Cvss3Base>>(iter: I) -> Self {
        let mut count: usize = 0;
        let mut sum = 0.0;
        for v in iter {
            sum += v.score().value();
            count += 1;
        }
        if count > 0 {
            Self::new(sum / (count as f64))
        } else {
            Self::default()
        }
    }
}
