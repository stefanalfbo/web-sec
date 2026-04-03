use crate::severity::Severity;

/// Represents the result of a security analysis check.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub severity: Severity,
    pub name: String,
    pub comment: String,
    /// Score impact for this result. Negative values are penalties deducted
    /// from the baseline; positive values are bonuses added when score >= 90.
    pub score_impact: i32,
}

impl AnalysisResult {
    pub fn new(
        severity: Severity,
        name: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            name: name.into(),
            comment: comment.into(),
            score_impact: 0,
        }
    }

    /// Set the score impact for this result.
    pub fn with_score(mut self, score_impact: i32) -> Self {
        self.score_impact = score_impact;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_result_with_correct_fields() {
        let result = AnalysisResult::new(Severity::Ok, "Test Name", "Test Comment");
        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(result.name, "Test Name");
        assert_eq!(result.comment, "Test Comment");
        assert_eq!(result.score_impact, 0);
    }

    #[test]
    fn new_accepts_owned_strings() {
        let name = String::from("Owned Name");
        let comment = String::from("Owned Comment");
        let result = AnalysisResult::new(Severity::Fail, name, comment);
        assert_eq!(result.name, "Owned Name");
        assert_eq!(result.comment, "Owned Comment");
    }

    #[test]
    fn with_score_sets_score_impact() {
        let result = AnalysisResult::new(Severity::Ok, "Name", "Comment").with_score(10);
        assert_eq!(result.score_impact, 10);
    }

    #[test]
    fn with_score_accepts_negative_values() {
        let result = AnalysisResult::new(Severity::Fail, "Name", "Comment").with_score(-25);
        assert_eq!(result.score_impact, -25);
    }

    #[test]
    fn clone_produces_independent_copy() {
        let original = AnalysisResult::new(Severity::Warning, "Name", "Comment").with_score(-5);
        let cloned = original.clone();
        assert_eq!(original.severity, cloned.severity);
        assert_eq!(original.name, cloned.name);
        assert_eq!(original.comment, cloned.comment);
        assert_eq!(original.score_impact, cloned.score_impact);
    }
}
