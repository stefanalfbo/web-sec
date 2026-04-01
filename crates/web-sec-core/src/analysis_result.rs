use crate::severity::Severity;

/// Represents the result of a security analysis check.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub severity: Severity,
    pub name: String,
    pub comment: String,
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
        }
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
    fn clone_produces_independent_copy() {
        let original = AnalysisResult::new(Severity::Warning, "Name", "Comment");
        let cloned = original.clone();
        assert_eq!(original.severity, cloned.severity);
        assert_eq!(original.name, cloned.name);
        assert_eq!(original.comment, cloned.comment);
    }
}
