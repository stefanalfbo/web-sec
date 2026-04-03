use crate::{analysis_result::AnalysisResult, analyze::Analyze, severity::Severity};

/// Analyzes the X-Content-Type-Options header to prevent MIME sniffing.
pub struct AnalyzeXContentTypeOptions {
    header_value: Option<String>,
}

impl AnalyzeXContentTypeOptions {
    pub fn new(header_value: Option<&str>) -> Self {
        Self {
            header_value: header_value.map(String::from),
        }
    }
}

impl Analyze for AnalyzeXContentTypeOptions {
    fn analyze(&self) -> Vec<AnalysisResult> {
        const NAME: &str = "MIME sniffing prevention";

        let value = match &self.header_value {
            None => {
                return vec![AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses.",
                )
                .with_score(-5)];
            }
            Some(v) => v.trim().to_lowercase(),
        };

        if value == "nosniff" {
            vec![AnalysisResult::new(
                Severity::Ok,
                NAME,
                "X-Content-Type-Options is set to nosniff. MIME sniffing is disabled.",
            )
            .with_score(0)]
        } else {
            vec![AnalysisResult::new(
                Severity::Warning,
                NAME,
                "X-Content-Type-Options has an unexpected value. nosniff is required.",
            )
            .with_score(-5)]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_header_returns_fail() {
        let results = AnalyzeXContentTypeOptions::new(None).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -5);
    }

    #[test]
    fn nosniff_returns_ok() {
        let results = AnalyzeXContentTypeOptions::new(Some("nosniff")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 0);
    }

    #[test]
    fn nosniff_is_case_insensitive() {
        let results = AnalyzeXContentTypeOptions::new(Some("NOSNIFF")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
    }

    #[test]
    fn unexpected_value_returns_warning() {
        let results = AnalyzeXContentTypeOptions::new(Some("sniff")).analyze();
        assert_eq!(results[0].severity, Severity::Warning);
        assert_eq!(results[0].score_impact, -5);
    }
}
