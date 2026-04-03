use crate::{analysis_result::AnalysisResult, analyze::Analyze, severity::Severity};

/// Analyzes the X-Frame-Options header for click-jacking protection.
///
/// Note: CSP `frame-ancestors` supersedes this header in modern browsers.
/// Both checks are reported independently.
pub struct AnalyzeXFrameOptions {
    header_value: Option<String>,
}

impl AnalyzeXFrameOptions {
    pub fn new(header_value: Option<&str>) -> Self {
        Self {
            header_value: header_value.map(String::from),
        }
    }
}

impl Analyze for AnalyzeXFrameOptions {
    fn analyze(&self) -> Vec<AnalysisResult> {
        const NAME: &str = "Click-jacking protection, using X-Frame-Options";

        let value = match &self.header_value {
            None => {
                return vec![AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "X-Frame-Options header is missing. Older browsers may be vulnerable to click-jacking.",
                )
                .with_score(-20)];
            }
            Some(v) => v.trim().to_uppercase(),
        };

        match value.as_str() {
            "DENY" => vec![AnalysisResult::new(
                Severity::Ok,
                NAME,
                "X-Frame-Options is set to DENY. Framing is fully blocked.",
            )
            .with_score(0)],
            "SAMEORIGIN" => vec![AnalysisResult::new(
                Severity::Ok,
                NAME,
                "X-Frame-Options is set to SAMEORIGIN. Only same-origin framing is allowed.",
            )
            .with_score(0)],
            v if v.starts_with("ALLOW-FROM") => vec![AnalysisResult::new(
                Severity::Warning,
                NAME,
                "X-Frame-Options uses the deprecated ALLOW-FROM directive. Use CSP frame-ancestors instead.",
            )
            .with_score(-5)],
            _ => vec![AnalysisResult::new(
                Severity::Fail,
                NAME,
                "X-Frame-Options has an unrecognised value and will not provide protection.",
            )
            .with_score(-20)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_header_returns_fail() {
        let results = AnalyzeXFrameOptions::new(None).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -20);
    }

    #[test]
    fn deny_returns_ok() {
        let results = AnalyzeXFrameOptions::new(Some("DENY")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 0);
    }

    #[test]
    fn sameorigin_returns_ok() {
        let results = AnalyzeXFrameOptions::new(Some("SAMEORIGIN")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 0);
    }

    #[test]
    fn allow_from_returns_warning() {
        let results = AnalyzeXFrameOptions::new(Some("ALLOW-FROM https://example.com")).analyze();
        assert_eq!(results[0].severity, Severity::Warning);
        assert_eq!(results[0].score_impact, -5);
    }

    #[test]
    fn unknown_value_returns_fail() {
        let results = AnalyzeXFrameOptions::new(Some("INVALID")).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
    }

    #[test]
    fn value_is_compared_case_insensitively() {
        let results = AnalyzeXFrameOptions::new(Some("deny")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
    }

    #[test]
    fn value_with_surrounding_whitespace_is_handled() {
        let results = AnalyzeXFrameOptions::new(Some("  DENY  ")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
    }
}
