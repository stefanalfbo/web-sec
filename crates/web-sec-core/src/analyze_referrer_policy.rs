use crate::{analysis_result::AnalysisResult, analyze::Analyze, severity::Severity};

/// Analyzes the Referrer-Policy header.
pub struct AnalyzeReferrerPolicy {
    header_value: Option<String>,
}

impl AnalyzeReferrerPolicy {
    pub fn new(header_value: Option<&str>) -> Self {
        Self {
            header_value: header_value.map(String::from),
        }
    }
}

impl Analyze for AnalyzeReferrerPolicy {
    fn analyze(&self) -> Vec<AnalysisResult> {
        const NAME: &str = "Cross-origin information leakage prevention";

        let value = match &self.header_value {
            None => {
                return vec![AnalysisResult::new(
                    Severity::Warning,
                    NAME,
                    "Referrer-Policy header is missing. The browser default may leak referrer information.",
                )
                .with_score(0)];
            }
            Some(v) => v.trim().to_lowercase(),
        };

        match value.as_str() {
            // Unsafe policies
            "unsafe-url" | "no-referrer-when-downgrade" => vec![AnalysisResult::new(
                Severity::Fail,
                NAME,
                "Referrer-Policy leaks full URLs to cross-origin destinations.",
            )
            .with_score(-5)],

            // Conservative policies — eligible for bonus
            "no-referrer" | "strict-origin" | "strict-origin-when-cross-origin" => {
                vec![AnalysisResult::new(
                    Severity::Ok,
                    NAME,
                    "Referrer-Policy is set to a conservative value that limits information leakage.",
                )
                .with_score(5)]
            }

            // Acceptable but not eligible for bonus
            "origin" | "same-origin" | "origin-when-cross-origin" => {
                vec![AnalysisResult::new(
                    Severity::Ok,
                    NAME,
                    "Referrer-Policy limits referrer to origin only.",
                )
                .with_score(0)]
            }

            _ => vec![AnalysisResult::new(
                Severity::Warning,
                NAME,
                "Referrer-Policy has an unrecognised value.",
            )
            .with_score(0)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_header_returns_warning_with_no_penalty() {
        let results = AnalyzeReferrerPolicy::new(None).analyze();
        assert_eq!(results[0].severity, Severity::Warning);
        assert_eq!(results[0].score_impact, 0);
    }

    #[test]
    fn unsafe_url_returns_fail() {
        let results = AnalyzeReferrerPolicy::new(Some("unsafe-url")).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -5);
    }

    #[test]
    fn no_referrer_when_downgrade_returns_fail() {
        let results =
            AnalyzeReferrerPolicy::new(Some("no-referrer-when-downgrade")).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -5);
    }

    #[test]
    fn no_referrer_returns_ok_with_bonus() {
        let results = AnalyzeReferrerPolicy::new(Some("no-referrer")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 5);
    }

    #[test]
    fn strict_origin_returns_ok_with_bonus() {
        let results = AnalyzeReferrerPolicy::new(Some("strict-origin")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 5);
    }

    #[test]
    fn strict_origin_when_cross_origin_returns_ok_with_bonus() {
        let results =
            AnalyzeReferrerPolicy::new(Some("strict-origin-when-cross-origin")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 5);
    }

    #[test]
    fn same_origin_returns_ok_without_bonus() {
        let results = AnalyzeReferrerPolicy::new(Some("same-origin")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 0);
    }

    #[test]
    fn value_is_compared_case_insensitively() {
        let results = AnalyzeReferrerPolicy::new(Some("No-Referrer")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 5);
    }
}
