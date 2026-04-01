use crate::{
    analysis_result::AnalysisResult,
    analyze::Analyze,
    severity::Severity,
};

/// Analyzes Content-Security-Policy headers for security issues.
pub struct AnalyzeCSP {
    pub directives: Vec<String>,
}

impl AnalyzeCSP {
    /// Create a new `AnalyzeCSP` from an optional CSP header value string.
    /// Directives are split by `;` and trimmed.
    pub fn new(csp_header_value: Option<&str>) -> Self {
        let directives = match csp_header_value {
            Some(value) => value
                .split(';')
                .map(|d| d.trim())
                .filter(|d| !d.is_empty())
                .map(String::from)
                .collect(),
            None => Vec::new(),
        };
        Self { directives }
    }

    fn frame_ancestors_check(directive: &str) -> Option<AnalysisResult> {
        const NAME: &str = "Clickjacking protection, using frame-ancestors";

        if !directive
            .to_lowercase()
            .starts_with("frame-ancestors")
        {
            return None;
        }

        if directive.contains("'none'") {
            Some(AnalysisResult::new(
                Severity::Ok,
                NAME,
                "CSP prevents clickjacking by blocking all frame ancestors.",
            ))
        } else if directive.contains("'self'") {
            Some(AnalysisResult::new(
                Severity::Warning,
                NAME,
                "CSP allows same-origin framing. Clickjacking risk may exist.",
            ))
        } else if directive.contains('*') {
            Some(AnalysisResult::new(
                Severity::Fail,
                NAME,
                "CSP allows framing from any origin. High clickjacking risk.",
            ))
        } else {
            Some(AnalysisResult::new(
                Severity::Fail,
                NAME,
                "CSP does not prevent clickjacking. Frame ancestors are allowed.",
            ))
        }
    }
}

impl Analyze for AnalyzeCSP {
    fn analyze(&self) -> Vec<AnalysisResult> {
        self.directives
            .iter()
            .filter_map(|d| Self::frame_ancestors_check(d))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Directive parsing tests (mirrors C# AnalyzeCSPFixture) ---

    #[test]
    fn directives_should_not_be_empty_when_a_value_exists() {
        let csp = AnalyzeCSP::new(Some("default-src 'self'"));
        assert!(!csp.directives.is_empty());
    }

    #[test]
    fn directives_should_be_empty_when_no_value_exists() {
        let csp = AnalyzeCSP::new(None);
        assert!(csp.directives.is_empty());
    }

    #[test]
    fn directives_should_be_separated_by_semicolons() {
        let csp = AnalyzeCSP::new(Some("default-src 'self'; img-src 'self' example.com"));
        assert_eq!(csp.directives.len(), 2);
        assert!(csp.directives.contains(&"default-src 'self'".to_string()));
        assert!(csp.directives.contains(&"img-src 'self' example.com".to_string()));
    }

    #[test]
    fn directives_trims_whitespace() {
        let csp = AnalyzeCSP::new(Some("  default-src 'self'  ;  img-src *  "));
        assert_eq!(csp.directives.len(), 2);
        assert!(csp.directives.contains(&"default-src 'self'".to_string()));
        assert!(csp.directives.contains(&"img-src *".to_string()));
    }

    #[test]
    fn directives_ignores_empty_segments_from_trailing_semicolons() {
        let csp = AnalyzeCSP::new(Some("default-src 'self';"));
        assert_eq!(csp.directives.len(), 1);
    }

    #[test]
    fn empty_string_produces_no_directives() {
        let csp = AnalyzeCSP::new(Some(""));
        assert!(csp.directives.is_empty());
    }

    // --- frame-ancestors analysis tests ---

    #[test]
    fn frame_ancestors_none_returns_ok() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors 'none'"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Ok);
    }

    #[test]
    fn frame_ancestors_self_returns_warning() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors 'self'"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Warning);
    }

    #[test]
    fn frame_ancestors_wildcard_returns_fail() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors *"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
    }

    #[test]
    fn frame_ancestors_specific_domain_returns_fail() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors https://example.com"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
    }

    #[test]
    fn non_frame_ancestors_directive_returns_no_result() {
        let csp = AnalyzeCSP::new(Some("default-src 'self'"));
        let results = csp.analyze();
        assert!(results.is_empty());
    }

    #[test]
    fn no_csp_header_returns_no_results() {
        let csp = AnalyzeCSP::new(None);
        let results = csp.analyze();
        assert!(results.is_empty());
    }

    #[test]
    fn frame_ancestors_check_is_case_insensitive() {
        let csp = AnalyzeCSP::new(Some("Frame-Ancestors 'none'"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Ok);
    }

    #[test]
    fn multiple_directives_only_reports_frame_ancestors() {
        let csp = AnalyzeCSP::new(Some(
            "default-src 'self'; frame-ancestors 'none'; img-src *",
        ));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Ok);
    }

    #[test]
    fn frame_ancestors_result_has_correct_name() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors 'none'"));
        let results = csp.analyze();
        assert_eq!(
            results[0].name,
            "Clickjacking protection, using frame-ancestors"
        );
    }

    #[test]
    fn frame_ancestors_none_has_correct_comment() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors 'none'"));
        let results = csp.analyze();
        assert_eq!(
            results[0].comment,
            "CSP prevents clickjacking by blocking all frame ancestors."
        );
    }

    #[test]
    fn frame_ancestors_self_has_correct_comment() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors 'self'"));
        let results = csp.analyze();
        assert_eq!(
            results[0].comment,
            "CSP allows same-origin framing. Clickjacking risk may exist."
        );
    }

    #[test]
    fn frame_ancestors_wildcard_has_correct_comment() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors *"));
        let results = csp.analyze();
        assert_eq!(
            results[0].comment,
            "CSP allows framing from any origin. High clickjacking risk."
        );
    }
}
