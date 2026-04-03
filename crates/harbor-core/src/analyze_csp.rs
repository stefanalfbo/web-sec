use crate::{analysis_result::AnalysisResult, analyze::Analyze, severity::Severity};

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
        const NAME: &str = "Click-jacking protection, using frame-ancestors";

        if !directive.to_lowercase().starts_with("frame-ancestors") {
            return None;
        }

        if directive.contains("'none'") {
            Some(
                AnalysisResult::new(
                    Severity::Ok,
                    NAME,
                    "CSP prevents click-jacking by blocking all frame ancestors.",
                )
                .with_score(0),
            )
        } else if directive.contains("'self'") {
            Some(
                AnalysisResult::new(
                    Severity::Warning,
                    NAME,
                    "CSP allows same-origin framing. Click-jacking risk may exist.",
                )
                .with_score(-5),
            )
        } else if directive.contains('*') {
            Some(
                AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "CSP allows framing from any origin. High click-jacking risk.",
                )
                .with_score(-10),
            )
        } else {
            Some(
                AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "CSP does not prevent click-jacking. Frame ancestors are allowed.",
                )
                .with_score(-10),
            )
        }
    }

    /// Checks the effective script source (script-src, falling back to
    /// default-src) for unsafe values.
    fn script_src_check(directives: &[String]) -> Option<AnalysisResult> {
        const NAME: &str = "Cross-site scripting prevention, using CSP";

        let effective = directives
            .iter()
            .find(|d| d.to_lowercase().starts_with("script-src"))
            .or_else(|| {
                directives
                    .iter()
                    .find(|d| d.to_lowercase().starts_with("default-src"))
            })?;

        let lower = effective.to_lowercase();

        if lower.contains("'unsafe-inline'") {
            return Some(
                AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "CSP allows unsafe-inline scripts. XSS risk is significantly elevated.",
                )
                .with_score(-15),
            );
        }

        if lower.contains("'unsafe-eval'") {
            return Some(
                AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "CSP allows unsafe-eval. Execution of arbitrary code is possible.",
                )
                .with_score(-10),
            );
        }

        if lower.contains(" data:") || lower.ends_with(" data:") || lower.contains(" data: ") {
            return Some(
                AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "CSP allows data: URIs in scripts. This can be abused for XSS.",
                )
                .with_score(-10),
            );
        }

        // Overly broad: just "https:" or "http:" as a source
        if lower
            .split_whitespace()
            .any(|tok| tok == "https:" || tok == "http:")
        {
            return Some(
                AnalysisResult::new(
                    Severity::Warning,
                    NAME,
                    "CSP allows scripts from any HTTPS/HTTP origin. Too permissive.",
                )
                .with_score(-20),
            );
        }

        None
    }

    /// Awards a bonus when the CSP is strictly locked down:
    /// `default-src 'none'` and no unsafe sources anywhere.
    fn csp_bonus_check(directives: &[String]) -> Option<AnalysisResult> {
        let has_none_default = directives
            .iter()
            .any(|d| d.to_lowercase().starts_with("default-src") && d.contains("'none'"));

        if !has_none_default {
            return None;
        }

        let any_unsafe = directives.iter().any(|d| {
            let lower = d.to_lowercase();
            lower.contains("'unsafe-inline'") || lower.contains("'unsafe-eval'")
        });

        if any_unsafe {
            return None;
        }

        Some(
            AnalysisResult::new(
                Severity::Ok,
                "Content Security Policy implementation",
                "CSP is optimally configured with default-src 'none' and no unsafe sources.",
            )
            .with_score(10),
        )
    }
}

impl Analyze for AnalyzeCSP {
    fn analyze(&self) -> Vec<AnalysisResult> {
        let mut results = Vec::new();

        for directive in &self.directives {
            if let Some(r) = Self::frame_ancestors_check(directive) {
                results.push(r);
            }
        }

        if let Some(r) = Self::script_src_check(&self.directives) {
            results.push(r);
        }

        if let Some(r) = Self::csp_bonus_check(&self.directives) {
            results.push(r);
        }

        results
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
        assert!(
            csp.directives
                .contains(&"img-src 'self' example.com".to_string())
        );
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
        assert_eq!(results[0].score_impact, -5);
    }

    #[test]
    fn frame_ancestors_wildcard_returns_fail() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors *"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -10);
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
            "Click-jacking protection, using frame-ancestors"
        );
    }

    #[test]
    fn frame_ancestors_none_has_correct_comment() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors 'none'"));
        let results = csp.analyze();
        assert_eq!(
            results[0].comment,
            "CSP prevents click-jacking by blocking all frame ancestors."
        );
    }

    #[test]
    fn frame_ancestors_self_has_correct_comment() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors 'self'"));
        let results = csp.analyze();
        assert_eq!(
            results[0].comment,
            "CSP allows same-origin framing. Click-jacking risk may exist."
        );
    }

    #[test]
    fn frame_ancestors_wildcard_has_correct_comment() {
        let csp = AnalyzeCSP::new(Some("frame-ancestors *"));
        let results = csp.analyze();
        assert_eq!(
            results[0].comment,
            "CSP allows framing from any origin. High click-jacking risk."
        );
    }

    // --- script-src analysis tests ---

    #[test]
    fn unsafe_inline_in_script_src_returns_fail() {
        let csp = AnalyzeCSP::new(Some("script-src 'self' 'unsafe-inline'"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -15);
    }

    #[test]
    fn unsafe_eval_in_script_src_returns_fail() {
        let csp = AnalyzeCSP::new(Some("script-src 'self' 'unsafe-eval'"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -10);
    }

    #[test]
    fn unsafe_inline_in_default_src_returns_fail() {
        let csp = AnalyzeCSP::new(Some("default-src 'unsafe-inline'"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
    }

    #[test]
    fn https_wildcard_in_script_src_returns_warning() {
        let csp = AnalyzeCSP::new(Some("script-src https: 'self'"));
        let results = csp.analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Warning);
        assert_eq!(results[0].score_impact, -20);
    }

    #[test]
    fn script_src_with_only_self_returns_no_result() {
        let csp = AnalyzeCSP::new(Some("script-src 'self'"));
        let results = csp.analyze();
        assert!(results.is_empty());
    }

    // --- CSP bonus tests ---

    #[test]
    fn default_src_none_with_no_unsafe_awards_bonus() {
        let csp = AnalyzeCSP::new(Some("default-src 'none'; frame-ancestors 'none'"));
        let results = csp.analyze();
        let bonus = results
            .iter()
            .find(|r| r.name == "Content Security Policy implementation");
        assert!(bonus.is_some());
        assert_eq!(bonus.unwrap().score_impact, 10);
    }

    #[test]
    fn default_src_none_with_unsafe_inline_does_not_award_bonus() {
        let csp = AnalyzeCSP::new(Some("default-src 'none'; script-src 'unsafe-inline'"));
        let results = csp.analyze();
        let bonus = results
            .iter()
            .find(|r| r.name == "Content Security Policy implementation");
        assert!(bonus.is_none());
    }

    #[test]
    fn default_src_self_does_not_award_bonus() {
        let csp = AnalyzeCSP::new(Some("default-src 'self'"));
        let results = csp.analyze();
        let bonus = results
            .iter()
            .find(|r| r.name == "Content Security Policy implementation");
        assert!(bonus.is_none());
    }
}
