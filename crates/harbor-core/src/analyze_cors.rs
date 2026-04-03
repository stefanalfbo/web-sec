use crate::{analysis_result::AnalysisResult, analyze::Analyze, severity::Severity};

/// Analyzes Cross-Origin Resource Sharing (CORS) headers.
pub struct AnalyzeCORS {
    allow_origin: Option<String>,
    allow_credentials: Option<String>,
}

impl AnalyzeCORS {
    pub fn new(allow_origin: Option<&str>, allow_credentials: Option<&str>) -> Self {
        Self {
            allow_origin: allow_origin.map(String::from),
            allow_credentials: allow_credentials.map(String::from),
        }
    }
}

impl Analyze for AnalyzeCORS {
    fn analyze(&self) -> Vec<AnalysisResult> {
        const NAME: &str = "Cross-Origin Resource Sharing (CORS)";

        let origin = match &self.allow_origin {
            None => return vec![], // No CORS header — not a problem
            Some(v) => v.trim().to_string(),
        };

        if origin == "*" {
            let credentials_enabled = self
                .allow_credentials
                .as_deref()
                .map(|v| v.trim().to_lowercase() == "true")
                .unwrap_or(false);

            if credentials_enabled {
                return vec![AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "CORS allows all origins with credentials. Any site can make authenticated requests.",
                )
                .with_score(-50)];
            }

            return vec![AnalysisResult::new(
                Severity::Warning,
                NAME,
                "CORS allows all origins (Access-Control-Allow-Origin: *). Sensitive data may be exposed.",
            )
            .with_score(-20)];
        }

        // Restricted to a specific origin — acceptable
        vec![AnalysisResult::new(
            Severity::Ok,
            NAME,
            "CORS is restricted to specific origins.",
        )
        .with_score(0)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cors_header_returns_no_results() {
        let results = AnalyzeCORS::new(None, None).analyze();
        assert!(results.is_empty());
    }

    #[test]
    fn wildcard_origin_returns_warning() {
        let results = AnalyzeCORS::new(Some("*"), None).analyze();
        assert_eq!(results[0].severity, Severity::Warning);
        assert_eq!(results[0].score_impact, -20);
    }

    #[test]
    fn wildcard_with_credentials_returns_fail() {
        let results = AnalyzeCORS::new(Some("*"), Some("true")).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -50);
    }

    #[test]
    fn wildcard_credentials_is_case_insensitive() {
        let results = AnalyzeCORS::new(Some("*"), Some("True")).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
    }

    #[test]
    fn wildcard_with_credentials_false_returns_warning() {
        let results = AnalyzeCORS::new(Some("*"), Some("false")).analyze();
        assert_eq!(results[0].severity, Severity::Warning);
    }

    #[test]
    fn specific_origin_returns_ok() {
        let results = AnalyzeCORS::new(Some("https://example.com"), None).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 0);
    }
}
