use std::collections::HashMap;

use crate::{analysis_result::AnalysisResult, analyze::Analyze, severity::Severity};

const NAME: &str = "Permissions Policy";
const SENSITIVE_FEATURES: &[&str] = &["camera", "microphone", "geolocation", "payment", "usb"];

/// Analyzes the Permissions-Policy header for risky browser feature access.
pub struct AnalyzePermissionsPolicy {
    header_value: Option<String>,
}

impl AnalyzePermissionsPolicy {
    pub fn new(header_value: Option<&str>) -> Self {
        Self {
            header_value: header_value.map(String::from),
        }
    }

    fn parse_directives(value: &str) -> HashMap<String, String> {
        value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .filter_map(|part| {
                let (feature, allowlist) = part.split_once('=')?;
                Some((feature.trim().to_lowercase(), allowlist.trim().to_string()))
            })
            .collect()
    }

    fn is_disabled(allowlist: &str) -> bool {
        allowlist.trim() == "()"
    }

    fn allows_all_origins(allowlist: &str) -> bool {
        let trimmed = allowlist.trim();
        trimmed == "*" || trimmed.contains('*')
    }
}

impl Analyze for AnalyzePermissionsPolicy {
    fn analyze(&self) -> Vec<AnalysisResult> {
        let value = match &self.header_value {
            None => {
                return vec![AnalysisResult::new(
                    Severity::Warning,
                    NAME,
                    "Permissions-Policy header is missing. Sensitive browser features are not explicitly restricted.",
                )
                .with_score(-5)];
            }
            Some(value) => value,
        };

        let directives = Self::parse_directives(value);
        let explicitly_listed = SENSITIVE_FEATURES
            .iter()
            .filter_map(|feature| {
                directives
                    .get(*feature)
                    .map(|allowlist| (*feature, allowlist))
            })
            .collect::<Vec<_>>();

        let wildcard_features = explicitly_listed
            .iter()
            .filter_map(|(feature, allowlist)| {
                Self::allows_all_origins(allowlist).then_some(*feature)
            })
            .collect::<Vec<_>>();

        if !wildcard_features.is_empty() {
            let feature_list = wildcard_features.join(", ");
            return vec![AnalysisResult::new(
                Severity::Fail,
                NAME,
                format!(
                    "Permissions-Policy allows sensitive features for all origins: {feature_list}."
                ),
            )
            .with_score(-10)];
        }

        if explicitly_listed.is_empty() {
            return vec![AnalysisResult::new(
                Severity::Warning,
                NAME,
                "Permissions-Policy is present but does not explicitly restrict common sensitive features.",
            )
            .with_score(0)];
        }

        let all_sensitive_disabled = SENSITIVE_FEATURES.iter().all(|feature| {
            directives
                .get(*feature)
                .map(|allowlist| Self::is_disabled(allowlist))
                .unwrap_or(false)
        });

        if all_sensitive_disabled {
            return vec![
                AnalysisResult::new(
                    Severity::Ok,
                    NAME,
                    "Permissions-Policy disables common sensitive browser features.",
                )
                .with_score(5),
            ];
        }

        vec![AnalysisResult::new(
            Severity::Ok,
            NAME,
            "Permissions-Policy is present and does not grant common sensitive features to all origins.",
        )
        .with_score(0)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_header_returns_warning() {
        let results = AnalyzePermissionsPolicy::new(None).analyze();
        assert_eq!(results[0].severity, Severity::Warning);
        assert_eq!(results[0].score_impact, -5);
    }

    #[test]
    fn wildcard_sensitive_feature_returns_fail() {
        let results = AnalyzePermissionsPolicy::new(Some("camera=*")).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -10);
    }

    #[test]
    fn wildcard_in_parenthesized_allowlist_returns_fail() {
        let results =
            AnalyzePermissionsPolicy::new(Some("microphone=(self \"https://example.com\" *)"))
                .analyze();
        assert_eq!(results[0].severity, Severity::Fail);
    }

    #[test]
    fn missing_sensitive_directives_returns_warning() {
        let results = AnalyzePermissionsPolicy::new(Some("fullscreen=(self)")).analyze();
        assert_eq!(results[0].severity, Severity::Warning);
        assert_eq!(results[0].score_impact, 0);
    }

    #[test]
    fn all_sensitive_features_disabled_returns_ok_with_bonus() {
        let results = AnalyzePermissionsPolicy::new(Some(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ))
        .analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 5);
    }

    #[test]
    fn self_only_sensitive_feature_returns_ok() {
        let results = AnalyzePermissionsPolicy::new(Some("camera=(self), microphone=()")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 0);
    }

    #[test]
    fn feature_names_are_compared_case_insensitively() {
        let results = AnalyzePermissionsPolicy::new(Some("CAMERA=*")).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
    }
}
