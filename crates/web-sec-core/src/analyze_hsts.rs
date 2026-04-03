use crate::{analysis_result::AnalysisResult, analyze::Analyze, severity::Severity};

const SIX_MONTHS_SECS: u64 = 15_768_000;
const ONE_YEAR_SECS: u64 = 31_536_000;

/// Analyzes the Strict-Transport-Security (HSTS) header.
pub struct AnalyzeHSTS {
    header_value: Option<String>,
}

impl AnalyzeHSTS {
    pub fn new(header_value: Option<&str>) -> Self {
        Self {
            header_value: header_value.map(String::from),
        }
    }

    fn parse_max_age(value: &str) -> Option<u64> {
        value
            .split(';')
            .map(str::trim)
            .find(|part| part.to_lowercase().starts_with("max-age"))
            .and_then(|part| part.split('=').nth(1))
            .and_then(|v| v.trim().parse::<u64>().ok())
    }

    fn has_directive(value: &str, directive: &str) -> bool {
        value
            .split(';')
            .map(str::trim)
            .any(|part| part.to_lowercase() == directive)
    }
}

impl Analyze for AnalyzeHSTS {
    fn analyze(&self) -> Vec<AnalysisResult> {
        const NAME: &str = "HTTP Strict Transport Security (HSTS)";

        let value = match &self.header_value {
            None => {
                return vec![AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "HSTS header is missing. Connections may be downgraded to HTTP.",
                )
                .with_score(-20)];
            }
            Some(v) => v,
        };

        let max_age = match Self::parse_max_age(value) {
            None => {
                return vec![AnalysisResult::new(
                    Severity::Fail,
                    NAME,
                    "HSTS header present but max-age is missing or invalid.",
                )
                .with_score(-20)];
            }
            Some(age) => age,
        };

        if max_age < SIX_MONTHS_SECS {
            return vec![AnalysisResult::new(
                Severity::Fail,
                NAME,
                "HSTS max-age is less than 6 months. Browsers will not enforce HSTS reliably.",
            )
            .with_score(-20)];
        }

        // Check eligibility for preload bonus: >= 1 year + includeSubDomains + preload
        let has_preload = Self::has_directive(value, "preload");
        let has_subdomains = Self::has_directive(value, "includesubdomains");
        if max_age >= ONE_YEAR_SECS && has_preload && has_subdomains {
            return vec![AnalysisResult::new(
                Severity::Ok,
                NAME,
                "HSTS is properly configured with preload and includeSubDomains.",
            )
            .with_score(5)];
        }

        vec![AnalysisResult::new(
            Severity::Ok,
            NAME,
            "HSTS is configured with an adequate max-age.",
        )
        .with_score(0)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_header_returns_fail() {
        let results = AnalyzeHSTS::new(None).analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -20);
    }

    #[test]
    fn max_age_below_six_months_returns_fail() {
        let results = AnalyzeHSTS::new(Some("max-age=86400")).analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -20);
    }

    #[test]
    fn max_age_exactly_six_months_returns_ok() {
        let results =
            AnalyzeHSTS::new(Some(&format!("max-age={SIX_MONTHS_SECS}"))).analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 0);
    }

    #[test]
    fn max_age_two_years_returns_ok() {
        let results = AnalyzeHSTS::new(Some("max-age=63072000")).analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Ok);
    }

    #[test]
    fn preload_and_include_subdomains_awards_bonus() {
        let results = AnalyzeHSTS::new(Some(
            "max-age=63072000; includeSubDomains; preload",
        ))
        .analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 5);
    }

    #[test]
    fn preload_without_include_subdomains_does_not_award_bonus() {
        let results =
            AnalyzeHSTS::new(Some("max-age=63072000; preload")).analyze();
        assert_eq!(results[0].score_impact, 0);
    }

    #[test]
    fn header_without_max_age_returns_fail() {
        let results = AnalyzeHSTS::new(Some("includeSubDomains; preload")).analyze();
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].score_impact, -20);
    }

    #[test]
    fn max_age_is_parsed_case_insensitively() {
        let results = AnalyzeHSTS::new(Some("Max-Age=63072000")).analyze();
        assert_eq!(results[0].severity, Severity::Ok);
    }

    #[test]
    fn directives_with_extra_whitespace_are_parsed() {
        let results =
            AnalyzeHSTS::new(Some("max-age=63072000 ; includeSubDomains ; preload"))
                .analyze();
        assert_eq!(results[0].score_impact, 5);
    }
}
