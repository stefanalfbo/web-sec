use crate::{analysis_result::AnalysisResult, analyze::Analyze, severity::Severity};

/// Represents a single parsed Set-Cookie header.
#[derive(Debug, PartialEq)]
struct ParsedCookie {
    name: String,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
}

impl ParsedCookie {
    fn parse(header: &str) -> Self {
        let parts: Vec<&str> = header.split(';').collect();
        let name = parts
            .first()
            .and_then(|p| p.split('=').next())
            .map(str::trim)
            .unwrap_or("")
            .to_string();

        let mut secure = false;
        let mut http_only = false;
        let mut same_site = None;

        for part in parts.iter().skip(1) {
            let lower = part.trim().to_lowercase();
            if lower == "secure" {
                secure = true;
            } else if lower == "httponly" {
                http_only = true;
            } else if let Some(val) = lower.strip_prefix("samesite=") {
                same_site = Some(val.to_string());
            }
        }

        Self {
            name,
            secure,
            http_only,
            same_site,
        }
    }
}

/// Analyzes Set-Cookie headers for secure configuration.
pub struct AnalyzeCookies {
    set_cookie_headers: Vec<String>,
}

impl AnalyzeCookies {
    /// `set_cookie_headers` is the list of all `Set-Cookie` header values
    /// from a single HTTP response.
    pub fn new(set_cookie_headers: Vec<&str>) -> Self {
        Self {
            set_cookie_headers: set_cookie_headers.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Analyze for AnalyzeCookies {
    fn analyze(&self) -> Vec<AnalysisResult> {
        if self.set_cookie_headers.is_empty() {
            return vec![];
        }

        let cookies: Vec<ParsedCookie> = self
            .set_cookie_headers
            .iter()
            .map(|h| ParsedCookie::parse(h))
            .collect();

        let mut results = Vec::new();

        // Check Secure flag
        let insecure: Vec<&str> = cookies
            .iter()
            .filter(|c| !c.secure)
            .map(|c| c.name.as_str())
            .collect();
        if !insecure.is_empty() {
            results.push(
                AnalysisResult::new(
                    Severity::Fail,
                    "Cookie security (Secure flag)",
                    "One or more cookies are missing the Secure flag and may be sent over HTTP.",
                )
                .with_score(-20),
            );
        }

        // Check HttpOnly flag
        let no_httponly: Vec<&str> = cookies
            .iter()
            .filter(|c| !c.http_only)
            .map(|c| c.name.as_str())
            .collect();
        if !no_httponly.is_empty() {
            results.push(
                AnalysisResult::new(
                    Severity::Warning,
                    "Cookie security (HttpOnly flag)",
                    "One or more cookies are missing the HttpOnly flag and are accessible via JavaScript.",
                )
                .with_score(-5),
            );
        }

        // Check SameSite attribute
        let no_samesite: Vec<&str> = cookies
            .iter()
            .filter(|c| c.same_site.is_none())
            .map(|c| c.name.as_str())
            .collect();

        // SameSite=None without Secure is a critical misconfiguration
        let samesite_none_without_secure: Vec<&str> = cookies
            .iter()
            .filter(|c| {
                c.same_site.as_deref() == Some("none") && !c.secure
            })
            .map(|c| c.name.as_str())
            .collect();

        if !samesite_none_without_secure.is_empty() {
            results.push(
                AnalysisResult::new(
                    Severity::Fail,
                    "Cookie security (SameSite=None)",
                    "Cookies with SameSite=None must also have the Secure flag.",
                )
                .with_score(-20),
            );
        } else if !no_samesite.is_empty() {
            results.push(
                AnalysisResult::new(
                    Severity::Warning,
                    "Cookie security (SameSite attribute)",
                    "One or more cookies are missing the SameSite attribute. CSRF risk may be elevated.",
                )
                .with_score(-5),
            );
        }

        // Bonus: all cookies are fully hardened
        if results.is_empty() {
            results.push(
                AnalysisResult::new(
                    Severity::Ok,
                    "Cookie security",
                    "All cookies are configured with Secure, HttpOnly, and SameSite.",
                )
                .with_score(5),
            );
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cookies_returns_no_results() {
        let results = AnalyzeCookies::new(vec![]).analyze();
        assert!(results.is_empty());
    }

    #[test]
    fn fully_hardened_cookie_returns_ok_with_bonus() {
        let results = AnalyzeCookies::new(vec![
            "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
        ])
        .analyze();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Ok);
        assert_eq!(results[0].score_impact, 5);
    }

    #[test]
    fn missing_secure_flag_returns_fail() {
        let results =
            AnalyzeCookies::new(vec!["session=abc; Path=/; HttpOnly; SameSite=Strict"])
                .analyze();
        assert!(results.iter().any(|r| r.name == "Cookie security (Secure flag)"
            && r.severity == Severity::Fail
            && r.score_impact == -20));
    }

    #[test]
    fn missing_httponly_flag_returns_warning() {
        let results = AnalyzeCookies::new(vec![
            "session=abc; Path=/; Secure; SameSite=Strict",
        ])
        .analyze();
        assert!(results
            .iter()
            .any(|r| r.name == "Cookie security (HttpOnly flag)"
                && r.severity == Severity::Warning
                && r.score_impact == -5));
    }

    #[test]
    fn missing_samesite_returns_warning() {
        let results =
            AnalyzeCookies::new(vec!["session=abc; Path=/; Secure; HttpOnly"]).analyze();
        assert!(results
            .iter()
            .any(|r| r.name == "Cookie security (SameSite attribute)"
                && r.severity == Severity::Warning));
    }

    #[test]
    fn samesite_none_without_secure_returns_fail() {
        let results =
            AnalyzeCookies::new(vec!["session=abc; Path=/; SameSite=None"]).analyze();
        assert!(results
            .iter()
            .any(|r| r.name == "Cookie security (SameSite=None)"
                && r.severity == Severity::Fail
                && r.score_impact == -20));
    }

    #[test]
    fn samesite_none_with_secure_does_not_trigger_samesite_fail() {
        let results =
            AnalyzeCookies::new(vec!["session=abc; Path=/; Secure; HttpOnly; SameSite=None"])
                .analyze();
        assert!(!results
            .iter()
            .any(|r| r.name == "Cookie security (SameSite=None)"));
    }

    #[test]
    fn multiple_cookies_all_issues_reported() {
        let results = AnalyzeCookies::new(vec![
            "a=1; Path=/; Secure; HttpOnly; SameSite=Strict",
            "b=2; Path=/", // missing Secure, HttpOnly, SameSite
        ])
        .analyze();
        let has_secure_fail = results
            .iter()
            .any(|r| r.name == "Cookie security (Secure flag)");
        let has_httponly_warn = results
            .iter()
            .any(|r| r.name == "Cookie security (HttpOnly flag)");
        let has_samesite_warn = results
            .iter()
            .any(|r| r.name == "Cookie security (SameSite attribute)");
        assert!(has_secure_fail);
        assert!(has_httponly_warn);
        assert!(has_samesite_warn);
    }

    #[test]
    fn parsed_cookie_extracts_name() {
        let cookie = ParsedCookie::parse("session=abc123; Path=/; Secure");
        assert_eq!(cookie.name, "session");
    }

    #[test]
    fn parsed_cookie_detects_secure_flag() {
        let c = ParsedCookie::parse("x=1; Secure");
        assert!(c.secure);
        let c2 = ParsedCookie::parse("x=1");
        assert!(!c2.secure);
    }

    #[test]
    fn parsed_cookie_detects_httponly_flag() {
        let c = ParsedCookie::parse("x=1; HttpOnly");
        assert!(c.http_only);
    }

    #[test]
    fn parsed_cookie_extracts_samesite_value() {
        let c = ParsedCookie::parse("x=1; SameSite=Lax");
        assert_eq!(c.same_site.as_deref(), Some("lax"));
    }
}
