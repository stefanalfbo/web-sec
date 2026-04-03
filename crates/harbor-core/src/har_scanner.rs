use std::{collections::HashMap, fs::File, path::Path};

use crate::{
    analysis_result::AnalysisResult, analyze::Analyze, analyze_cookies::AnalyzeCookies,
    analyze_cors::AnalyzeCORS, analyze_csp::AnalyzeCSP, analyze_hsts::AnalyzeHSTS,
    analyze_permissions_policy::AnalyzePermissionsPolicy,
    analyze_referrer_policy::AnalyzeReferrerPolicy,
    analyze_x_content_type_options::AnalyzeXContentTypeOptions,
    analyze_x_frame_options::AnalyzeXFrameOptions, scoring::ScanScore, severity::Severity,
};

/// The complete output of a HAR file scan.
pub struct ScanReport {
    /// De-duplicated results, one per check — the worst severity observed
    /// across all entries wins.
    pub results: Vec<AnalysisResult>,
    pub score: ScanScore,
}

/// Scans HAR (HTTP Archive) files for security issues.
pub struct HarScanner;

impl HarScanner {
    /// Scan a HAR file and return a `ScanReport` containing deduplicated
    /// results and the computed score.
    ///
    /// When a HAR file contains multiple entries the worst-case result for
    /// each named check is kept, giving a conservative picture of the
    /// overall security posture.
    pub fn scan_file<P: AsRef<Path>>(path: P) -> Result<ScanReport, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let har = har::from_reader(file)?;

        let mut all_results: Vec<AnalysisResult> = Vec::new();

        match har.log {
            har::Spec::V1_2(log) => {
                for entry in &log.entries {
                    let headers: Vec<(&str, &str)> = entry
                        .response
                        .headers
                        .iter()
                        .map(|h| (h.name.as_str(), h.value.as_str()))
                        .collect();
                    all_results.extend(analyze_response(&headers));
                }
            }
            har::Spec::V1_3(log) => {
                for entry in &log.entries {
                    let headers: Vec<(&str, &str)> = entry
                        .response
                        .headers
                        .iter()
                        .map(|h| (h.name.as_str(), h.value.as_str()))
                        .collect();
                    all_results.extend(analyze_response(&headers));
                }
            }
        }

        let results = deduplicate_by_worst_severity(all_results);
        let score = ScanScore::calculate(&results);
        Ok(ScanReport { results, score })
    }
}

/// Runs all analyzers against a single response's headers.
fn analyze_response(headers: &[(&str, &str)]) -> Vec<AnalysisResult> {
    let get = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(n, _)| n.to_lowercase() == name)
            .map(|(_, v)| *v)
    };

    let get_all = |name: &str| -> Vec<&str> {
        headers
            .iter()
            .filter(|(n, _)| n.to_lowercase() == name)
            .map(|(_, v)| *v)
            .collect()
    };

    let csp_value = get("content-security-policy");
    let mut results = Vec::new();

    // CSP: report missing header as a scored failure, then run directive checks
    if csp_value.is_none() {
        results.push(
            AnalysisResult::new(
                Severity::Fail,
                "Content-Security-Policy header",
                "No CSP header found in response. Security policy is not enforced.",
            )
            .with_score(-25),
        );
    } else {
        results.extend(AnalyzeCSP::new(csp_value).analyze());
    }

    results.extend(AnalyzeHSTS::new(get("strict-transport-security")).analyze());
    results.extend(AnalyzePermissionsPolicy::new(get("permissions-policy")).analyze());
    results.extend(AnalyzeXFrameOptions::new(get("x-frame-options")).analyze());
    results.extend(AnalyzeXContentTypeOptions::new(get("x-content-type-options")).analyze());
    results.extend(AnalyzeReferrerPolicy::new(get("referrer-policy")).analyze());
    results.extend(
        AnalyzeCORS::new(
            get("access-control-allow-origin"),
            get("access-control-allow-credentials"),
        )
        .analyze(),
    );
    results.extend(AnalyzeCookies::new(get_all("set-cookie")).analyze());

    results
}

/// Keeps the result with the highest (worst) severity for each check name.
/// Results are sorted by severity (Fail → Warning → Ok) for display.
fn deduplicate_by_worst_severity(results: Vec<AnalysisResult>) -> Vec<AnalysisResult> {
    let mut map: HashMap<String, AnalysisResult> = HashMap::new();

    for result in results {
        let entry = map
            .entry(result.name.clone())
            .or_insert_with(|| result.clone());
        if severity_rank(&result.severity) > severity_rank(&entry.severity) {
            *entry = result;
        }
    }

    let mut deduplicated: Vec<AnalysisResult> = map.into_values().collect();
    deduplicated.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then(a.name.cmp(&b.name))
    });
    deduplicated
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Ok => 0,
        Severity::Warning => 1,
        Severity::Fail => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_har(response_headers: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        let content = format!(
            r#"{{
  "log": {{
    "version": "1.2",
    "creator": {{ "name": "test", "version": "1.0" }},
    "entries": [
      {{
        "startedDateTime": "2024-01-01T00:00:00.000Z",
        "time": 100.0,
        "request": {{
          "method": "GET",
          "url": "https://example.com/",
          "httpVersion": "HTTP/1.1",
          "cookies": [],
          "headers": [],
          "queryString": [],
          "headersSize": -1,
          "bodySize": -1
        }},
        "response": {{
          "status": 200,
          "statusText": "OK",
          "httpVersion": "HTTP/1.1",
          "cookies": [],
          "headers": [{response_headers}],
          "content": {{ "size": 0, "mimeType": "text/html" }},
          "redirectURL": "",
          "headersSize": -1,
          "bodySize": -1
        }},
        "cache": {{}},
        "timings": {{ "send": 0.0, "wait": 100.0, "receive": 0.0 }}
      }}
    ]
  }}
}}"#
        );
        file.write_all(content.as_bytes())
            .expect("failed to write temp file");
        file
    }

    fn make_empty_har() -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        let content = r#"{
  "log": {
    "version": "1.2",
    "creator": { "name": "test", "version": "1.0" },
    "entries": []
  }
}"#;
        file.write_all(content.as_bytes())
            .expect("failed to write temp file");
        file
    }

    fn find<'a>(results: &'a [AnalysisResult], name: &str) -> Option<&'a AnalysisResult> {
        results.iter().find(|r| r.name == name)
    }

    #[test]
    fn scan_file_errors_on_missing_file() {
        let result = HarScanner::scan_file("/nonexistent/path/file.har");
        assert!(result.is_err());
    }

    #[test]
    fn empty_har_returns_no_results_and_perfect_score() {
        let tmp = make_empty_har();
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        assert!(report.results.is_empty());
        assert_eq!(report.score.score, 100);
    }

    #[test]
    fn missing_csp_returns_fail_with_score_penalty() {
        let tmp = make_har("");
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(&report.results, "Content-Security-Policy header").unwrap();
        assert_eq!(r.severity, Severity::Fail);
        assert_eq!(r.score_impact, -25);
    }

    #[test]
    fn frame_ancestors_none_returns_ok() {
        let tmp = make_har(
            r#"{ "name": "content-security-policy", "value": "default-src 'self'; frame-ancestors 'none'" }"#,
        );
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(
            &report.results,
            "Click-jacking protection, using frame-ancestors",
        )
        .unwrap();
        assert_eq!(r.severity, Severity::Ok);
    }

    #[test]
    fn frame_ancestors_self_returns_warning() {
        let tmp =
            make_har(r#"{ "name": "content-security-policy", "value": "frame-ancestors 'self'" }"#);
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(
            &report.results,
            "Click-jacking protection, using frame-ancestors",
        )
        .unwrap();
        assert_eq!(r.severity, Severity::Warning);
    }

    #[test]
    fn frame_ancestors_wildcard_returns_fail() {
        let tmp =
            make_har(r#"{ "name": "content-security-policy", "value": "frame-ancestors *" }"#);
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(
            &report.results,
            "Click-jacking protection, using frame-ancestors",
        )
        .unwrap();
        assert_eq!(r.severity, Severity::Fail);
    }

    #[test]
    fn missing_hsts_returns_fail() {
        let tmp = make_har("");
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(&report.results, "HTTP Strict Transport Security (HSTS)").unwrap();
        assert_eq!(r.severity, Severity::Fail);
        assert_eq!(r.score_impact, -20);
    }

    #[test]
    fn present_hsts_returns_ok() {
        let tmp = make_har(
            r#"{ "name": "strict-transport-security", "value": "max-age=63072000; includeSubDomains; preload" }"#,
        );
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(&report.results, "HTTP Strict Transport Security (HSTS)").unwrap();
        assert_eq!(r.severity, Severity::Ok);
        assert_eq!(r.score_impact, 5);
    }

    #[test]
    fn missing_permissions_policy_returns_warning() {
        let tmp = make_har("");
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(&report.results, "Permissions Policy").unwrap();
        assert_eq!(r.severity, Severity::Warning);
        assert_eq!(r.score_impact, -5);
    }

    #[test]
    fn restrictive_permissions_policy_returns_ok() {
        let tmp = make_har(
            r#"{ "name": "permissions-policy", "value": "camera=(), microphone=(), geolocation=(), payment=(), usb=()" }"#,
        );
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(&report.results, "Permissions Policy").unwrap();
        assert_eq!(r.severity, Severity::Ok);
        assert_eq!(r.score_impact, 5);
    }

    #[test]
    fn wildcard_permissions_policy_returns_fail() {
        let tmp = make_har(r#"{ "name": "permissions-policy", "value": "camera=*" }"#);
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(&report.results, "Permissions Policy").unwrap();
        assert_eq!(r.severity, Severity::Fail);
        assert_eq!(r.score_impact, -10);
    }

    #[test]
    fn missing_x_frame_options_returns_fail() {
        let tmp = make_har("");
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(
            &report.results,
            "Click-jacking protection, using X-Frame-Options",
        )
        .unwrap();
        assert_eq!(r.severity, Severity::Fail);
    }

    #[test]
    fn missing_x_content_type_options_returns_fail() {
        let tmp = make_har("");
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(&report.results, "MIME sniffing prevention").unwrap();
        assert_eq!(r.severity, Severity::Fail);
    }

    #[test]
    fn cors_wildcard_is_reported() {
        let tmp = make_har(r#"{ "name": "access-control-allow-origin", "value": "*" }"#);
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        let r = find(&report.results, "Cross-Origin Resource Sharing (CORS)").unwrap();
        assert_eq!(r.severity, Severity::Warning);
    }

    #[test]
    fn deduplicate_keeps_worst_severity_across_entries() {
        // Build a two-entry HAR: first entry has good HSTS, second is missing it
        let mut file = NamedTempFile::new().unwrap();
        let content = r#"{
  "log": {
    "version": "1.2",
    "creator": { "name": "test", "version": "1.0" },
    "entries": [
      {
        "startedDateTime": "2024-01-01T00:00:00.000Z",
        "time": 10.0,
        "request": { "method": "GET", "url": "https://example.com/a", "httpVersion": "HTTP/1.1", "cookies": [], "headers": [], "queryString": [], "headersSize": -1, "bodySize": -1 },
        "response": { "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "cookies": [], "headers": [{ "name": "strict-transport-security", "value": "max-age=63072000" }], "content": { "size": 0, "mimeType": "text/html" }, "redirectURL": "", "headersSize": -1, "bodySize": -1 },
        "cache": {}, "timings": { "send": 0.0, "wait": 10.0, "receive": 0.0 }
      },
      {
        "startedDateTime": "2024-01-01T00:00:00.100Z",
        "time": 10.0,
        "request": { "method": "GET", "url": "https://example.com/b", "httpVersion": "HTTP/1.1", "cookies": [], "headers": [], "queryString": [], "headersSize": -1, "bodySize": -1 },
        "response": { "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "cookies": [], "headers": [], "content": { "size": 0, "mimeType": "text/html" }, "redirectURL": "", "headersSize": -1, "bodySize": -1 },
        "cache": {}, "timings": { "send": 0.0, "wait": 10.0, "receive": 0.0 }
      }
    ]
  }
}"#;
        file.write_all(content.as_bytes()).unwrap();
        let report = HarScanner::scan_file(file.path()).unwrap();
        // The missing-HSTS entry should win (Fail beats Ok)
        let r = find(&report.results, "HTTP Strict Transport Security (HSTS)").unwrap();
        assert_eq!(r.severity, Severity::Fail);
    }

    #[test]
    fn results_sorted_fails_first() {
        let tmp = make_har("");
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        // At least the first result should be a Fail when everything is missing
        assert_eq!(report.results[0].severity, Severity::Fail);
    }

    #[test]
    fn score_is_penalised_for_missing_headers() {
        let tmp = make_har("");
        let report = HarScanner::scan_file(tmp.path()).unwrap();
        // Many headers missing — score must be well below 100
        assert!(report.score.score < 50);
    }
}
