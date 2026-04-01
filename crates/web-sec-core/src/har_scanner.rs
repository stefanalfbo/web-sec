use std::{fs::File, path::Path};

use crate::{
    analysis_result::AnalysisResult,
    analyze::Analyze,
    analyze_csp::AnalyzeCSP,
    severity::Severity,
};

/// Scans HAR (HTTP Archive) files for security issues.
pub struct HarScanner;

impl HarScanner {
    /// Scan a HAR file and return all security analysis results.
    /// Each entry's response headers are analyzed independently.
    pub fn scan_file<P: AsRef<Path>>(path: P) -> Result<Vec<AnalysisResult>, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let har = har::from_reader(file)?;

        let mut results = Vec::new();

        match har.log {
            har::Spec::V1_2(log) => {
                for entry in &log.entries {
                    let csp_value = entry
                        .response
                        .headers
                        .iter()
                        .find(|h| h.name.to_lowercase() == "content-security-policy")
                        .map(|h| h.value.as_str());
                    results.extend(analyze_response_csp(csp_value));
                }
            }
            har::Spec::V1_3(log) => {
                for entry in &log.entries {
                    let csp_value = entry
                        .response
                        .headers
                        .iter()
                        .find(|h| h.name.to_lowercase() == "content-security-policy")
                        .map(|h| h.value.as_str());
                    results.extend(analyze_response_csp(csp_value));
                }
            }
        }

        Ok(results)
    }
}

fn analyze_response_csp(csp_value: Option<&str>) -> Vec<AnalysisResult> {
    if csp_value.is_none() {
        vec![AnalysisResult::new(
            Severity::Fail,
            "Content-Security-Policy header",
            "No CSP header found in response. Security policy is not enforced.",
        )]
    } else {
        AnalyzeCSP::new(csp_value).analyze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_har_with_csp(csp_value: &str) -> NamedTempFile {
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
          "headers": [
            {{ "name": "content-security-policy", "value": "{}" }}
          ],
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
}}"#,
            csp_value
        );
        file.write_all(content.as_bytes())
            .expect("failed to write temp file");
        file
    }

    fn make_har_without_csp() -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        let content = r#"{
  "log": {
    "version": "1.2",
    "creator": { "name": "test", "version": "1.0" },
    "entries": [
      {
        "startedDateTime": "2024-01-01T00:00:00.000Z",
        "time": 100.0,
        "request": {
          "method": "GET",
          "url": "https://example.com/",
          "httpVersion": "HTTP/1.1",
          "cookies": [],
          "headers": [],
          "queryString": [],
          "headersSize": -1,
          "bodySize": -1
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "HTTP/1.1",
          "cookies": [],
          "headers": [],
          "content": { "size": 0, "mimeType": "text/html" },
          "redirectURL": "",
          "headersSize": -1,
          "bodySize": -1
        },
        "cache": {},
        "timings": { "send": 0.0, "wait": 100.0, "receive": 0.0 }
      }
    ]
  }
}"#;
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

    #[test]
    fn scan_file_returns_ok_for_frame_ancestors_none() {
        let tmp = make_har_with_csp("default-src 'self'; frame-ancestors 'none'");
        let results = HarScanner::scan_file(tmp.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Ok);
    }

    #[test]
    fn scan_file_returns_fail_when_no_csp_header() {
        let tmp = make_har_without_csp();
        let results = HarScanner::scan_file(tmp.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
        assert_eq!(results[0].name, "Content-Security-Policy header");
    }

    #[test]
    fn scan_file_returns_empty_for_har_with_no_entries() {
        let tmp = make_empty_har();
        let results = HarScanner::scan_file(tmp.path()).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn scan_file_returns_warning_for_frame_ancestors_self() {
        let tmp = make_har_with_csp("frame-ancestors 'self'");
        let results = HarScanner::scan_file(tmp.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Warning);
    }

    #[test]
    fn scan_file_returns_fail_for_wildcard_frame_ancestors() {
        let tmp = make_har_with_csp("frame-ancestors *");
        let results = HarScanner::scan_file(tmp.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Fail);
    }

    #[test]
    fn scan_file_errors_on_missing_file() {
        let result = HarScanner::scan_file("/nonexistent/path/file.har");
        assert!(result.is_err());
    }
}
