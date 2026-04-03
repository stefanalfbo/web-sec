<p align="center">
  <img src="https://raw.githubusercontent.com/stefanalfbo/harbor/main/assets/logo.svg" alt="Harbor logo" width="720" />
</p>

# harbor-core

[![CI](https://github.com/stefanalfbo/harbor/actions/workflows/ci.yml/badge.svg)](https://github.com/stefanalfbo/harbor/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/stefanalfbo/harbor/graph/badge.svg)](https://codecov.io/github/stefanalfbo/harbor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Harbor is an offline security analyzer for HAR files.

The `harbor-core` crate is the library that parses HAR captures, runs security checks against recorded HTTP responses, and produces de-duplicated findings with an overall score and grade.

## What It Provides

`harbor-core` includes:

- HAR parsing based on the `har` crate
- Security analysis of recorded response headers and cookies
- Worst-case de-duplication across multiple HAR entries
- An HTTP Observatory-style score and grade

## Current Checks

The library currently analyzes:

- Content-Security-Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- Permissions-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- CORS
- Cookie security flags and SameSite settings

## Installation

```toml
[dependencies]
harbor-core = "0.1"
```

## Example

```rust
use harbor_core::har_scanner::HarScanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let report = HarScanner::scan_file("capture.har")?;

	println!("score: {} ({})", report.score.score, report.score.grade);

	for result in report.results {
		println!(
			"[{:#?}] {}: {} ({})",
			result.severity,
			result.name,
			result.comment,
			result.score_impact
		);
	}

	Ok(())
}
```

## Scoring Model

Harbor uses an HTTP Observatory-style scoring approach:

- Start from a baseline score of `100`
- Apply penalties first
- Apply bonuses only if the post-penalty score is at least `90`
- Clamp the final score to the range `0..145`

The resulting `ScanReport` includes both the per-check findings and the aggregated score.

## Intended Use

`harbor-core` is useful if you want to:

- Build your own CLI or UI on top of Harbor analysis
- Integrate HAR security checks into automation or CI
- Inspect a full browser session offline instead of probing live endpoints
- Reuse Harbor scoring and finding logic in another Rust project

## Related Crate

If you want the ready-to-use terminal interface, install `harbor-cli`.

Repository: https://github.com/stefanalfbo/harbor
