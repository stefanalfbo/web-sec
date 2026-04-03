<p align="center">
	<img src="https://raw.githubusercontent.com/stefanalfbo/harbor/main/assets/logo.svg" alt="Harbor logo" width="720" />
</p>

# HARbor

[![CI](https://github.com/stefanalfbo/harbor/actions/workflows/ci.yml/badge.svg)](https://github.com/stefanalfbo/harbor/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/stefanalfbo/harbor/graph/badge.svg)](https://codecov.io/github/stefanalfbo/harbor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

HARbor is an offline analyzer for HAR files.

It analyzes recorded HTTP responses for security headers, cookie settings, CSP, HSTS, Permissions-Policy, CORS, and related browser policy issues without making live requests.

## Workspace

This repository contains two Rust crates:

- `harbor-cli` - the end-user command-line interface and terminal UI
- `harbor-core` - the reusable library for HAR parsing, analysis, scoring, and reporting

## Crates

### harbor-cli

Use `harbor-cli` if you want a ready-to-run terminal tool.

Install from crates.io:

```bash
cargo install harbor-cli
```

Run a scan:

```bash
harbor scan path/to/capture.har
```

### harbor-core

Use `harbor-core` if you want to embed Harbor analysis in another Rust application or automation workflow.

Add it as a dependency:

```toml
[dependencies]
harbor-core = "0.1"
```

## Current Checks

Harbor currently analyzes:

- Content-Security-Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- Permissions-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- CORS
- Cookie security flags and SameSite settings

## Development

Run the CLI from this workspace:

```bash
cargo run -p harbor-cli -- scan services.google.com.har
```

Run the test suite:

```bash
cargo test
```

## Scoring

Harbor follows an HTTP Observatory-style scoring model:

- Start from a baseline score of `100`
- Apply penalties first
- Apply bonuses only if the post-penalty score is at least `90`
- Clamp the final score to the range `0..145`

