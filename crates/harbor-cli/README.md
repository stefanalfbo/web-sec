<p align="center">
	<img src="https://raw.githubusercontent.com/stefanalfbo/harbor/main/assets/logo.svg" alt="Harbor logo" width="720" />
</p>

# harbor-cli

[![CI](https://github.com/stefanalfbo/harbor/actions/workflows/ci.yml/badge.svg)](https://github.com/stefanalfbo/harbor/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/stefanalfbo/harbor/graph/badge.svg)](https://codecov.io/github/stefanalfbo/harbor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Harbor is an offline security analyzer for HAR files.

The `harbor-cli` crate provides the `harbor` command-line interface and terminal UI for scanning recorded HTTP traffic and surfacing security issues without making live requests.

## What It Checks

`harbor-cli` currently reports findings for:

- Content-Security-Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- Permissions-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- CORS
- Cookie security flags and SameSite settings

## Install

```bash
cargo install harbor-cli
```

## Usage

Scan a HAR file:

```bash
harbor scan path/to/capture.har
```

From this workspace during development:

```bash
cargo run -p harbor-cli -- scan services.google.com.har
```

## Output

The CLI opens a terminal UI that shows:

- The overall score and grade
- The number of failed checks
- A table of findings with severity, score impact, check name, and explanation

Press `q` or `Esc` to exit the interface.

## Use Cases

- Review exported browser traffic offline
- Check security headers across multiple responses in one session
- Compare worst-case behavior across a site capture
- Triage header and cookie regressions during development

## How Scoring Works

Harbor follows an HTTP Observatory-style scoring model:

- Start from a baseline score of `100`
- Apply penalties first
- Apply bonuses only if the post-penalty score is at least `90`
- Clamp the final score to the range `0..145`

## Workspace

This crate is the CLI frontend for the Harbor workspace. The core analysis logic lives in the `harbor-core` crate.

Repository: https://github.com/stefanalfbo/harbor
