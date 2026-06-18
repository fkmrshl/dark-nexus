# OSINT Module Changes

## Overview

The OSINT module was updated to reduce false positives, handle local helper tools more predictably, expose better HTTP/process result details, and add an in-memory identity graph. The visible command-line workflow is still the same: a user provides a username, email address, or phone number, and the module prints terminal results for the local scan.

The changes are intended to make results easier to reason about. A page fetch, a generated candidate, and an external tool observation now mean different things internally.

## What the OSINT Module Does

The module accepts three input types:

- Username
- Email address
- Phone number

Depending on the input type, it may:

- Generate likely username, email, or phone-format candidates.
- Check known platform profile URLs for username hits.
- Run supported external tools when they are installed.
- Correlate internal hits with external tool observations.
- Print a terminal summary of findings, candidates, and graph-backed relationships.

## What Was Improved

The refactor focused on local correctness and maintainability:

- Internal platform hits now need stronger evidence.
- HTTP fetch results now include status and final URL metadata.
- External tools no longer block installed sibling tools when some tools are missing.
- External-only observations are no longer promoted to confirmed findings.
- The identity graph separates verified seeds, generated hypotheses, observed accounts, and external evidence.
- The final terminal summary now uses graph data while preserving the existing flat hit output.

## False Positive Reduction

Internal platform checks are more conservative now:

- Empty responses score as no hit.
- A fetched body alone is not enough to create a hit.
- Positive markers are required before a platform hit can be emitted.
- A missing dead marker is weak evidence by itself.
- A dead marker suppresses the hit unless there is strong positive evidence.
- Blocked pages, generic HTML, redirects, and error pages are less likely to become account hits.

This does not make every platform check perfect. Public sites can change markup, block automation, or return localized pages. The module should still be treated as a triage tool, not proof of identity.

## HTTP and Process Handling Improvements

The existing `safe_exec(args, timeout)` API remains compatible and still uses argv-style process execution rather than shell commands.

The HTTP wrapper now has a detailed result path:

- `safe_curl(url, timeout)` still returns the body only for old callers.
- `safe_curl_detailed(url, timeout)` returns body, final URL, HTTP status, curl exit code, timeout state, and classification flags.
- curl output metadata is separated from the response body so large bodies do not hide status information.
- Response bodies are capped in memory.
- 403, 404, 429, 5xx, curl failures, timeouts, invalid URLs, and empty bodies are not treated as usable OSINT fetch evidence.

The module still uses the curl command-line tool through argv-style execution. It does not require libcurl integration for these OSINT checks.

## External Tool Handling Improvements

External tools are optional local helpers. Supported tools include entries such as Sherlock, Maigret, Holehe, theHarvester, and PhoneInfoga when they are available on the system.

Preparation behavior is now narrower:

- Missing tools do not disable installed tools in the same flow.
- Refusing installation skips only the missing tools.
- Non-interactive mode skips only missing tools.
- Existing tool runners still self-skip when their binary is unavailable.
- User-facing text should describe missing tools as skipped, not as disabling all external checks.

The install behavior is intentionally minimal. A future change could make installation mode more configurable, but this refactor does not redesign tool installation policy.

## Identity Graph Model

The module now keeps a graph alongside the existing flat hit list. The graph is in-memory only and is not exported through JSON or CSV.

The graph contains:

- Nodes for values such as usernames, emails, phones, accounts, platforms, and tool findings.
- Edges for relationships such as generated candidates, account-on-platform findings, and external corroboration.
- Evidence records for seed input, generated candidates, internal HTTP observations, and external tool observations.

Node, edge, and evidence IDs are deterministic. They are based on stable values rather than random IDs, timestamps, or global counters.

## Seeds, Candidates, Hypotheses, Internal Hits, and External Evidence

The graph distinguishes these concepts:

- Seed input: the original username, email, or phone value. It is represented as verified.
- Generated candidates: possible usernames, emails, or phone formats derived from the seed. They are hypotheses.
- Internal hits: accepted platform scan results. These create account and platform graph records.
- External observations: output from local helper tools. These are observed or possible evidence, not automatic proof.
- External corroboration: an exact URL match between an external observation and an internal account hit. This can support an existing account finding.

Generated candidates are not treated as found accounts. External-only observations are not confirmed by themselves.

## Graph-Aware Terminal Summary

The final `IDENTITY GRAPH SUMMARY` block now uses the in-memory graph. It separates:

- The verified seed
- Account findings
- Exact external corroboration
- External observations
- Generated hypotheses
- Conflicts, when any exist

The detailed flat hit list and profile output remain unchanged. The graph summary is a terminal view only.

## What Did Not Change

These parts were intentionally preserved:

- Existing username, email, and phone command flow
- Existing flat `Hit` output
- Existing `OsintEntry` shape
- Existing JSON, CSV, and TXT export shape
- Existing `OutputWriter` behavior
- Existing CLI flags
- Existing install scripts
- External tool binaries and their command-line behavior

The graph does not add a new export format in this change.

## Limitations

The OSINT module still has practical limits:

- Public websites can block, redirect, localize, or change markup.
- External tools can have their own false positives and parsing limitations.
- A matching account URL does not prove account ownership by the seed identity.
- Generated candidates are only hypotheses.
- Some external tool output that lacks a URL or platform may not be represented as graph evidence yet.
- The graph is useful for reasoning, but it is not a full investigation database.

## Safety and Ethics Notes

Use the OSINT module only for authorized, lawful, and appropriate checks. Avoid scanning people or accounts where you do not have a legitimate reason. Treat results as leads that require human review, especially when the output is possible or probable rather than confirmed.

Do not publish private personal data from scan output. Avoid committing local scan results, credentials, API keys, or environment files to a public repository.

## Basic Local Checks

Build the project:

```sh
cmake --build build -j2
```

Run quick manual checks only when you intend to perform a local terminal test:

```sh
./build/dark_nexus osint example_user
./build/dark_nexus osint user@example.com
./build/dark_nexus osint +15551234567
```

For automated or repeatable checks, prefer fake local helper scripts and controlled curl behavior. Do not run live OSINT scans in automated tests unless that is explicitly intended.
