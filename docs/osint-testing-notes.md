# OSINT Testing Notes

## Build Command

Build the project before running OSINT checks:

```sh
cmake --build build -j2
```

The OSINT module is a local terminal workflow. Do not run live scans in automated tests unless that is explicitly intended.

## Basic Username Test

For a manual username check:

```sh
./build/dark_nexus osint example_user
```

Use a handle you own or a harmless test value. Do not scan third-party targets without authorization.

Expected terminal areas may include:

- Generated username or email candidates
- Internal platform results, if any accepted hits are found
- External tool status, if optional tools are installed
- Profile summary
- Identity graph summary

## Basic Email Test

For a manual email check:

```sh
./build/dark_nexus osint user@example.com
```

Use an address you control or a clearly fake test address. Email tests may generate username candidates from the local part. Those candidates should remain hypotheses unless later evidence supports them.

## Basic Phone Test

For a manual phone check:

```sh
./build/dark_nexus osint +15551234567
```

Use a test number or a number you are authorized to check. Phone-format variants should appear as hypotheses, not confirmed accounts.

## Avoiding External Tool Installation During Quick Checks

External helper tools are optional. During a quick local check:

- Do not install missing tools unless the test is specifically about installation.
- In non-interactive runs, missing tools should be skipped.
- If prompted interactively, answering no should skip only the missing tools.
- Installed sibling tools should still run when another helper is missing.

For controlled tests, prefer fake helper scripts on a temporary `PATH` rather than real network-facing tools.

## Terminal Output Sections to Check

The visible output should still include the existing detailed flat results where applicable. The final graph-aware summary should be compact and separated into sections such as:

- `SEED`
- `ACCOUNT FINDINGS`
- `EXTERNAL CORROBORATION`
- `EXTERNAL OBSERVATIONS`
- `GENERATED HYPOTHESES`
- `CONFLICTS`, only when relevant or shown as none

The graph summary should not dump internal graph IDs, evidence IDs, raw tool-finding keys, or export-only data.

## What Should Not Happen

These are important regression checks:

- Fetched-only pages should not create platform hits.
- Pages without positive markers should not create internal hits.
- 403, 404, 429, curl failures, timeouts, invalid URLs, and empty responses should not create internal platform hits.
- Generated username, email, or phone hypotheses should not appear as confirmed accounts.
- External-only observations should not become confirmed.
- Platform-name-only external matches should not be shown as exact proof.
- Substring platform matching should not upgrade a hit.
- Missing external tools should not disable installed sibling tools.

## Controlled HTTP Checks

When testing HTTP behavior, avoid live platform scans. Use a fake `curl` command on a temporary `PATH` or another controlled local setup.

Useful cases:

- HTTP 200 with a known positive marker can produce an internal hit.
- HTTP 404 with a body should not produce a hit.
- HTTP 403 or 429 with a body should not produce a hit.
- curl nonzero exit should not produce a hit.
- Timeout behavior should classify the result as blocked or error.
- Large response bodies should not hide curl metadata such as status and final URL.

## Controlled External Tool Checks

When testing external correlation, use fake `ToolResult` data or temporary helper scripts. Avoid real external services unless a manual test explicitly calls for them.

Useful cases:

- Exact URL match can corroborate an existing internal account hit.
- Platform-only exact normalized match remains weak and observed.
- Structured external-only observations are probable at most.
- Unstructured external-only observations are possible at most.
- External-only observations never become confirmed.

## Output and Export Compatibility

The graph is currently terminal-only. JSON, CSV, and TXT exports should continue to use the existing `ScanResult` and `OsintEntry` fields.

Regression checks:

- No graph export appears in JSON or CSV.
- `OutputWriter` behavior remains unchanged.
- The final terminal `IDENTITY GRAPH SUMMARY` can change, but existing detailed hit output should remain compatible.

## Notes for Automated Tests

Automated tests should avoid live OSINT scans by default. Prefer:

- Compile-only tests
- Temporary local harnesses
- Fake `curl`
- Fake external helper scripts
- Synthetic graph data

Live checks can be useful for manual smoke testing, but they are noisy. Network blocks, rate limits, redirects, and site markup changes should be reported as network or tool uncertainty, not automatically as code bugs.
