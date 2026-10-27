# Module reliability audit

## DNS and WHOIS

This pass covers the DNS/WHOIS command paths and their shared process supervisor. Subdomain discovery is covered separately below; other network modules have not received the same module-level audit.

Resolved issues:

- Helper deadlines now cover process exit even after stdout/stderr close. Continuous output cannot prevent timeout or cancellation checks. Helpers have isolated process groups, close-on-exec pipes and capped output. Cleanup terminates descendants that remain in the helper's process group; it does not track processes that create a separate session or group.
- DNS distinguishes successful empty/negative answers from process errors, timeouts, truncated or malformed replies and server failures. CNAME records remain distinct from addresses, and answer owners must correlate with the question or its bounded CNAME chain.
- Reverse lookups in the DNS module use the same supervised `dig` path. SPF references and nameservers are validated before follow-up calls. Optional enrichment and total runtime have explicit limits.
- AXFR requires complete SOA framing; diagnostic text is never treated as transfer success. DS/DNSKEY observations are no longer advertised as cryptographic DNSSEC validation.
- WHOIS lines reach JSON, CSV and text exports. Repeated and unfamiliar fields, long lines and partial responses are retained within the capture limit. Common service refusal messages on stdout or stderr are distinguished from negative registry replies.
- Module errors and cancellation finalize requested exports with explicit status and diagnostics. Existing report fields remain available; new fields are additive.

The regression suite uses local fake helpers and synthetic replies. It checks successful and negative responses, malformed data, unrelated answer owners, unsafe references, error/partial exports, timeouts and cancellation. Process tests exercise stream closure, continuous output, concurrent helpers and descendants in the helper's process group. The Linux CI workflow is configured to build and run these checks, then test installation into a temporary prefix. Its actual run results determine whether each environment passes.

These checks do not establish availability of public resolvers or registries. WHOIS classification recognizes common free-form messages; it is not a validator for every registry's text format. DNS parsing checks reply structure, answer correlation and the syntax of selected record types. It is not a universal DNS resource-record validator; policy and cryptographic validation remain outside this command's contract. See the [command reference](cli.md#dns-and-whois) for exact limits, statuses and exit codes.

## Subdomain discovery

This pass covers candidate validation, A/AAAA resolution, the DNS/HTTP queue, cancellation, optional enrichment and result-file handling.

- DNS observations reach shared and module reports before HTTP enrichment. IPv6-only names remain available without enrichment. Operational DNS failures are distinct from negative answers.
- Queue waits and active DNS/HTTP operations observe cancellation. Queue teardown joins workers on normal completion and exceptions; thread-pool construction cleans up workers when creation fails.
- Passive names must remain under the requested domain. Certificate JSON and DoH responses are parsed structurally; DoH checks status, owner/CNAME correlation, record type and address syntax. API requests verify TLS, bound capture and report failures.
- Wildcard coincidences remain visible as marked observations. CNAME fingerprints are manual-inspection hints and do not establish a takeover.
- Module exports and checkpoints use unique temporary files and checked atomic replacement. Final snapshots are written after enrichment; checkpoints contain results, not resumable scan state. Concurrent runs can replace each other's complete files, with the last successful writer winning.

Local fixtures exercise the pipeline, resolver replies, passive parsing, HTTP limits, cancellation, worker errors and file-write failures. External resolver/registry/API availability and complete Internet-wide discovery remain outside these checks. The [command reference](cli.md#subdomains) describes limits and report behavior.
