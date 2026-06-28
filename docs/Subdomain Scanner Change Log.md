# Subdomain Scanner Change Log

This file lists major architectural changes to the subdomain scanner. Small fixes, typo corrections, and one-line safety patches are intentionally omitted.

## Scanner architecture split

The subdomain scanner was split out of a single large source file into smaller internal components.

The current layout separates orchestration, HTTP enrichment, passive enumeration, candidate generation, shared internal declarations, and DNS backend logic.

This makes the scanner easier to maintain without changing the public command syntax.

## Streaming deep wordlist scans

Deep mode now streams wordlist candidates instead of loading the full list into memory.

The scanner normalizes, deduplicates, and resolves candidates in batches. This supports large wordlists while keeping memory usage bounded.

## Async DNS pipeline hardening

The DNS engine now honors requested concurrency, rotates resolver shards, and collects callback results through per-host index storage.

This removed shared result-map writes from DNS callbacks and made batch execution safe under high concurrency.

## Resolver health and ranking

Custom resolver files are deduplicated, tested, ranked, and filtered before use.

Large resolver lists are reduced to a healthy subset based on measured response time. Built-in resolvers remain available as a fallback.

## DNS event loop correction

The c-ares event loop now processes timeout ticks correctly.

The poll backend notifies c-ares when no socket event arrives, when there are no active descriptors, and when poll times out. This prevents unresolved brute-force candidates from stalling until the outer batch deadline.

Bulk DNS currently uses the corrected poll backend instead of the older `io_uring` hot path.

## Direct bulk A lookups

Bulk wordlist DNS uses direct A-record queries through c-ares.

The scanner no longer uses general address resolution for the brute-force A-record path. This keeps the hot path narrow and predictable.

## Pipeline idle barriers

The HTTP enrichment queue now tracks active work and supports idle waiting.

The scanner waits for HTTP enrichment at phase boundaries before building snapshots for permutations and JavaScript scraping.

## Result attribution cleanup

The scanner no longer copies HTTP metadata between hosts that share the same IP address.

Each discovered subdomain is enriched and reported as its own result. This prevents wrong titles, server headers, technology labels, and WAF labels from being attributed to the wrong host.

## Wildcard fingerprinting

Wildcard detection now uses multiple random probes and response signatures.

Candidates are filtered only when they match wildcard behavior strongly enough. Partial IP overlap is not enough to discard a result.

## Streaming permutations

Permutation candidates are emitted directly into DNS batches.

The scanner no longer builds one large permutation vector before resolving. This reduces memory pressure on domains with many discovered base hosts.

## Lightweight JavaScript target selection

JavaScript scraping now uses a compact host list selected from HTTP-positive results.

The scanner does not copy the full result set just to build JS scraping targets.

## Internal CNAME enrichment

CNAME enrichment is handled by the internal DNS engine.

The scanner no longer shells out to `dig` for CNAME checks. This avoids command overhead and prevents command error text from being stored as CNAME data.

## Checkpoint output

Deep scans now write atomic checkpoint files during long runs.

Checkpoint files contain partial results and are written at batch or phase boundaries. They do not replace the final JSON and CSV export.

## User interface compatibility

The public subdomain commands stayed compatible:

```bash
dark-nexus --subdomain example.com --mode F
dark-nexus --subdomain example.com --mode D
```

Custom resolvers are configured by placing resolver files in supported locations. No new resolver CLI flag is required.
