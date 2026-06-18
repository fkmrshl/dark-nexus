# OSINT Identity Graph

## Why the Graph Was Added 

The OSINT module already had a flat list of hits. That list is useful for terminal output and export compatibility, but it cannot clearly separate a verified seed, a generated candidate, an observed account, and a supporting external tool observation.

The identity graph adds that structure without changing the old output shape. It gives the module a place to record relationships and evidence while keeping generated hypotheses separate from account findings.

## Main Data Types

### Nodes

Nodes represent values or entities. Examples include a username value, an email address, a phone number, a platform name, an account URL, or a tool finding.

Each node has:

- A deterministic ID
- A type
- A value
- A status
- A confidence value

### Edges

Edges represent relationships between nodes. An edge can say that a candidate was generated from a seed, an account was found on a platform, or an external tool observation corroborates an account URL.

Each edge can reference evidence IDs. This keeps the relationship tied to the observation that caused it.

### Evidence

Evidence records explain why a node or edge exists. Evidence can come from the original seed input, generated candidate logic, internal HTTP checks, or external tools.

Each evidence record includes source fields, optional tool and URL fields, detail text, confidence, certainty, and status.

### Hypotheses

A hypothesis is a generated value that might be useful to check later. It is not a finding. Username variants, generated email addresses, email local-part username candidates, and phone formats are stored as hypotheses.

### Confidence and Certainty

Confidence is a numeric score. Certainty is the user-facing level used by the OSINT module:

- Confirmed
- Probable
- Possible

The graph stores both where needed. A higher confidence does not automatically prove identity ownership.

## Node Types in Practical Terms

Common node types include:

- `Username`: a username seed or generated username candidate.
- `Email`: an email seed or generated email candidate.
- `Phone`: a phone seed or generated phone-format candidate.
- `Account`: an account URL or stable account identity.
- `Platform`: a platform or site name.
- `ToolFinding`: a stable representation of an external tool observation.

Other node types exist for future use, such as domain, location, name, carrier, and web mention.

## Edge Types in Practical Terms

Common edge types include:

- `GeneratedCandidate`: a generated username or email hypothesis from a username seed.
- `DerivedFromEmail`: a username hypothesis derived from an email local part.
- `DerivedFromPhone`: a phone-format hypothesis derived from a phone seed.
- `AccountOnPlatform`: an internal platform scan found an account URL on a platform.
- `ExternalToolObserved`: an external tool observed an account, platform, or related finding.
- `Corroborates`: an external tool exact URL match supports an existing account node.
- `ConflictsWith`: reserved for future conflict handling.

`SeedIs`, `ProfileAttribute`, and other edge types are present for future extension, but are not the main path for current terminal behavior.

## Evidence Types in Practical Terms

Current evidence types include:

- `SeedInput`: the original input supplied to the OSINT scan.
- `Generated`: a candidate generated from the seed or another input value.
- `InternalHttp`: an accepted internal platform scan result.
- `ExternalTool`: an observation from a local helper tool.
- `PhoneHeuristic`, `EmailHeuristic`, and `WebSearch`: reserved for future use.

## Username Inputs

For a username scan:

- The seed username is stored as a verified `Username` node.
- Generated username variants are stored as hypothesis `Username` nodes.
- Generated email guesses are stored as hypothesis `Email` nodes.
- Internal platform hits create `Account` and `Platform` nodes connected by `AccountOnPlatform`.
- External tool output can add tool findings, observations, or corroboration.

Generated variants remain hypotheses. They do not become account hits just because they were generated.

## Email Inputs

For an email scan:

- The seed email is stored as a verified `Email` node.
- Username candidates derived from the local part are stored as hypothesis `Username` nodes.
- External email tools can add observed evidence.

The local part of an email can be useful, but it is not treated as a verified username.

## Phone Inputs

For a phone scan:

- The seed phone is normalized to a `+digits` style value and stored as a verified `Phone` node.
- Alternate phone formats are stored as hypothesis `Phone` nodes.
- Phone helper tools can add observed evidence when available.

The normalized seed stays verified. Alternate formats are hypotheses.

## Internal Platform Hits

When an internal platform scan accepts a hit, the graph records:

- A `Platform` node for the site name.
- An `Account` node for the account URL.
- `InternalHttp` evidence with source `internal`.
- An `AccountOnPlatform` edge from the account to the platform.

The existing flat hit is still created as before. The graph record is additional in-memory structure.

## External Tool Observations

External tools produce observations that can be structured or unstructured.

The graph can record:

- A `ToolFinding` node for the tool observation.
- `ExternalTool` evidence.
- An `ExternalToolObserved` edge to an account URL or platform.
- A `Corroborates` edge when an external observation exactly matches an internal account URL.

Platform-only external matches are weak observations. They are not exact proof.

## Evidence Status Values

Statuses are intentionally conservative:

- `Verified`: the seed value supplied by the user.
- `Hypothesis`: a generated candidate that has not been observed as an account.
- `Observed`: evidence was observed, but is not proof of ownership.
- `Corroborated`: evidence supports another observation, usually by exact URL match.
- `Conflict`: reserved for future disagreement handling.
- `Rejected`: reserved for future rejected evidence.

## Why Generated Candidates Are Not Facts

Generated candidates are guesses. For example, a username can produce likely email addresses, and an email local part can produce likely usernames. These values may be useful for follow-up checks, but they are not account findings until independent evidence supports them.

Keeping hypotheses separate avoids turning string generation into false OSINT results.

## Why External-Only Observations Are Not Confirmed

External tools can be useful, but their output can include stale data, partial matches, parsing artifacts, or unrelated accounts. An external-only observation can be possible or probable, depending on structure, but it is not confirmed by itself.

An exact URL match can corroborate an existing internal account hit. Platform-name-only matches remain weaker because many platforms and usernames can overlap.

## Future Extension Ideas

Possible future graph work:

- Add graph export formats after the terminal behavior is stable.
- Add conflict records for contradictory evidence.
- Add richer profile attributes with explicit evidence.
- Represent info-only external tool output without changing flat results.
- Add controlled tests for graph summary rendering.
- Add clearer install-mode configuration for optional tools.

These are extension points, not current guarantees.
