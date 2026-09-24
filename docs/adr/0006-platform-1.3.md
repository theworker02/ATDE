# ADR-0006: Accept ATDE 1.3 as the stable product line

- Status: Accepted (v1.3.0)
- Date: 2026-09-24
- Deciders: ATDE maintainers

## Context

Early packaging used 0.x labels while the monorepo already contained a full JetStream pipeline, local-first containment, Atlas honeypot, catch-node baits, operator console, and acquisition diligence pack. Operators and acquirers reasonably treat a working multi-surface appliance with OpenAPI, STIX/abuse export, and seven bait protocols as a **product line**, not a pre-release experiment.

## Decision

1. Stamp the current platform as **ATDE 1.3.0** (semver major ≥ 1).  
2. Treat **1.3.x** as the supported stable line for security disclosures and operator docs.  
3. Fold prior 0.1 / 0.2 notes into the 1.0–1.2 changelog narrative; do not market 0.x as current.  
4. Keep defensive non-goals (ADR-0003) and local-first containment (ADR-0001) unchanged under the 1.3 product claim.  
5. Roadmap forward as **1.4 fleet → 1.5 packaging → 2.0 enterprise**, not another 0.x climb.

## Consequences

### Positive

- Acquisition and SKU language match deployable capability.  
- Clear support matrix in `SECURITY.md`.  
- Operators get a single “current” version for `atde -version`, badges, and RELEASE notes.

### Negative / trade-offs

- Semver history is compressed (multiple capability milestones share one calendar day). Acceptable for a single-founder GA packaging event; future releases should land on distinct dates when possible.  
- Callers that keyed off `0.2.0` must update scripts — document in `RELEASE.md`.

## Related

- [`RELEASE.md`](../../RELEASE.md)  
- [`CHANGELOG.md`](../../CHANGELOG.md)  
- [`docs/ROADMAP.md`](../ROADMAP.md)  
- ADR-0001, ADR-0003
