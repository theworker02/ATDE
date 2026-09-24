# ADR-0005: Catch ledger format

## Status

Accepted (v0.1.0)

## Context

Operators and diligence demos need durable proof of catches without standing up Postgres on day one. Abuse handoff needs a per-IP summary; auditors need an append-only trail.

## Decision

- Append every event to `data/caught/events.jsonl` (plus daily shards)  
- Upsert rolling `data/caught/dossier_<IP>.json` with hit counts and last-seen  
- CLI `atde -mode caught` reads the ledger without the bus  

## Consequences

- Zero-DB demo path  
- Filesystem growth must be rotated (OPERATOR.md)  
- Future Postgres fleet ledger can ingest the same JSONL schema  
