# Threat bus contracts (`threat.v1`)

Canonical subject contracts for `THREAT_PIPELINE`. JSON Schema drafts live in `/schemas`. Breaking changes require a new major subject prefix (`threat.v2`).

## Stream

| Field | Value |
|-------|-------|
| Name | `THREAT_PIPELINE` |
| Subjects | `threat.v1.raw.*`, `threat.v1.artifact.*`, `threat.v1.action.*` |
| Retention | Limits, max age 7d (default) |
| Storage | File |

## Subjects

| Subject | Schema | Producer | Consumers | Ack |
|---------|--------|----------|-----------|-----|
| `threat.v1.raw.ct` | `schemas/raw-ct.json` | ct-streamer | extract | Manual |
| `threat.v1.raw.honeypot` | (event struct) | honeypot, deception | extract, active | Manual |
| `threat.v1.artifact.extracted` | `schemas/artifact-extracted.json` | extract | enrich, active | Manual |
| `threat.v1.artifact.attack` | models.AttackEvent | deception | SIEM path / future | Manual |
| `threat.v1.action.takedown` | `schemas/takedown.json` | enrich | dispatcher | Manual |
| `threat.v1.action.disrupt` | `schemas/disrupt.json` | active, deception | edge containment | Manual |
| `threat.v1.action.sinkhole` | `schemas/sinkhole.json` | enrich | sinkhole | Manual |
| `threat.v1.action.publish` | `schemas/publish.json` | enrich | publisher | Manual |
| `threat.v1.action.dlq` | opaque | bus helpers | ops | — |

## Invariants

1. IPs in disrupt events must be parseable; private IPs are not OS-blocked.  
2. `dry_run` may appear on action events; live mode clears subsystem dry-run via config cascade.  
3. Poison actions are **simulated** (`simulated: true` / evidence files only).  
4. Consumers must not crash the process on single poison messages — log + DLQ/ack policy per worker.

## Versioning policy

- Additive optional JSON fields: minor  
- Removing/renaming fields or subject meaning: new `threat.vN`  
