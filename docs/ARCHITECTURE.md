# Architecture

## Design principles

1. **Owned infrastructure only** — decoys, firewalls, WAF IPSets, and DNS rewrites under operator control  
2. **Local-first containment** — OS block is mandatory when enabled; cloud is best-effort  
3. **Fail-soft integrations** — missing/failed Cloudflare/AWS/Abuse APIs never abort the catch pipeline  
4. **Evidence over offense** — stolen exfil channels and third-party P2P remain simulation artifacts  
5. **Event-driven** — NATS JetStream subjects under `threat.v1.*` (optional on catch-node)  
6. **Operator export** — abuse Markdown + STIX 2.1 from the same dossier model (ATDE 1.3)

## Pipeline (1.3)

```
┌──────────────────────────────────────────────────────────────────────┐
│ 1. BAIT MESH (catch-node)                                            │
│  HTTP :8080 · SSH :2222 · Redis :6379 · Telnet :2323                 │
│  MySQL :3306 · FTP :2121 · Deception :8443                           │
└───────────────────────────────┬──────────────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 2. FINGERPRINT + DOSSIER                                             │
│  severity · tool · tags → events.jsonl + dossier_<IP>.json           │
│  optional NATS: threat.v1.raw.honeypot                               │
└───────────────┬───────────────────────────────┬──────────────────────┘
                ▼                               ▼
┌───────────────────────────┐    ┌─────────────────────────────────────┐
│ 3A. LOCAL FIREWALL        │    │ 3B. OPERATOR SURFACE                │
│ ipset / nft / iptables /  │    │ console · OpenAPI · STIX · abuse MD │
│ netsh (first)             │    │ PGP email · webhook                 │
└───────────────────────────┘    └─────────────────────────────────────┘
                │
                ▼ (optional full mesh)
┌──────────────────────────────────────────────────────────────────────┐
│ 4. JETSTREAM MESH                                                    │
│  extract → enrich → disrupt / publish / sinkhole / immunize          │
└──────────────────────────────────────────────────────────────────────┘
```

## Containment API

`internal/disrupt/edge.Blocker.EnforceContainment(ctx, ip, reason, score, dry)`:

- `score < 0.8` → skip  
- private / loopback / TEST-NET → record only  
- local `LocalFirewall.BlockIP` (ipset preferred on Linux)  
- spawn Cloudflare / AWS / webhook goroutines; wait up to ~12s without failing the caller  

## Subjects

See `schemas/` and `internal/models/events.go`. Catch OpenAPI: `schemas/openapi-catch-v1.json`.

| Subject | Producer → Consumer |
|---------|---------------------|
| `threat.v1.raw.ct` | CT streamer → extract |
| `threat.v1.raw.honeypot` | honeypot/deception → extract + active |
| `threat.v1.artifact.extracted` | extract → enrich + active |
| `threat.v1.action.takedown` | enrich → dispatcher |
| `threat.v1.action.disrupt` | active → edge containment |
| `threat.v1.action.sinkhole` | enrich → sinkhole |
| `threat.v1.action.publish` | enrich → publisher |
| `threat.v1.artifact.attack` | deception recorder |

## Trust boundaries

- Decoy processes must not hold production database credentials  
- Firewall commands never go through a shell  
- Secrets loaded from environment (`hydrateSecretsFromEnv`), never committed  
- Ops `:9091` is privileged read of catch evidence — token + network ACL required in production  

See ADR 0006 for the 1.3 stable-line decision.
