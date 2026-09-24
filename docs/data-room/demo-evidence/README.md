# Demo evidence pack (sanitized)

Synthetic catch records for diligence demos. **Not** from a live production node.  
IPs use documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`).

| File | Purpose |
|------|---------|
| `events.jsonl` | Append-only hit stream (fingerprinted) |
| `dossier_203.0.113.50.json` | Multi-hit scanner dossier |
| `dossier_198.51.100.22.json` | SSH password-burn dossier |
| `summary.json` | Console `/v1/summary`-shaped snapshot |

Reproduce live: `bash scripts/verify-catch.sh` after `deploy-catch-node`.
