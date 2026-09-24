# Operator handbook

Day-2 operations for ATDE **1.3** catch nodes.

## Daily

```bash
atde -mode caught -limit 100
ls data/caught/dossier_*.json | wc -l   # or Get-ChildItem on Windows
```

Review high `hit_count` dossiers before opening abuse tickets. Prefer correlating with your SIEM webhook if configured. Export STIX when feeding a TIP.

## Ops surface

```bash
curl -sS http://127.0.0.1:9091/healthz
curl -sS http://127.0.0.1:9091/metrics | findstr /i honeypot   # PowerShell: Select-String
curl -sS http://127.0.0.1:9091/v1/openapi.json | head
```

Useful counters: `atde_honeypot_hits_total`, `atde_auth_burns_total`, `atde_vuln_bait_hits_total`, `atde_catch_records_total`.

**Operator console (read-only):** [http://127.0.0.1:9091/console](http://127.0.0.1:9091/console)  
Live feed with severity, tool fingerprints, hot dossiers, Markdown + STIX export.  
Set `ATDE_OPS_TOKEN` in production; pass as `?token=` or `X-ATDE-Token`.

### Catch API (1.3)

| Path | Purpose |
|------|---------|
| `/v1/openapi.json` | OpenAPI schema for catch API |
| `/v1/capabilities` | Product capability map |
| `/v1/status` | Process / config status |
| `/v1/summary` | Dashboard stats + hot dossiers + recent feed |
| `/v1/caught?limit=50&ip=` | Recent events |
| `/v1/dossiers` | Ranked dossiers |
| `/v1/dossier/{ip}` | One dossier JSON |
| `/v1/export/{ip}` | Abuse Markdown package |
| `/v1/stix/{ip}` | STIX 2.1 indicator bundle |
| `/console` | Live operator UI |

Prove recording: `.\scripts\verify-catch.ps1` / `bash scripts/verify-catch.sh`. See [CATCH.md](CATCH.md) · [HONEYPOT.md](HONEYPOT.md).

## CLI convenience

```bash
atde -mode doctor          # preflight (NATS, ports, dirs, keys)
atde -mode status          # config + catch summary
atde -mode caught -limit 20
atde -mode caught -ip 203.0.113.10
atde -mode dossier         # list dossiers
atde -mode dossier -ip 203.0.113.10
atde -mode export -ip 203.0.113.10
atde -mode abuse -ip 203.0.113.10   # Markdown + STIX bundle
atde -mode stix -ip 203.0.113.10    # STIX 2.1 JSON
atde -mode watch           # tail events.jsonl
atde -mode seed-demo       # sanitized multi-surface lab evidence
```

Optional `-out path` writes export/stix to a file; `abuse` writes both under `data/evidence/` (or `-out` dir).

Optional alerts: set `ATDE_WEBHOOK_URL` and/or encrypted owner email (`ATDE_ALERT_TO` + SMTP + `ATDE_PGP_PUBLIC_KEY_FILE`). See [CATCH.md](CATCH.md).

### Useful URLs (replace HOST)

| URL | Use |
|-----|-----|
| `http://HOST:9091/console` | Live operator UI |
| `http://HOST:9091/v1/openapi.json` | Catch API schema |
| `http://HOST:9091/v1/summary` | JSON dashboard |
| `http://HOST:9091/v1/export/{ip}` | Abuse Markdown package |
| `http://HOST:9091/v1/stix/{ip}` | STIX bundle |
| `http://HOST:8080/` | Atlas bait (public) |
| `http://HOST:8080/openapi.json` | **Decoy** OpenAPI (not ops) |

## Containment order

1. Local OS block (ipset/netsh) — happens automatically in live mode  
2. Cloudflare / AWS — if keys present  
3. AbuseIPDB / hosting abuse — if keys / endpoints present  

If (2)/(3) fail, (1) and the dossier still stand.

## Tuning

| Goal | Setting |
|------|---------|
| Lab only (no OS blocks) | `ATDE_LOCAL_FIREWALL=0` or `ATDE_DRY_RUN=1` |
| Production catcher | `ATDE_LIVE=1`, expose decoy ports, keep harden optional |
| Disable MySQL/FTP baits | `mysql_addr: off` / `ftp_addr: off` in config |
| Fewer false blocks | Raise `active_defense.min_confidence` / deception `auto_block_score` |
| Brand CT focus | Edit `brands:` in `configs/config.yaml` |

## Rotation

- Rotate Cloudflare/AWS/AbuseIPDB keys on a schedule; update env, restart container
- Archive `data/caught/events.jsonl` monthly; keep dossiers needed for open cases
- After acquisition or personnel change, rotate `ATDE_MASTER_KEY` / `NATS_AUTH_TOKEN` if used

## Incident package

For law enforcement or hosting abuse, attach:

1. `dossier_<IP>.json`
2. Relevant lines from `events.jsonl`
3. Output of `atde -mode abuse -ip <IP>` (or `/v1/export/{ip}`)
4. Optional STIX: `atde -mode stix -ip <IP>`
5. `data/evidence/*-abuse-report.md` if a pipeline takedown was generated
6. Your authorization statement (you own the decoy host)

## Do not

- Point deception `upstream_url` at sensitive production apps without an allowlist
- Disable private-IP refusal
- Enable live third-party “poison” channels (they are intentionally simulation-only)
- Expose `:9091` to the public internet without `ATDE_OPS_TOKEN` and IP allowlisting
