# Configuration reference

Complete map of ATDE configuration surfaces. Prefer environment variables for secrets; YAML for structure.

## Files

| File | Role |
|------|------|
| `configs/config.yaml` | Default **live** operator profile |
| `configs/config.example.yaml` | Dry-run / lab template |
| `.env` / `.env.example` | Secrets and live toggles (never commit `.env`) |

Load path: `atde -config <path>` (default `configs/config.yaml`). YAML values are expanded with `os.ExpandEnv`.

## App

| Key | Env override | Default (live profile) | Description |
|-----|--------------|------------------------|-------------|
| `app.name` | — | `atde` | Process name in logs |
| `app.env` | — | `production` | `production` enables live cascade unless dry-run forced |
| `app.log_level` | — | `info` | `debug` / `info` / `warn` / `error` |
| `app.live` | `ATDE_LIVE=1` | `true` | Master live switch |
| `app.dry_run` | `ATDE_DRY_RUN=1` forces true dry-run | `false` | Simulation; overrides live |
| `app.ops_addr` | — | `:9091` | Health, metrics, console, catch API (`off` disables) |

When live: local firewall defaults **on**; subsystem `dry_run` flags cascade to `false`.

### Operator access (env)

| Env | Purpose |
|-----|---------|
| `ATDE_OPS_TOKEN` | Protects `/console` and `/v1/*` catch API (empty = open, lab only) |
| `ATDE_WEBHOOK_URL` | POST JSON on each catch ledger write |
| `ATDE_WEBHOOK_TOKEN` | Optional `Authorization: Bearer` for webhook |

## NATS

| Key | Env | Default |
|-----|-----|---------|
| `nats.url` | `NATS_URL` | `nats://127.0.0.1:4222` |

Requires JetStream (`-js`).

## Ingest

### CT (`ingest.ct`)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | CertStream consumer |
| `ws_url` | `wss://certstream.calidog.io/` | Public CT websocket |
| `workers` | `10` | Rule workers |
| `queue_size` | `5000` | Job buffer |

### Honeypot (`ingest.honeypot`)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | HTTP + protocol decoys |
| `http_addr` | `:8080` | HTTP Atlas honeypot bind |
| `ssh_addr` | `:2222` | SSH password-burn bind |
| `redis_addr` | `:6379` | Redis protocol bait (`off` disables) |
| `telnet_addr` | `:2323` | Telnet login bait (`off` disables) |
| `mysql_addr` | `:3306` | MySQL greeting/auth bait (`off` disables) — **1.3+** |
| `ftp_addr` | `:2121` | FTP login bait (`off` disables) — **1.3+** |

## Extract / Trace / Disrupt

| Key | Default | Description |
|-----|---------|-------------|
| `extract.work_dir` | `./data/sandbox` | Scratch for fetches |
| `extract.timeout` | `2m` | Fetch budget |
| `trace.eth_rpc` | public RPC | Optional wallet hop tracing |
| `trace.max_hops` | `3` | Trace depth |
| `disrupt.evidence_dir` | `./data/evidence` | Abuse Markdown output |
| `disrupt.min_confidence` | `0.7` | Enrich gate (honeypot artifacts score ≥ 0.9) |

## Active defense

| Key | Default | Description |
|-----|---------|-------------|
| `active_defense.enabled` | `true` | Disrupt controller |
| `active_defense.min_confidence` | `0.7` | Artifact gate for drop-IP blocks |
| `active_defense.tarpit.*` | enabled | Slow-byte HTTP/TCP |
| `active_defense.poison.enabled` | `true` | **Evidence simulation only** |
| `active_defense.edge.enabled` | `true` | Containment consumer |
| `active_defense.edge.local_firewall` | `true` (live) | OS blocks; `ATDE_LOCAL_FIREWALL=0` disables |
| `active_defense.edge.cloudflare_*` | env | Owned zone bans |
| `active_defense.edge.aws_waf_*` | env | Owned IPSet |

## Sinkhole / Publish / Deception / Harden

See `configs/config.yaml` comments and [ARCHITECTURE.md](ARCHITECTURE.md). Publish channels activate only when corresponding API keys are set.

## Environment secrets checklist

Copy from `.env.example`:

- Edge: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID`, `AWS_WAF_IPSET_ID`, `AWS_WAF_IPSET_NAME`, `AWS_REGION`, `WAF_BLOCK_WEBHOOK`
- Intel: `ABUSEIPDB_API_KEY`, `MISP_URL`, `MISP_API_KEY`, `GITHUB_TOKEN`, …
- Optional: `SIEM_WEBHOOK_URL`, `COREDNS_REWRITE_API`, `CF_GATEWAY_REWRITE_URL`, `ATDE_MASTER_KEY`, `NATS_AUTH_TOKEN`
- Operator UX: `ATDE_OPS_TOKEN`, `ATDE_WEBHOOK_URL`, `ATDE_WEBHOOK_TOKEN`
- Owner email alerts: `ATDE_ALERT_TO`, `ATDE_SMTP_*`, `ATDE_PGP_PUBLIC_KEY_FILE`, `ATDE_PGP_REQUIRE`, `ATDE_ALERT_COOLDOWN`, `ATDE_ALERT_BOOT`

## Modes relevant to ops (1.3)

| Mode | Purpose |
|------|---------|
| `catch-node` | Standalone bait + ledger (+ optional local bans) |
| `seed-demo` | Write sanitized multi-surface catch evidence for lab/diligence |
| `abuse` | Markdown abuse package for `-ip` |
| `stix` | STIX 2.1 JSON for `-ip` |
| `export` | Legacy Markdown export (same family as abuse) |
| `doctor` / `status` / `watch` | Preflight, summary, live tail |

See [OPERATOR.md](OPERATOR.md) and [CATCH.md](CATCH.md).
