<p align="center">
  <img src="docs/assets/logo.svg" alt="ATDE logo" width="128" height="128" />
</p>

<h1 align="center">ATDE</h1>

<p align="center">
  <strong>Autonomous Threat Disruption Engine</strong><br/>
  Defensive honeypot · asymmetric deception · local-first containment<br/>
  for infrastructure <em>you own</em>
</p>

<p align="center">
  <a href="https://github.com/theworker02/ATDE/actions/workflows/ci.yml"><img src="https://github.com/theworker02/ATDE/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://pkg.go.dev/github.com/theworker02/ATDE/v2"><img src="https://pkg.go.dev/badge/github.com/theworker02/ATDE/v2.svg" alt="Go Reference" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" /></a>
  <a href="VERSION"><img src="https://img.shields.io/badge/version-2.0.2-2EC4B6.svg" alt="Version" /></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/go-1.24+-00ADD8.svg?logo=go&logoColor=white" alt="Go" /></a>
  <a href="deployments/docker-compose.yml"><img src="https://img.shields.io/badge/docker-compose-2496ED.svg?logo=docker&logoColor=white" alt="Docker" /></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-red.svg" alt="Security" /></a>
  <a href="docs/LEGAL.md"><img src="https://img.shields.io/badge/use-defensive%20only-0F1419.svg" alt="Defensive only" /></a>
  <a href=".github/FUNDING.yml"><img src="https://img.shields.io/badge/sponsor-theworker02-ea4aaa.svg?logo=github" alt="Sponsor" /></a>
</p>

<p align="center">
  <a href="docs/CATCH.md"><strong>Catch attackers (start here)</strong></a> ·
  <a href="https://pkg.go.dev/github.com/theworker02/ATDE/v2"><strong>pkg.go.dev</strong></a> ·
  <a href="RELEASE.md"><strong>Release 2.0</strong></a> ·
  <a href="docs/DEPLOY.md">Deploy</a> ·
  <a href="docs/OPERATOR.md">Operate</a> ·
  <a href="docs/ARCHITECTURE.md">Architecture</a> ·
  <a href="docs/CONFIGURATION.md">Configure</a> ·
  <a href="acquisition.md"><strong>Acquisition</strong></a> ·
  <a href="GETTING-THE-RIGHTS.md">Get the rights</a> ·
  <a href="docs/VALUATION.md">Valuation</a> ·
  <a href="docs/SKU.md">SKUs</a> ·
  <a href="docs/IP.md">IP</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="docs/LEGAL.md">Legal</a>
</p>

---

> **Product name:** ATDE &nbsp;|&nbsp; **Historical repo dirname:** `blind-botnet` (do not lead marketing with this name)  
> Brand assets: [`docs/BRANDING.md`](docs/BRANDING.md) · Wordmark: [`docs/assets/logo-wordmark.svg`](docs/assets/logo-wordmark.svg)

## Go module (pkg.go.dev)

**Docs:** [pkg.go.dev/github.com/theworker02/ATDE/v2](https://pkg.go.dev/github.com/theworker02/ATDE/v2)

```bash
go get github.com/theworker02/ATDE/v2@latest
```

Module path: `github.com/theworker02/ATDE/v2` (matches the GitHub repo [theworker02/ATDE](https://github.com/theworker02/ATDE)).

## What this is for

**Deploy ATDE 2.0 on a public VPS → ten decoys disrupt scanners with graduated policy → every attack is recorded, clustered, and exportable** under `data/caught/` (console `:9091/console`).

You do **not** need Cloudflare, AWS, or AbuseIPDB keys to catch and contain attackers locally. Those are optional escalations.

**One-page playbook:** **[docs/CATCH.md](docs/CATCH.md)** · **Release:** **[RELEASE.md](RELEASE.md)**

```bash
cp .env.example .env
docker compose -f deployments/catch-node.yml up -d --build
# bait: 8080,2222,6379,2323,3306,2121,2525,9200,27017,8443 — lock 9091
bash scripts/verify-catch.sh
# review: http://YOUR_IP:9091/console  ·  campaigns: /v1/campaigns
```

## Overview

ATDE is an event-driven **defensive** security appliance you run on hosts and edges under your control. It baits scanners on decoy surfaces, scores and dossiers every hit, then **contains locally first** (Linux `ipset` / iptables / nft, Windows `netsh`). Cloudflare, AWS WAFv2, AbuseIPDB, and related APIs are **optional best-effort escalations** — missing credentials or cloud failures never abort the catch pipeline.

```
┌──────────────┐     ┌─────────────────────┐     ┌──────────────────┐
│ 1. BAIT      │────▶│ 2. DOSSIER ENGINE   │────▶│ 3A. LOCAL FW     │
│ 7 surfaces   │     │ events.jsonl        │     │ ipset · netsh    │
│ HTTP··FTP··  │     │ dossier_<IP>.json   │     │ (mandatory path) │
└──────────────┘     └─────────────────────┘     └──────────────────┘
                                   │
                     ┌─────────────┼─────────────▶┌──────────────────┐
                     ▼             ▼              │ 3C. EXPORT       │
            ┌──────────────┐  ┌──────────┐        │ abuse · STIX     │
            │ 3B. NOTIFY   │  │ OpenAPI  │        │ OpenAPI catch API│
            │ PGP · webhook│  │ :9091    │        └──────────────────┘
            └──────────────┘  └──────────┘
                                   │
                                   └────────────▶┌──────────────────┐
                                                 │ 3D. CLOUD/ABUSE  │
                                                 │ CF · AWS · TIP   │
                                                 │ (best-effort)    │
                                                 └──────────────────┘
```

**Seven bait surfaces:** Atlas HTTP · SSH · Redis · Telnet · MySQL · FTP · deception L7.  
Backed by **NATS JetStream** (`THREAT_PIPELINE`) with typed subjects under `threat.v1.*`.

## What's included

### Runtime & packaging

| Item | Path | Description |
|------|------|-------------|
| All-in-one binary | `cmd/atde` | Modes: `all`, `catch-node`, `honeypot`, `caught`, `doctor`, `dossier`, `export`, `abuse`, `stix`, `seed-demo`, `watch`, `status`, … |

| CT / dispatcher entrypoints | `cmd/ct-streamer`, `cmd/dispatcher` | Split-process blueprint |
| Docker image | `Dockerfile` | Distroless-friendly Go build + `iptables`/`ipset` |
| Compose stack | `deployments/docker-compose.yml` | NATS JetStream + ATDE catcher |
| Live config | `configs/config.yaml` | Production defaults (`live: true`) |
| Lab config | `configs/config.example.yaml` | Dry-run template |
| Env template | `.env.example` | Secrets checklist |
| Event schemas | `schemas/*.json` | JSON Schema drafts for the bus |
| Makefile | `Makefile` | `build`, `test`, `up`, `caught`, `release` |
| Version stamp | `VERSION` | Semver `2.0.2` (`atde -version`) |

### Core Go packages

| Package | Responsibility |
|---------|----------------|
| `internal/natsbus` | JetStream connect, publish, durable consumers, DLQ |
| `internal/ingest/ct` | CertStream + brand RuleEngine |
| `internal/ingest/honeypot` | Atlas Control Plane HTTP portal + SSH/Redis/Telnet/MySQL/FTP baits |

| `internal/ingest/rules` | Phishing / brand heuristics |
| `internal/extract` | Artifact + IoC isolation |
| `internal/enrich` | Infra map → takedown / sinkhole / publish events |
| `internal/catch` | Audit ledger + rolling dossiers |
| `internal/disrupt/active` | Phase-4 controller |
| `internal/disrupt/edge` | **Local-first** `EnforceContainment` + ipset/netsh |
| `internal/disrupt/tarpit` | Slow-byte protocol starvation |
| `internal/disrupt/poison` | Evidence-only exfil simulation |
| `internal/disrupt/dispatcher` | Abuse Markdown + provider posts |
| `internal/immunize` | Cloudflare + AWS WAFv2 adapters |
| `internal/deception` | Asymmetric L7 honey-interface |
| `internal/sinkhole` | Owned DNS rewrite orchestration |
| `internal/publish` | STIX 2.1 + community intel channels |
| `internal/harden` | Optional anti-analysis / seccomp |
| `internal/config` | YAML + live cascade + secret hydration |

### Documentation & governance

| Document | Audience |
|----------|----------|
| [RELEASE.md](RELEASE.md) | 2.0.0 threat disruption release notes |
| [acquisition.md](acquisition.md) | Buyers / diligence |
| [docs/IP.md](docs/IP.md) | Intellectual property schedule |
| [docs/data-room/INDEX.md](docs/data-room/INDEX.md) | Virtual data room |
| [docs/CATCH.md](docs/CATCH.md) | Deploy bait → record attacks |
| [docs/DEPLOY.md](docs/DEPLOY.md) | First install & verify |
| [docs/OPERATOR.md](docs/OPERATOR.md) | Day-2 operations |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Engineers |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Full config map |
| [docs/HONEYPOT.md](docs/HONEYPOT.md) | Atlas portal / SSH burn / demo |
| [docs/VALUATION.md](docs/VALUATION.md) | Pre-revenue rebuild thesis |
| [docs/BRANDING.md](docs/BRANDING.md) | Logo & trademarks |
| [docs/LEGAL.md](docs/LEGAL.md) | Acceptable use |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure |
| [CHANGELOG.md](CHANGELOG.md) | Releases (Keep a Changelog) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | DCO / contribution rules |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community norms |
| [LICENSE](LICENSE) / [NOTICE](NOTICE) / [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Apache-2.0 + attribution |
| [AUTHORS](AUTHORS) / [COPYRIGHT](COPYRIGHT) | Copyright holders |
| [CITATION.cff](CITATION.cff) | Academic citation |
| `.github/workflows/ci.yml` | Test + build badges |
| `.github/ISSUE_TEMPLATE/*` | Bug / feature forms |
| `.github/FUNDING.yml` | Sponsors + thanks.dev |

### Catch artifacts (runtime)

| Artifact | Location |
|----------|----------|
| Append-only audit log | `data/caught/events.jsonl` |
| Per-IP rolling dossier | `data/caught/dossier_<IP>.json` |
| Daily shards | `data/caught/caught-YYYY-MM-DD.jsonl` |
| Abuse packages | `data/evidence/*-abuse-report.md` |

## Features

- **Local-first containment** — OS block is the guaranteed path; cloud is async and fail-soft  
- **High-scale Linux bans** — `ipset` hash set (`atde_honeypot_bans`, 24h TTL) + one iptables match-set rule  
- **Safe exec** — firewall binaries via argv `exec.CommandContext` (no shell)  
- **Private IP refusal** — loopback / RFC1918 / TEST-NET never OS-blocked  
- **Seven-surface decoy mesh** — Atlas (`:8080`), SSH (`:2222`), Redis (`:6379`), Telnet (`:2323`), MySQL (`:3306`), FTP (`:2121`), deception (`:8443`)  
- **CT monitoring** — brand-aware certificate transparency streaming  
- **Intel packaging** — STIX 2.1 + abuse Markdown (CLI + catch API); AbuseIPDB / MISP / Mastodon / Gist when keyed  
- **Owned-edge immunize** — Cloudflare Access Rules + AWS WAFv2 IPSet  
- **Operator CLI** — `caught` / `dossier` / `export` / `abuse` / `stix` / `seed-demo` / `watch` / `doctor` / `status`  
- **Operator console** — read-only UI at `:9091/console` + catch REST API + **OpenAPI** at `:9091/v1/openapi.json`  
- **Catch webhooks** — optional `ATDE_WEBHOOK_URL` on every ledger write  
- **Encrypted owner email** — SMTP + OpenPGP alerts when attackers are recorded  

## Quick start

### Option A — One-shot quickstart

```powershell
.\scripts\quickstart.ps1
# then:
.\bin\atde.exe -config configs\config.yaml -mode all
# console: http://127.0.0.1:9091/console
```

```bash
bash scripts/quickstart.sh
./bin/atde -config configs/config.yaml -mode all
```

### Option B — Docker Compose (recommended)

```bash
git clone https://github.com/theworker02/ATDE.git
cd ATDE
cp .env.example .env

docker compose -f deployments/docker-compose.yml up -d --build

# Probe decoys locally
curl -sS http://127.0.0.1:8080/wp-login.php
curl -sS "http://127.0.0.1:8443/api/v1/debug?cmd=id"

# Review ledger (from host with ./data mounted)
go run ./cmd/atde -mode caught
```

Expose TCP **8080**, **2222**, **6379**, **2323**, **3306**, **2121**, and **8443** on a public IP (or port-forward) to collect internet scanners. The `:8080` portal looks like a real ops gateway — see **[docs/HONEYPOT.md](docs/HONEYPOT.md)**.

### Option C — Local binary

```bash
docker compose -f deployments/docker-compose.yml up -d nats
cp .env.example .env
go mod tidy
go test ./...
make build

# PowerShell
$env:NATS_URL = "nats://127.0.0.1:4222"
$env:ATDE_LIVE = "1"
.\bin\atde.exe -config configs\config.yaml -mode all
```

```bash
# bash
export NATS_URL=nats://127.0.0.1:4222 ATDE_LIVE=1
./bin/atde -config configs/config.yaml -mode all
```

### Verify

| Check | Command |
|-------|---------|
| Version | `atde -version` → `2.0.0` |
| Doctor | `atde -mode doctor` |
| Console | `http://HOST:9091/console` |
| OpenAPI | `http://HOST:9091/v1/openapi.json` |
| Honeypot | `curl http://HOST:8080/` · `.\scripts\demo-honeypot.ps1` |
| Metrics | `curl http://HOST:9091/metrics` |
| Deception | `curl "http://HOST:8443/.env"` |
| Ledger | `atde -mode caught` · `atde -mode abuse -ip <IP>` · `atde -mode stix -ip <IP>` |
| Seed demo | `atde -mode seed-demo` |
| NATS | `http://127.0.0.1:8222/healthz` |

Full install guide: **[docs/DEPLOY.md](docs/DEPLOY.md)**.

## Detailed operating instructions

### 1. Choose a profile

| Profile | How | When |
|---------|-----|------|
| **Live catcher** | `configs/config.yaml` + `ATDE_LIVE=1` | Internet-facing decoy node |
| **Lab / CI** | `ATDE_DRY_RUN=1` or `config.example.yaml` | No OS blocks / no live API posts |
| **Local FW only** | Live + no cloud env vars | Contain without Cloudflare/AWS |
| **Cloud escalated** | Live + CF/AWS/Abuse keys | Owned accounts only |

Disable OS blocks anytime: `ATDE_LOCAL_FIREWALL=0`.

### 2. Run modes

| Mode | Starts | Use |
|------|--------|-----|
| `all` | Full mesh (default container entrypoint) | Production catcher |
| `honeypot` / `tarpit` | Decoys + extract + active | Lightweight bait node |
| `deception` | L7 honey-interface + active | App-edge deception |
| `ct` | Certificate Transparency only | Passive monitor |
| `extract` / `enrich` / `dispatch` | Pipeline stages | Horizontal scale |
| `active` | Containment consumer | Edge worker |
| `sinkhole` / `publish` | DNS rewrite / intel | Optional stages |
| `caught` | Ledger printer | Ops review |
| `version` | Semver | Releases / CI |

### 3. What happens on a hit

1. Decoy records telemetry → `data/caught/events.jsonl` + upserts `dossier_<IP>.json`  
2. Event published on `threat.v1.raw.honeypot` (confidence **0.9+**)  
3. Active defense emits `threat.v1.action.disrupt`  
4. `EnforceContainment` applies **local** block, then best-effort cloud bans  
5. Enrich may queue abuse packages / AbuseIPDB when keys exist  

### 4. Secrets (owned accounts only)

| Variable | Effect |
|----------|--------|
| `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ZONE_ID` | Zone Access Rule blocks |
| `AWS_WAF_IPSET_ID` + `AWS_WAF_IPSET_NAME` | WAFv2 IPSet updates |
| `ABUSEIPDB_API_KEY` | Live IP reports |
| `SIEM_WEBHOOK_URL` | Attack event fan-out |
| `COREDNS_REWRITE_API` / `CF_GATEWAY_REWRITE_URL` | Owned DNS sinkhole |

Complete map: **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**.

### 5. Day-2

See **[docs/OPERATOR.md](docs/OPERATOR.md)** for rotation, incident packages, and tuning.

## Architecture

Event bus subjects and trust boundaries: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

| Subject | Purpose |
|---------|---------|
| `threat.v1.raw.ct` | Suspicious CT domains |
| `threat.v1.raw.honeypot` | Honeypot / deception captures |
| `threat.v1.artifact.extracted` | Isolated IoCs |
| `threat.v1.artifact.attack` | Deception attack events |
| `threat.v1.action.takedown` | Abuse packages |
| `threat.v1.action.disrupt` | Containment |
| `threat.v1.action.sinkhole` | Owned DNS rewrites |
| `threat.v1.action.publish` | STIX / community intel |
| `threat.v1.action.dlq` | Dead-letter |

## Explicit non-goals

| Not implemented | Why |
|-----------------|-----|
| Live Telegram / Discord floods with stolen tokens | Unauthorized access; evidence simulation only |
| Live Mirai/Hajime (etc.) DHT peer injection | Third-party network interference |
| OS blocks of private / loopback / TEST-NET | Operator safety |

Catching attackers does **not** depend on those features. See **[docs/LEGAL.md](docs/LEGAL.md)**.

## Development

```bash
go test ./...
make build
make caught
```

CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (vet, test, build artifact).  
Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

## Acquisition

Diligence packet: **[acquisition.md](acquisition.md)** · **Release:** **[RELEASE.md](RELEASE.md)** · **Take the rights:** **[GETTING-THE-RIGHTS.md](GETTING-THE-RIGHTS.md)** · IP: **[docs/IP.md](docs/IP.md)** · Data room: **[docs/data-room/INDEX.md](docs/data-room/INDEX.md)**.

## Support & funding

- GitHub Sponsors: [`theworker02`](https://github.com/sponsors/theworker02)  
- thanks.dev: [`u/gh/theworker02`](https://thanks.dev/u/gh/theworker02)  
- Security reports: [SECURITY.md](SECURITY.md)

## License

Copyright 2026 theworker02. Licensed under the [Apache License 2.0](LICENSE).
