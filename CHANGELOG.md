# Changelog

All notable changes to ATDE (Autonomous Threat Disruption Engine) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Postgres fleet ledger
- Terraform / signed release attestations

## [2.0.1] — 2026-09-24

### Changed

- Go module path set to `github.com/theworker02/blind-botnet/v2` (required for semver major ≥ 2)
- README links to [pkg.go.dev](https://pkg.go.dev/github.com/theworker02/blind-botnet/v2)

## [2.0.0] — 2026-09-24

### Added

- **Graduated threat policy engine** (`internal/policy`) — observe → tarpit → local ban → cloud → abuse pack
- **Campaign correlator** (`internal/campaign`) + `GET /v1/campaigns`
- **MITRE ATT&CK** technique tagging on every fingerprint
- **SIEM/TIP exports:** ECS JSONL, CEF, MISP (`/v1/ecs|cef|misp/{ip}`)
- **Fleet ban sync** for owned catch-nodes (`internal/fleet`, `/v1/fleet/bans`)
- Protocol baits: **SMTP :2525**, **Elasticsearch :9200**, **MongoDB :27017** (10-surface mesh)
- Console / capabilities / status branded as **ATDE 2.0** disruption platform
- Dossier fields: `techniques`, `campaign_ids`, `policy_tier`

### Changed

- Semver advanced to **2.0.0** (major: policy + fleet + multi-export disruption platform)
- Catch-node Compose publishes 2525 / 9200 / 27017

## [1.3.0] — 2026-09-24

### Added

- **MySQL greeting bait** (`:3306`) and **FTP login bait** (`:2121`) on catch-node
- Catch **STIX 2.1** export (`-mode stix`, `GET /v1/stix/{ip}`)
- **Abuse bundle** CLI (`-mode abuse`) — Markdown + STIX under `data/evidence/`
- Thickened abuse Markdown (timeline table, recipient actions, ATDE 1.3 header)
- **OpenAPI** catch surface (`GET /v1/openapi.json`) + **capabilities** map
- **`seed-demo`** mode to load `docs/data-room/demo-evidence/events.jsonl`
- `/v1/status` product line / bait list; Prometheus `atde_info` labels
- Console 1.3 branding + STIX download action
- `RELEASE.md`, ADR 0006 (platform 1.3 line), thickened acquisition/valuation/SKU/CATCH docs
- Demo evidence extended for MySQL/FTP hits

### Changed

- Semver line advanced to **1.3.0** (stable 1.x product)
- Rebuild-cost thesis updated for 1.3 surface area
- Catch-node Compose publishes 3306 + 2121

## [1.2.0] — 2026-09-24

### Added

- Catch-node Redis / Telnet baits, scanner fingerprinting, local block-on-hit
- Encrypted owner email (SMTP + OpenPGP), boot “armed” notice, per-IP cooldown
- Live console v2, CATCH playbook, verify/deploy scripts
- Acquisition significance pack (Schedule A, SKUs, valuation bands, demo evidence)
- Short-form rights transfer (`GETTING-THE-RIGHTS.md`, `TRANSFER.md`)

## [1.1.0] — 2026-09-24

### Added

- Operator console on `:9091/console`
- Catch REST API (`/v1/caught`, `/v1/dossiers`, `/v1/export/{ip}`, `/v1/summary`)
- CLI: `doctor`, `status`, `dossier`, `export`, `watch`
- Optional catch webhook (`ATDE_WEBHOOK_URL`)
- Quickstart scripts and Makefile operator targets

## [1.0.0] — 2026-09-24

### Added

- GA foundation: Trap → Extract → Trace → Disrupt on NATS JetStream
- Atlas Control Plane honeypot + SSH password-burn + deception L7
- Catch ledger (`events.jsonl` + dossiers)
- Local-first containment (Linux ipset / Windows netsh) + fail-soft CF/AWS
- CT streamer + RuleEngine, STIX/Markdown publisher, sinkhole / harden
- Acquisition brief, LEGAL, threat model, ADRs, CI, Apache-2.0

## [0.2.0] / [0.1.0] — superseded

Pre-1.0 packaging snapshots; all capabilities rolled into 1.0–1.3 above.
