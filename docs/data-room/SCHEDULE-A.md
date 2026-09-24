# Schedule A — Assigned Assets (ATDE 1.3)

**Incorporated into** [`TRANSFER.md`](TRANSFER.md) by reference.  
Buyer receives a named **1.3 platform** asset set, not an amorphous “repo.”

## A1. Software & schemas

| Asset | Location |
|-------|----------|
| All Go application source | `cmd/`, `internal/` (~9.5k+ LOC) |
| Entry binaries | `cmd/atde`, `cmd/ct-streamer`, `cmd/dispatcher` |
| Event / bus JSON Schemas | `schemas/` |
| Catch OpenAPI | `schemas/openapi-catch-v1.json` |
| JetStream subject contracts | `docs/contracts/BUS.md` |
| Configuration templates | `configs/`, `.env.example` |

## A2. Product surfaces (1.3 shipped)

| Surface | Evidence |
|---------|----------|
| Catch-node appliance (7 baits) | `deployments/catch-node.yml`, `docs/CATCH.md` |
| Atlas Control Plane honeypot | `internal/ingest/honeypot/` |
| SSH / Redis / Telnet / **MySQL** / **FTP** baits | same |
| Deception L7 | `internal/deception/` |
| Catch ledger + dossiers | `internal/catch/` |
| Abuse Markdown + STIX 2.1 export | `internal/catch/export_ext.go` |
| Operator console + REST + OpenAPI | `internal/ops/` (`:9091`) |
| Fingerprinting / severity | `internal/fingerprint/` |
| Local-first containment | `internal/disrupt/edge/` |
| Cloud immunize (CF / AWS) | `internal/immunize/` |
| Encrypted owner alerts | `internal/notify/` |
| Full NATS pipeline | `internal/natsbus/`, extract/enrich/publish/sinkhole |

## A3. Packaging & ops IP

| Asset | Location |
|-------|----------|
| Docker / Compose | `Dockerfile`, `deployments/` |
| Deploy / verify / demo / seed scripts | `scripts/` |
| CI / Dependabot / templates | `.github/` |
| ADRs (incl. 0006 — 1.3 line) | `docs/adr/` |
| Threat model | `docs/THREAT_MODEL.md` |
| Operator / deploy / release docs | `docs/CATCH.md`, `RELEASE.md`, … |

## A4. Brand & commercial narrative

| Asset | Location |
|-------|----------|
| Product name / goodwill **ATDE** | `docs/BRANDING.md` |
| Logo / wordmark / banner | `docs/assets/` |
| Acquisition brief + RELEASE 1.3 | `acquisition.md`, `RELEASE.md` |
| Valuation / SKU / competitive | `docs/VALUATION.md`, `SKU.md`, `COMPETITIVE.md` |
| Demo evidence pack | `docs/data-room/demo-evidence/` |

## A5. Diligence & transfer instruments

| Asset | Location |
|-------|----------|
| IP schedule | `docs/IP.md` |
| OSS inventory + notices | `OSS-INVENTORY.md`, `THIRD_PARTY_NOTICES.md` |
| CLA / DCO | `CLA.md`, `CONTRIBUTING.md` |
| This Schedule A + Transfer | `SCHEDULE-A.md`, `TRANSFER.md` |

## A6. Excluded (see Schedule B on TRANSFER.md)

API keys, `.env`, PGP **private** keys, production `data/caught/`, VPS/cloud accounts, registered trademarks (none filed), patents (none filed), third-party OSS licenses (continue in force).
