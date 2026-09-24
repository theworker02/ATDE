# Virtual data room index

Curated diligence map for **acquisition / investment / IP transfer**. All paths are in-repo unless marked *external*.

**Start here for ownership transfer:** [`GETTING-THE-RIGHTS.md`](../../GETTING-THE-RIGHTS.md) → sign [`TRANSFER.md`](TRANSFER.md)

**Start here for product diligence:** [`acquisition.md`](../../acquisition.md) → [`docs/IP.md`](../IP.md)

---

## A. Corporate & product

| ID | Artifact | Path |
|----|----------|------|
| A1 | Acquisition brief | [`acquisition.md`](../../acquisition.md) |
| A2 | Pre-revenue valuation thesis | [`docs/VALUATION.md`](../VALUATION.md) |
| A3 | Competitive positioning | [`docs/COMPETITIVE.md`](../COMPETITIVE.md) |
| A3b | Commercial SKU map | [`docs/SKU.md`](../SKU.md) |
| A4 | Product roadmap | [`docs/ROADMAP.md`](../ROADMAP.md) |
| A5 | Changelog | [`CHANGELOG.md`](../../CHANGELOG.md) |
| A5b | **Release notes (1.3.0)** | [`RELEASE.md`](../../RELEASE.md) |
| A6 | Brand kit | [`docs/BRANDING.md`](../BRANDING.md), [`docs/assets/`](../assets/) |
| A7 | ADRs | [`docs/adr/`](../adr/) (incl. ADR-0006) |
| A8 | Threat model | [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) |
| A9 | Catch playbook | [`docs/CATCH.md`](../CATCH.md) |

## B. Legal, IP & security

| ID | Artifact | Path |
|----|----------|------|
| B1 | License | [`LICENSE`](../../LICENSE) |
| B2 | NOTICE / third-party | [`NOTICE`](../../NOTICE), [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) |
| B3 | Copyright / AUTHORS | [`COPYRIGHT`](../../COPYRIGHT), [`AUTHORS`](../../AUTHORS) |
| B4 | **IP schedule** | [`docs/IP.md`](../IP.md) |
| B5 | OSS inventory | [`OSS-INVENTORY.md`](OSS-INVENTORY.md) |
| B6 | Individual CLA | [`CLA.md`](CLA.md) |
| B7 | **Sign this to transfer rights** | [`TRANSFER.md`](TRANSFER.md) |
| B7a | **Schedule A — assigned assets** | [`SCHEDULE-A.md`](SCHEDULE-A.md) |
| B7b | Longer assignment alternate | [`ASSIGNMENT-TEMPLATE.md`](ASSIGNMENT-TEMPLATE.md) |
| B7c | SPA disclosure schedule map | [`DISCLOSURE-SCHEDULE.md`](DISCLOSURE-SCHEDULE.md) |
| B7d | How-to for acquirer | [`GETTING-THE-RIGHTS.md`](../../GETTING-THE-RIGHTS.md) |
| B8 | Acceptable use | [`docs/LEGAL.md`](../LEGAL.md) |
| B9 | Security policy | [`SECURITY.md`](../../SECURITY.md) |
| B10 | Code of conduct | [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md) |
| B11 | Contributing / DCO | [`CONTRIBUTING.md`](../../CONTRIBUTING.md) |

## C. Technical IP

| ID | Artifact | Path |
|----|----------|------|
| C1 | Architecture | [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) |
| C2 | ADRs | [`docs/adr/`](../adr/) |
| C3 | Bus contracts | [`docs/contracts/BUS.md`](../contracts/BUS.md) |
| C4 | JSON schemas | [`schemas/`](../../schemas/) |
| C5 | Configuration reference | [`docs/CONFIGURATION.md`](../CONFIGURATION.md) |
| C6 | Source tree | `cmd/`, `internal/` |
| C7 | Honeypot / bait design | [`docs/HONEYPOT.md`](../HONEYPOT.md) |
| C8 | **Catch OpenAPI schema** | [`schemas/openapi-catch-v1.json`](../../schemas/openapi-catch-v1.json) · live `GET /v1/openapi.json` |

## D. Operations

| ID | Artifact | Path |
|----|----------|------|
| D1 | Catch deploy playbook | [`docs/CATCH.md`](../CATCH.md) |
| D2 | Deploy guide | [`docs/DEPLOY.md`](../DEPLOY.md) |
| D3 | Operator handbook | [`docs/OPERATOR.md`](../OPERATOR.md) |
| D4 | Catch-node Compose | [`deployments/catch-node.yml`](../../deployments/catch-node.yml) |
| D5 | Full mesh Compose | [`deployments/docker-compose.yml`](../../deployments/docker-compose.yml) |
| D6 | CI | [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) |
| D7 | SBOM | [`scripts/sbom.sh`](../../scripts/sbom.sh) / `make sbom` |
| D8 | Verify catch | [`scripts/verify-catch.sh`](../../scripts/verify-catch.sh) |

## E. Demo evidence (in-repo + live)

| ID | Artifact / how |
|----|----------------|
| E0 | **Sanitized pack (committed)** [`demo-evidence/`](demo-evidence/) |
| E1 | `bash scripts/deploy-catch-node.sh` |
| E2 | `bash scripts/verify-catch.sh` → attach console screenshot |
| E3 | Live sanitized `events.jsonl` / `dossier_*.json` (redact if needed) |
| E4 | `go test ./...` + CI green |
| E5 | `make sbom` → attach `dist/sbom-lite.txt` |
| E6 | Sample encrypted alert (optional): configure SMTP+PGP in lab |

---

*Do not commit real production dossiers, API keys, SMTP passwords, or PGP private keys.*
