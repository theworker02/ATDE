# ATDE — Intellectual Property Schedule

**Status:** Diligence aid for acquisition / investment. Not a formal legal opinion.  
**Copyright holder (claimed):** `theworker02` (GitHub)  
**Primary license of this repository:** Apache License 2.0  
**Product name:** ATDE (Autonomous Threat Disruption Engine)  
**Module path:** `github.com/theworker02/blind-botnet`

---

## 1. Ownership representation (seller)

As of the date of this document, the sole author and claimed copyright owner of **original** ATDE source, documentation, schemas, brand assets, and ADRs in this repository is **theworker02**, unless a file header or `NOTICE` / third-party notice states otherwise.

| Assertion | Evidence |
|-----------|----------|
| Single-owner authorship | `AUTHORS`, `.github/CODEOWNERS` → `@theworker02` |
| License grant | Root `LICENSE` (Apache-2.0) + `NOTICE` |
| Contribution terms | `CONTRIBUTING.md` (DCO) + `docs/data-room/CLA.md` |
| No known encumbrances | No patent liens, no pledged collateral recorded in-repo |
| No registered TM/patent yet | See §4 — common-law mark use only |

**Buyer action at close:** sign the short form [`docs/data-room/TRANSFER.md`](data-room/TRANSFER.md) with [`SCHEDULE-A.md`](data-room/SCHEDULE-A.md) (see [`GETTING-THE-RIGHTS.md`](../GETTING-THE-RIGHTS.md)), then transfer the GitHub repository. Longer alternate: [`ASSIGNMENT-TEMPLATE.md`](data-room/ASSIGNMENT-TEMPLATE.md).

---

## 2. Asset inventory

### 2.1 Copyrightable works (in-repo)

| Category | Paths | Notes |
|----------|-------|-------|
| Application source | `cmd/`, `internal/` | Original Go |
| Event schemas | `schemas/` | JSON Schema contracts |
| Operator docs | `docs/`, `README.md`, `acquisition.md` | |
| Architecture decisions | `docs/adr/` | Doctrine / design IP |
| Brand artwork | `docs/assets/` | Logo, wordmark, banner |
| CI / packaging | `Dockerfile`, `deployments/`, `.github/` | |
| Scripts | `scripts/` | Deploy, SBOM, verify |

### 2.2 Trade secrets / confidential (not in public git)

| Item | Location | Handling |
|------|----------|----------|
| Production catch dossiers | operator `data/caught/` | gitignored; do not transfer without sanitization |
| API keys / SMTP / PGP private keys | operator `.env` / secrets | never committed |
| Customer lists / LOIs | *external* | not in this repo |
| Unpublished vulnerability research | *external* | disclose under NDA if any |

### 2.3 Third-party / OSS components

See [`docs/data-room/OSS-INVENTORY.md`](data-room/OSS-INVENTORY.md) and [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).  
All direct Go dependencies are **permissive** (Apache-2.0 / BSD / MIT family). **No known GPL/AGPL copyleft** in the direct dependency set.

### 2.4 Domains & accounts (*external — confirm at diligence*)

| Asset | Holder | Transfers? |
|-------|--------|------------|
| GitHub repo `theworker02/blind-botnet` | @theworker02 | Via GitHub ownership transfer |
| thanks.dev `u/gh/theworker02` | @theworker02 | Separate; see FUNDING.yml |
| Cloud accounts (CF/AWS) | Operator | **Not** transferred by this repo |
| Trademark registrations | None filed | Optional post-close filing |

---

## 3. Chain of title

1. Original authorship by theworker02 (2026).  
2. Public distribution under Apache-2.0 — outbound license to the public; **seller retains copyright** under Apache-2.0 until assignment.  
3. Future contributors: must agree to DCO (`CONTRIBUTING.md`) and, for material contributions, Individual CLA (`docs/data-room/CLA.md`).  
4. Acquisition close: copyright assignment from theworker02 → Buyer (and any CLA contributors if required).

---

## 4. Trademarks & branding

| Mark | Status | Notes |
|------|--------|-------|
| **ATDE** | Common-law use in commerce (docs, UI, NOTICE) | Recommend USPTO / equivalent filing post-close |
| **Autonomous Threat Disruption Engine** | Descriptive product phrase | |
| Historical dirname `blind-botnet` | **Not** a product mark — optics risk; rebrand in marketing | |

Brand usage: [`docs/BRANDING.md`](BRANDING.md). Logo files are part of the copyrighted work product.

---

## 5. Patents

| Item | Status |
|------|--------|
| Filed patents | **None** disclosed in this repository |
| Provisional / trade-secret algorithms | Local-first containment + deception doctrine documented in ADRs (copyright + know-how; not patent claims) |
| Apache-2.0 patent grant | Applies to contributions under the License §3 |

Buyer may independently file patents on novel methods; consult counsel. Prior public disclosure in this OSS repo may affect novelty.

---

## 6. Open-source compliance posture

| Control | Implementation |
|---------|------------------|
| License | Apache-2.0 |
| NOTICE propagation | Root `NOTICE` + `THIRD_PARTY_NOTICES.md` |
| SBOM | `make sbom` / `scripts/sbom.*` |
| Policy | Defensive-only (`docs/LEGAL.md`); no offensive third-party interference |
| SCA | Buyer should run independent SCA at diligence |

---

## 7. Representations suitable for a SPA schedule (*draft*)

Seller represents, to its knowledge:

1. Seller is the sole author of original ATDE code in this repository, or has obtained assignments/CLAs covering third-party contributions.  
2. The Work is offered under Apache-2.0; seller has not dual-licensed the Work under a conflicting proprietary exclusive grant that would prevent Apache-2.0 use.  
3. Seller has not intentionally inserted malicious code or GPL/AGPL copyleft into the primary application tree.  
4. No pending IP litigation concerning ATDE is known to seller.  
5. Cloud credentials and production catch data are **excluded** unless listed on a separate schedule.

*Counsel must adapt these for the actual purchase agreement.*

---

## 8. Related diligence docs

| Doc | Purpose |
|-----|---------|
| [`acquisition.md`](../acquisition.md) | Buyer brief |
| [`docs/VALUATION.md`](VALUATION.md) | Rebuild-cost thesis |
| [`docs/data-room/INDEX.md`](data-room/INDEX.md) | Data room map |
| [`docs/data-room/OSS-INVENTORY.md`](data-room/OSS-INVENTORY.md) | Dependency licenses |
| [`docs/data-room/CLA.md`](data-room/CLA.md) | Contributor license agreement |
| [`docs/data-room/ASSIGNMENT-TEMPLATE.md`](data-room/ASSIGNMENT-TEMPLATE.md) | Copyright assignment at close |
| [`docs/LEGAL.md`](LEGAL.md) | Acceptable use |
