# Pre-revenue valuation thesis

**Status:** Diligence aid for acquirers evaluating **ATDE 1.3** as a significant pre-revenue defensive security asset.  
**Not a formal appraisal.** Numbers are engineering reconstruction estimates converted to indicative consideration bands.

## Why 1.3 is a significant asset

| Significance signal | Evidence |
|---------------------|----------|
| Stable product line | Semver **1.3.0** · ADR 0006 · `RELEASE.md` |
| Scale | ~9.5k+ lines of Go + schemas + Compose + CI; full test suite |
| Surfaces | **Seven** baits — HTTP Atlas, SSH, Redis, Telnet, MySQL, FTP, deception |
| Interop | OpenAPI catch API · STIX 2.1 · Prometheus · SIEM webhook · PGP email |
| Doctrine | Local-first / fail-soft encoded in code + ADRs |
| Close readiness | Schedule A + short-form assignment + demo evidence + seed-demo |
| Commercial shape | Day-1 SKUs in [`SKU.md`](SKU.md) |

## Reconstruction effort (1.3 scope)

Assumes a competent Go platform team (2 seniors + 1 security engineer), **not** including GTM or trademark filings.

| Workstream | Est. rebuild (person-weeks) |
|------------|-----------------------------|
| JetStream bus + schemas + DLQ | 3–5 |
| CT ingest + RuleEngine | 4–6 |
| Seven-surface bait mesh + Atlas portal + fingerprint | 12–18 |
| Extract / enrich / STIX publish | 5–8 |
| Local-first edge + CF/AWS | 4–7 |
| Catch ledger + console + OpenAPI + abuse/STIX + PGP | 7–10 |
| Sinkhole / dispatcher / harden | 3–5 |
| Packaging + CI | 2–3 |
| Docs / legal / ADRs / acquisition / IP / SKU | 5–7 |
| Tests / benchmarks / ops metrics | 3–5 |
| **Total (engineering only)** | **≈ 48–75 person-weeks** |
| **Calendar (3 FTE)** | **≈ 5–9 months** |
| **Calendar (1–2 FTE)** | **≈ 10–18 months** |

## Indicative consideration bands (engineering-value floor)

| Rate assumption | Low (48 pw) | Mid (~62 pw) | High (75 pw) |
|-----------------|-------------|--------------|--------------|
| ≈ $4,000 / pw | ~$190k | ~$250k | ~$300k |
| ≈ $5,500 / pw | ~$265k | ~$340k | ~$415k |
| ≈ $7,000 / pw | ~$335k | ~$435k | ~$525k |

**Buyer takeaway:** Six-figure engineering asset with day-1 SKUs and a one-page IP close. Price on avoided rebuild calendar + legal/design mistakes + platform optionality — not ARR (none claimed).

## Moat characteristics

Integration + process + compliance + time + brand seed + close packaging — see acquisition brief.

## Diligence order

1. [`RELEASE.md`](../RELEASE.md) + this file + [`SKU.md`](SKU.md)  
2. [`demo-evidence/`](data-room/demo-evidence/) or `atde -mode seed-demo`  
3. Threat model · ADRs · BUS contracts · live verify  
4. Sign [`TRANSFER.md`](data-room/TRANSFER.md)
