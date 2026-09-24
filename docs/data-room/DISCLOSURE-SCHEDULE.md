# Suggested SPA disclosure schedules (draft)

Map these schedules in the purchase agreement. Paths are in-repo starting points.

| Schedule | Contents | Source |
|----------|----------|--------|
| **IP Assets** | Copyrighted works, brand assets, schemas, docs | [`docs/IP.md`](../IP.md) §2 |
| **Open Source** | Direct/indirect deps + licenses | [`OSS-INVENTORY.md`](OSS-INVENTORY.md), `THIRD_PARTY_NOTICES.md`, `make sbom` |
| **Excluded Assets** | Keys, cloud accounts, production dossiers, personal domains | [`docs/IP.md`](../IP.md) §2.2–2.4 |
| **Contracts** | None in-repo (no customer MSAs yet) | N/A — disclose *external* |
| **Litigation** | None known to seller | Seller representation |
| **Employees / contractors** | Sole author `theworker02` unless CLA list grows | `AUTHORS` |
| **Domains / accounts** | GitHub repo, thanks.dev | *External transfer checklist* |
| **Trademarks** | Common-law ATDE only; no registration | [`docs/BRANDING.md`](../BRANDING.md) |
| **Patents** | None filed | [`docs/IP.md`](../IP.md) §5 |

## Closing checklist (seller)

- [ ] Execute short-form transfer ([`TRANSFER.md`](TRANSFER.md)) with [`SCHEDULE-A.md`](SCHEDULE-A.md) — see [`GETTING-THE-RIGHTS.md`](../../GETTING-THE-RIGHTS.md)
- [ ] Transfer GitHub repository ownership
- [ ] Deliver sanitized demo evidence (E1–E6 in [`INDEX.md`](INDEX.md))
- [ ] Confirm no secrets in git history (`git log -p -- .env` empty)
- [ ] Hand off FUNDING.yml / sponsors only if negotiated
- [ ] Buyer independent SCA + counsel review of Apache-2.0 outbound

## Closing checklist (buyer)

- [ ] File / search **ATDE** trademark in target jurisdictions
- [ ] Decide module rename (`github.com/<buyer>/atde`)
- [ ] Re-issue CODEOWNERS / CI secrets under buyer org
- [ ] Rotate any shared diligence credentials
- [ ] Optional: dual-license policy for future proprietary SKUs
