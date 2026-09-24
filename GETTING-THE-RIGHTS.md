# How the acquirer gets the rights

**One instrument + Schedule A + one GitHub transfer.** That is the close for **ATDE 1.3** IP in this repository.

You are buying a **significant 1.3 platform asset** (seven-bait catch appliance + pipeline + operator stack + brand goodwill) — the paperwork stays short on purpose.

| Step | Action | Document |
|------|--------|----------|
| **0** | (Optional) See what you get | [`SCHEDULE-A.md`](docs/data-room/SCHEDULE-A.md) · [`SKU.md`](docs/SKU.md) · [`VALUATION.md`](docs/VALUATION.md) · [`RELEASE.md`](RELEASE.md) |
| **1** | Fill Buyer name / date / governing law | [`docs/data-room/TRANSFER.md`](docs/data-room/TRANSFER.md) |
| **2** | Seller + Buyer sign | same file (signature block) |
| **3** | Seller transfers GitHub repo to Buyer | GitHub → Settings → Transfer ownership |

That assigns Seller’s **copyright** in ATDE 1.3 (code, docs, schemas, brand assets — Schedule A) and the common-law **ATDE** name/goodwill.

### What you already have after signing

- Ownership of Seller’s copyright in this Work (full Schedule A inventory)  
- Right to commercialize day-1 SKUs (Catch Appliance 1.3 / Edge / Pipeline)  
- Right to rebrand, rename the module, dual-license **new** releases you control  
- Repo control after GitHub transfer  

### Proof without a live deploy

```bash
go run ./cmd/atde -mode seed-demo
go run ./cmd/atde -mode caught
```

Or open [`docs/data-room/demo-evidence/`](docs/data-room/demo-evidence/).

### What Apache-2.0 still means

Anyone who already obtained a copy under Apache-2.0 keeps that license for those copies. Your assignment does **not** need to “revoke the internet.”

### What is *not* in the repo transfer

Cloud keys, SMTP passwords, PGP **private** keys, live `data/caught/` dossiers, VPS instances — list keep-backs on Schedule B in `TRANSFER.md`.

### Seller identity (pre-filled)

- **Copyright holder / Assignor:** theworker02  
- **Evidence:** `AUTHORS`, `COPYRIGHT`, `NOTICE`, `.github/CODEOWNERS`  
- **Contact:** https://github.com/theworker02  

### Longer diligence

[`acquisition.md`](acquisition.md) · [`docs/IP.md`](docs/IP.md) · [`docs/data-room/INDEX.md`](docs/data-room/INDEX.md)

---

**Not legal advice.** Counsel may attach `TRANSFER.md` + Schedule A as exhibits to a broader asset purchase agreement.
