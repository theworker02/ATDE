# ATDE — Acquisition Brief

**Product:** Autonomous Threat Disruption Engine (ATDE)  
**Codename / repo:** `blind-botnet` (historical; **product name is ATDE**)  
**Version:** **2.0.0**  
**Classification:** Defensive cybersecurity **threat disruption platform** — ten-surface bait mesh, graduated policy, campaigns, SIEM/TIP export, fleet ban sync, owner alerting  
**Owner / seller contact:** GitHub [`@theworker02`](https://github.com/theworker02) · [thanks.dev/u/gh/theworker02](https://thanks.dev/u/gh/theworker02)  

**Release notes:** [`RELEASE.md`](RELEASE.md)  
**Why this is significant:** Full disruption stack on owned edge — **10 baits** · policy engine · ATT&CK · campaigns · STIX/ECS/CEF/MISP · fleet sync · PGP alerts · one-page IP close  
**IP schedule:** [`docs/IP.md`](docs/IP.md) · **Data room:** [`docs/data-room/INDEX.md`](docs/data-room/INDEX.md) · **Valuation:** [`docs/VALUATION.md`](docs/VALUATION.md) · **SKUs:** [`docs/SKU.md`](docs/SKU.md)

### Acquirer: get the rights in three steps → **[`GETTING-THE-RIGHTS.md`](GETTING-THE-RIGHTS.md)**  
Sign: **[`docs/data-room/TRANSFER.md`](docs/data-room/TRANSFER.md)** (+ Schedule A) · then transfer the GitHub repo.

---

## 1. Executive summary

ATDE **2.0** is the **most complete owned-edge threat disruption system** in this product line:

1. Deploy on a VPS you own (`catch-node`)  
2. Internet scanners hit **ten** decoys (HTTP / SSH / Redis / Telnet / MySQL / FTP / **SMTP** / **Elasticsearch** / **MongoDB** / deception)  
3. Hits are fingerprinted with **MITRE ATT&CK**, scored, and **campaign-clustered**  
4. **Policy engine** escalates: observe → tarpit → local ban → cloud → abuse pack  
5. Export **Abuse MD · STIX · ECS · CEF · MISP**; sync bans across **owned fleet** nodes  
6. Owner receives **encrypted email** (OpenPGP)  

| Value for acquirer | Detail |
|--------------------|--------|
| Working 1.3 platform | Go monorepo + Docker catch-node; records attacks with **zero** cloud keys |
| Day-1 SKUs | Catch Appliance · Edge Containment · Threat Pipeline ([`docs/SKU.md`](docs/SKU.md)) |
| Interop | OpenAPI catch API · STIX 2.1 · Prometheus metrics · SIEM webhook |
| Clear legal boundary | No hacking-back; no stolen-token floods; no third-party DHT attacks |
| Operator-ready | CATCH playbook, doctor/status/seed-demo/abuse CLI, console, verify scripts |
| Transferable IP | Apache-2.0 + **Schedule A** + short-form assignment |
| Proof in the packet | Sanitized demo dossiers + `seed-demo` ([`demo-evidence/`](docs/data-room/demo-evidence/)) |

**One-line pitch:** *ATDE 1.3 — a transferable deception + containment platform with seven baits, STIX/abuse export, and a one-page IP close.*

### Pre-revenue value (rebuild cost)

Independent reconstruction estimated at **≈ 48–75 person-weeks** (~**$190k–$525k** engineering-value floor at illustrative loaded rates). Thesis: [`docs/VALUATION.md`](docs/VALUATION.md).

---

## 2. What transfers

| Asset | Location | Notes |
|-------|----------|--------|
| **Schedule A (full list)** | [`docs/data-room/SCHEDULE-A.md`](docs/data-room/SCHEDULE-A.md) | Named assets in the close |
| Source code | Entire repository | Module `github.com/theworker02/blind-botnet/v2` |
| Copyright | `AUTHORS`, `COPYRIGHT`, `NOTICE` | Sign [`TRANSFER.md`](docs/data-room/TRANSFER.md) |
| Event schemas + Catch OpenAPI | `schemas/` | Bus + `openapi-catch-v1.json` |
| Catch-node packaging | `deployments/catch-node.yml`, `Dockerfile` | Seven public baits |
| Full mesh packaging | `deployments/docker-compose.yml` | NATS + full pipeline |
| Documentation | `docs/`, `RELEASE.md`, `acquisition.md` | Including CATCH / IP / LEGAL / SKU |
| Brand kit | `docs/assets/`, `docs/BRANDING.md` | **ATDE** common-law mark |
| Demo evidence | `docs/data-room/demo-evidence/` | Sanitized catch proof |
| CI / governance | `.github/` | CODEOWNERS → `@theworker02` |

**Does not transfer unless scheduled:** cloud accounts, API keys, SMTP credentials, PGP **private** keys, production `data/caught/` dossiers, VPS instances, registered trademarks (none filed yet).

**Apache-2.0 caveat:** prior public copies retain Apache-2.0; assignment gives Buyer ownership of Seller’s copyright for future Buyer-controlled commercialization (counsel for dual-license).

---

## 3. Product capabilities (1.3 shipped)

### 3.1 Catch-node

| Surface | Port | Function |
|---------|------|----------|
| Atlas Control Plane | 8080 | Impossible-auth fake ops portal + vuln bait |
| SSH password-burn | 2222 | Credential capture, always deny |
| Redis bait | 6379 | Protocol + exploit-cmd logging |
| Telnet bait | 2323 | IoT-style login burn |
| **MySQL bait** | **3306** | Greeting + auth deny (1.3) |
| **FTP bait** | **2121** | Login burn (1.3) |
| Deception API | 8443 | Synthetic vuln responses |
| Operator console | 9091 | Live dossiers / STIX / export (**lock down**) |

### 3.2 Export & notify

- Abuse Markdown + STIX 2.1 (`-mode abuse` / `-mode stix` / REST)  
- SMTP + OpenPGP owner alerts · webhook · boot “armed” notice  

### 3.3 Full pipeline (optional)

NATS JetStream · CT · extract/enrich · STIX publish · sinkhole · CF/AWS immunize · harden.

### 3.4 Explicit non-goals

See [`docs/LEGAL.md`](docs/LEGAL.md) and ADR 0003.

---

## 4. Technical architecture

```
Public bait (HTTP/SSH/Redis/Telnet/MySQL/FTP/Deception)
        │
        ├─► catch ledger ──► console / OpenAPI / abuse+STIX / PGP email
        │
        └─► NATS JetStream (optional) ──► extract → enrich → disrupt / publish
```

**Runtime:** Go 1.24+ · Docker · Linux preferred (ipset) · Windows netsh supported.

---

## 5. Operator deployability

```bash
cp .env.example .env
bash scripts/deploy-catch-node.sh
bash scripts/verify-catch.sh
# or diligence without public hits:
go run ./cmd/atde -mode seed-demo
```

Playbook: [`docs/CATCH.md`](docs/CATCH.md) · Release: [`RELEASE.md`](RELEASE.md).

---

## 6. IP & diligence checklist

| Item | Status |
|------|--------|
| Apache-2.0 + NOTICE + AUTHORS | Done |
| Schedule A + TRANSFER + GETTING-THE-RIGHTS | Done |
| OpenAPI schema + demo evidence + RELEASE.md | Done |
| Trademark / patents filed | **Not filed** — post-close |

---

## 7. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Repo name optics (“botnet”) | Lead with ATDE 1.3; rename at close |
| Misuse | LEGAL.md + CLA; no offensive live primitives |
| Ops port exposure | Lock 9091; `ATDE_OPS_TOKEN` |
| Email without PGP | `ATDE_PGP_REQUIRE=1` |

---

## 8. Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) — next: 1.4 fleet ledger, 1.5 Terraform, 2.0 enterprise bar.

---

## 9. Contact & next steps

1. [`GETTING-THE-RIGHTS.md`](GETTING-THE-RIGHTS.md)  
2. [`docs/data-room/SCHEDULE-A.md`](docs/data-room/SCHEDULE-A.md)  
3. Sign [`TRANSFER.md`](docs/data-room/TRANSFER.md)  
4. GitHub transfer from `@theworker02`  

**Funding:** `.github/FUNDING.yml` — `github: [theworker02]`, `thanks_dev: u/gh/theworker02`.
