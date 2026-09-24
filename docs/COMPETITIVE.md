# Competitive positioning

ATDE **1.3** sits in **owned-edge active defense / deception platforms**, not in offensive “hack-back” tooling and not in full TIP platforms alone.

## Category claim

**Self-hosted seven-surface deception + local-first containment appliance with a full threat bus, OpenAPI catch API, and STIX/abuse export** — transferable as a product platform (see [`SKU.md`](SKU.md)), not a one-off honeypot.

## Category map

| Category | Examples (illustrative) | ATDE 1.3 relationship |
|----------|---------------------------|-------------------|
| Classic honeypots | Cowrie, Dionaea | Overlaps bait; ATDE adds bus + dossiers + MySQL/FTP + local-first + PGP + STIX |
| Commercial deception | Various enterprise suites | ATDE is single-tenant / self-host, local FW first, acquisition-ready IP |
| WAF management | Cloudflare / AWS consoles | ATDE automates bans from decoy signal; does not replace WAF |
| TIP / SOAR | MISP, commercial SOARs | ATDE **publishes into** them (STIX 2.1); is not a full TIP |
| Offensive “active defense” folklore | Token flooding, botnet DHT attacks | **Explicit non-goal** — diligence differentiator |

## Differentiation checklist

1. **Seven bait surfaces** on one catch-node  
2. **Local-first containment** without cloud keys  
3. **Fail-soft cloud** — never blocks the catch pipeline on API errors  
4. **Unified JetStream contracts** from CT + honeypot through disrupt  
5. **OpenAPI + STIX + thick abuse packages** for operator handoff  
6. **Legal clarity** baked into ADRs and LEGAL.md  
7. **Significant acquisition packaging** (1.3 RELEASE, valuation bands, Schedule A, SKUs, demo evidence)

## What buyers should not expect (yet)

- Multi-tenant SaaS control plane  
- Guaranteed SOC2  
- Mobile / agent implants  
- Replacement for full EDR  

See [`ROADMAP.md`](ROADMAP.md) for 1.4+ options.
