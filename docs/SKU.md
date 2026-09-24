# ATDE — Commercial SKUs (1.3)

What an acquirer can **productize immediately** from ATDE **1.3.0**. Pricing is illustrative only.

## SKU map

| SKU | What ships | Buyer motion |
|-----|------------|--------------|
| **ATDE Catch Appliance 1.3** | Seven baits + ledger + console + OpenAPI + STIX/abuse + PGP alerts | Self-host / MSP managed node |
| **ATDE Edge Containment** | Local-first `EnforceContainment` + optional CF/AWS | Bolt onto existing deception/SOC edge |
| **ATDE Threat Pipeline** | NATS JetStream mesh + extract/enrich/STIX publish | Platform / TIP integration |
| **ATDE Doctrine Pack** | ADRs, LEGAL, threat model, CATCH, RELEASE | Included with any SKU |

## 1.3 capability matrix

| Capability | Catch Appliance | Edge | Pipeline |
|------------|-----------------|------|----------|
| HTTP/SSH/Redis/Telnet baits | ✓ | — | ingest |
| MySQL + FTP baits | ✓ | — | ingest |
| Fingerprint + dossiers | ✓ | ✓ | ✓ |
| Live console + OpenAPI | ✓ | optional | — |
| Abuse MD + STIX export | ✓ | ✓ | ✓ |
| PGP owner email | ✓ | optional | — |
| Local-first FW | ✓ | ✓ | via disrupt |
| JetStream full mesh | optional | — | ✓ |

## Buyer archetypes

| Buyer | Primary SKU |
|-------|-------------|
| Security product company | Catch Appliance + Pipeline |
| MSSP / SOC | Catch Appliance (fleet in 1.4) |
| Cloud / edge vendor | Edge Containment |
| PE cyber roll-up | Full platform |

Multi-tenant SaaS metering and SOC2 attestation remain post-1.3 ([`ROADMAP.md`](ROADMAP.md)).
