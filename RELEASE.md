# ATDE 2.0.0 — The Threat Disruption Platform

**Product:** Autonomous Threat Disruption Engine  
**Date:** 2026-09-24  
**Line:** Stable **2.0** — maximal defensive disruption on infrastructure you own

## Headline

ATDE **2.0** is a full **threat disruption system**: ten decoy surfaces, graduated policy engine, campaign correlation, MITRE ATT&CK tagging, local-first + cloud containment, fleet ban sync, and SIEM/TIP export (Abuse MD · STIX · ECS · CEF · MISP) — still **zero hack-back**.

## Disruption stack

| Layer | What it does |
|-------|----------------|
| **Bait mesh (10)** | HTTP Atlas · SSH · Redis · Telnet · MySQL · FTP · SMTP · Elasticsearch · MongoDB · Deception |
| **Fingerprint** | Tool · tags · severity · **MITRE ATT&CK** techniques |
| **Policy engine** | observe → tarpit → local ban → cloud escalate → abuse pack |
| **Campaign intel** | Cluster related IPs by tradecraft (`/v1/campaigns`) |
| **Containment** | Local-first ipset/netsh · fail-soft CF/AWS |
| **Fleet** | Owned-node ban list sync (`/v1/fleet/bans`) |
| **Export** | Markdown · STIX 2.1 · ECS · CEF · MISP |
| **Notify** | OpenPGP email · webhook |
| **Pipeline** | Optional NATS JetStream mesh |

## Deploy

```bash
cp .env.example .env
docker compose -f deployments/catch-node.yml up -d --build
# open bait ports; lock 9091
bash scripts/verify-catch.sh
```

## Legal boundary (unchanged)

No stolen-token floods · no third-party botnet DHT · no offensive action on hosts you do not own. See `docs/LEGAL.md`.

## Acquirer

[`GETTING-THE-RIGHTS.md`](GETTING-THE-RIGHTS.md) · [`acquisition.md`](acquisition.md)
