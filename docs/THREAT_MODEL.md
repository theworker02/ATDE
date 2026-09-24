# Threat model (ATDE catch node)

Methodology inspired by STRIDE applied to a **single-tenant operator-owned** catcher. Not a full pentest report.

## Assets

| Asset | Sensitivity |
|-------|-------------|
| Catch dossiers / events.jsonl | Medium–High (attacker IPs, UA, paths) |
| Abuse evidence Markdown | Medium |
| API tokens (CF/AWS/Abuse) | High |
| Host firewall state | High (availability) |
| Decoy listeners | Low data; High as attack surface of the process itself |

## Trust boundaries

```
Internet ──► Decoy ports (8080/2222/8443/9080)
                │
                ▼
           ATDE process ──► localhost NATS
                │
                ├──► OS firewall (privileged)
                ├──► Cloudflare / AWS APIs (egress)
                └──► data/caught filesystem
```

## STRIDE summary

| Threat | Mitigation in design |
|--------|----------------------|
| Spoofing (XFF) | Trusted-proxy list on deception; prefer direct RemoteAddr |
| Tampering (ledger) | File perms 0600/0750; future: signing roadmap |
| Repudiation | Append-only `events.jsonl` audit trail |
| Information disclosure | No production secrets on decoy upstream by default; LEGAL warns |
| Denial of service | Tarpit + ipset O(1); connection caps on tarpit engine |
| Elevation | Firewall argv-only exec; no shell; private IP refuse |

## Abuse cases (out of scope / refused)

- Operator points ATDE at third-party networks to “hack back” → rejected by product doctrine (ADR-0003)
- Attacker supplies `1.2.3.4; rm -rf /` as IP → sanitized / parsed as net.IP; invalid rejected

## Residual risks

| Risk | Severity | Notes |
|------|----------|-------|
| Compromised ATDE host | High | Harden optional; isolate catcher VM |
| Malicious upstream_url | High | Operator config error — document only |
| Log PII retention | Medium | OPERATOR rotation guidance |
| Dependency CVEs | Medium | Dependabot + `make sbom` |

## Review cadence

Revisit on each minor release or when adding a new egress integration.
