# Legal & acceptable use

ATDE is a **defensive** security product. By deploying it you agree to:

1. Run decoys, firewall rules, WAF updates, and DNS rewrites only on systems **you own** or are **explicitly authorized** to defend.
2. Use abuse / Safe Browsing / registrar / hosting report channels only through **legitimate** APIs and processes.
3. **Not** use ATDE to attack, flood, hijack, or interfere with third-party networks, botnets’ peer tables, or stolen credentials/tokens belonging to others.
4. Comply with applicable law (computer fraud statutes, CFAA/equivalents, export controls, privacy) and provider Terms of Service.

## What ATDE will not do

| Action | Status |
|--------|--------|
| Post to Telegram/Discord using stolen bot tokens or webhooks harvested from malware | Not implemented (evidence simulation only) |
| Inject peers into Mirai/Hajime or other third-party DHTs | Not implemented (evidence simulation only) |
| Block RFC1918 / loopback / documentation TEST-NET addresses at the OS firewall | Refused by design |
| Bypass Cloudflare/AWS account boundaries | Requires **your** API credentials |

## Evidence handling

Catch dossiers under `data/caught/` may contain attacker IPs, User-Agents, and request metadata. Treat them as sensitive operational data. Retain and share according to your organization’s incident-response and privacy policy (and applicable law).

## No warranty

Software is provided under Apache-2.0 **AS IS**. See `LICENSE`. Operators are responsible for configuration, privilege, and lawful use.
