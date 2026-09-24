# ADR-0004: Linux ipset for O(1) bans

## Status

Accepted (v0.1.0)

## Context

Per-IP `iptables -I INPUT -s <ip> -j DROP` does not scale to thousands of scanner addresses (linear rule walk). Catch nodes on the public internet see continuous unique sources.

## Decision

Prefer **ipset** hash:ip set `atde_honeypot_bans` with timeout 86400, bound once via `iptables -m set --match-set … -j DROP`. Fall back to nft/iptables per-IP if ipset unavailable. Windows uses netsh rules.

## Consequences

- Stable packet-filter performance under scanner floods  
- Requires `ipset` in image/host (Dockerfile installs it)  
- Duplicate adds are idempotent (`-exist`)  
