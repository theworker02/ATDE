# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| **2.0.x** | Yes (current) |
| 1.3.x / 1.x | Security fixes best-effort |
| 0.x | No — superseded |

## Reporting a vulnerability

Please report security issues privately:

- GitHub Security Advisories on this repository (preferred), or
- Contact the maintainer via GitHub `@theworker02`

Do **not** open a public issue for remotely exploitable flaws in the deception/honeypot listeners, the NATS consumer path, or privilege-escalation via firewall exec wrappers.

Include: affected version/commit, reproduction steps, impact, and any suggested fix.

We aim to acknowledge reports within 7 days.

## Security design notes

- Local firewall commands use argv-only `exec.CommandContext` (no shell)
- Private and documentation IPs are never OS-blocked
- Cloud bans are best-effort and fail-soft
- Secrets belong in environment variables / secret managers — never in git
- Offensive third-party interference features are intentionally unimplemented
- Ops console (`:9091`) should be token-protected and IP-restricted in production

See also: [docs/LEGAL.md](docs/LEGAL.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [RELEASE.md](RELEASE.md).
