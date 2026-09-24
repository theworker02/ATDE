# Atlas honeypot portal & bait mesh

ATDE **1.3** ships a **seven-surface** bait mesh. The HTTP honeypot on `:8080` is a substantial fake **Atlas Control Plane** — it looks like a production ops gateway with tempting vulnerabilities, but **authentication and privilege elevation are impossible**. Protocol baits (SSH, Redis, Telnet, MySQL, FTP) and the deception L7 surface feed the same catch ledger and fingerprint model.

## What scanners see (HTTP Atlas `:8080`)

| Surface | Appearance | Reality |
|---------|------------|---------|
| `/` | Corporate SaaS landing | Static decoy |
| `/login` | Directory login + HTML SQL comment bait | Always fails; delays increase; lockouts |
| `/wp-login.php` | WordPress bridge skin | Same impossible auth |
| `/mfa` | Hardware token prompt | Codes never accepted |
| `/admin` | Sets session cookie | Still `401 Console locked` |
| `/.env`, `/.git/*`, `/phpinfo.php` | Juicy files / phpinfo | Canary-only content |
| `/backup/` | Directory listing of secrets | Downloads `403` |
| `/api/v1/debug?cmd=id` | Root shell output | Synthetic JSON; no shell |
| `/api/v1/admin/*` | REST admin API | Always `401` |
| `/openapi.json` | Swagger surface | Fake schema + canary paths (**decoy**, not ops OpenAPI) |
| `/.well-known/security.txt` | Disclosure contact | Points at honeypot mailbox |
| `/favicon.ico` | Brand icon | Tiny decoy GIF |
| `/tarpit`, `/cgi-bin/…` | Slow endpoints | Protocol tarpit |

Tempting response headers include `X-Debug-Token` / `X-Powered-By: PHP/8.1.27` — they do not unlock a profiler.

## Hard to get into (by design)

1. No credential pair grants a valid session  
2. Default creds (`admin/admin`) open a **dead-end MFA** page  
3. SQLi payloads get fake `pg_query` errors, then quarantine  
4. Cookies that look authenticated are ignored for elevation  
5. Progressive delays + lockouts burn brute-force tooling  

Every hit is recorded to the catch ledger and NATS (`threat.v1.raw.honeypot`) when the bus is available.

## Protocol baits

| Port | Config key | Behavior |
|------|------------|----------|
| `:2222` | `ssh_addr` | OpenSSH-like banner; plaintext login; credentials burned (`Permission denied`) |
| `:6379` | `redis_addr` | Speaks enough Redis for `PING`/`INFO`; logs exploit-ish cmds (`CONFIG`, `SLAVEOF`, …) |
| `:2323` | `telnet_addr` | Fake telnet login; credentials burned |
| `:3306` | `mysql_addr` | MySQL-style greeting / auth bait; scanners tagged `mysql-bait` / `db-scan` |
| `:2121` | `ftp_addr` | FTP login bait; scanners tagged `ftp-bait` / `cred-spray` |
| `:8443` | deception | Synthetic vuln responses (asymmetric L7 honey-interface) |

Set any bind address to `off` in `configs/config.yaml` to disable that surface.

### MySQL bait (`:3306`)

Presents a server greeting and accepts auth attempts long enough to capture username/password material for the dossier. No real query engine; no filesystem access; credentials always fail. Fingerprint summaries include “MySQL greeting / auth bait” and “MySQL root auth attempt” when applicable.

### FTP bait (`:2121`)

Presents an FTP welcome and login dialog. Credentials are recorded and rejected. Useful against automated cred-spray and IoT FTP scanners that still probe non-standard ports.

## Fingerprinting

Each hit is tagged with tool guess (`nuclei`, `sqlmap`, `masscan`, `mysql-scanner`, `ftp-scanner`, …), severity 1–100, and tags (`cred-spray`, `vuln-bait`, `redis-exploit`, `mysql-bait`, `ftp-bait`, …) for the live console and export packages.

## Ops metrics

With ATDE running, honeypot counters appear on `:9091/metrics`:

- `atde_honeypot_hits_total`
- `atde_auth_burns_total`
- `atde_vuln_bait_hits_total`
- `atde_catch_records_total`

Ops OpenAPI (catch API schema) is at `:9091/v1/openapi.json` — do not confuse with the **decoy** `/openapi.json` on `:8080`.

## Demo script

```powershell
# with honeypot already up:
.\scripts\demo-honeypot.ps1
```

```bash
bash scripts/demo-honeypot.sh
```

Lab multi-surface evidence without public exposure:

```bash
atde -mode seed-demo
```

## Verify

```bash
curl -sS http://127.0.0.1:8080/ | head
curl -sS -X POST http://127.0.0.1:8080/login -d 'username=admin&password=admin'
curl -sS http://127.0.0.1:8080/.env | head
curl -sS 'http://127.0.0.1:8080/api/v1/debug?cmd=id'
curl -sS http://127.0.0.1:8080/openapi.json | head
# protocol baits (examples):
# nc / redis-cli / mysql client / ftp against the published ports
go test ./internal/ingest/honeypot -bench=. -benchmem
```
