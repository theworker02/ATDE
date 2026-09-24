# Catch attackers — deploy → bait → record

Primary ATDE **1.3** use case, polished for a public VPS.

```text
  YOU deploy one box              INTERNET bots / scanners hit bait ports
  (Docker catch-node)         ──▶ HTTP · SSH · Redis · Telnet · MySQL · FTP · deception
                                         │
                                         ▼
                                  Every hit is fingerprinted + written to disk
                                  data/caught/events.jsonl
                                  data/caught/dossier_<IP>.json
                                         │
                                         ▼
                                  YOU review the live console + OpenAPI
                                  http://YOUR_IP:9091/console
                                  http://YOUR_IP:9091/v1/openapi.json
                                  (severity · tools · tags · abuse · STIX export)
```

No Cloudflare / AWS / AbuseIPDB keys are required to **record** attacks.
After a few high-severity hits from a public IP, ATDE can also apply a **local OS ban** (ipset/netsh) without NATS.

---

## 1. Deploy (one command)

```bash
git clone https://github.com/theworker02/blind-botnet.git
cd blind-botnet
cp .env.example .env
# strongly recommended:
# echo 'ATDE_OPS_TOKEN=long-random-secret' >> .env

bash scripts/deploy-catch-node.sh
# Windows:  .\scripts\deploy-catch-node.ps1
```

Or:

```bash
docker compose -f deployments/catch-node.yml up -d --build
```

### Open these ports

| Port | Bait | Who hits it |
|------|------|-------------|
| **8080** | Atlas fake control-plane (login, `.env`, RCE canary) | Web scanners / bots |
| **2222** | SSH password-burn | Credential stuffers |
| **6379** | Redis protocol bait | Redis exploit bots |
| **2323** | Telnet login bait | IoT botnet scanners |
| **3306** | MySQL greeting / auth bait | DB scanners / credential stuffers |
| **2121** | FTP login bait | Cred-spray / IoT FTP probes |
| **8443** | Deception API surface | Exploit kit probes |
| **9091** | Operator console + catch API + OpenAPI — **your IP only** | You |

```bash
sudo ufw allow 22/tcp
sudo ufw allow 8080,2222,6379,2323,3306,2121,8443/tcp
sudo ufw allow from YOUR.ADMIN.IP to any port 9091
sudo ufw enable
```

Config keys: `ingest.honeypot.mysql_addr` (default `:3306`), `ingest.honeypot.ftp_addr` (default `:2121`). Set either to `off` to disable.

---

## 2. Prove recording works

```bash
# with catch-node already up:
bash scripts/verify-catch.sh
# Windows:
.\scripts\verify-catch.ps1
```

Then open `http://YOUR_IP:9091/console` — you should see hits, severity, and tool tags.

### Lab proof without public scanners (`seed-demo`)

```bash
atde -config configs/config.yaml -mode seed-demo
# writes sanitized multi-surface events under data/caught/
atde -mode caught -limit 20
```

Use for diligence demos, CI smoke, or training — not a substitute for a public catch-node when you want real internet telemetry.

---

## 3. What each record contains

| Field | Example |
|-------|---------|
| IP / time | `203.0.113.50`, UTC timestamp |
| Service / path | `mysql-bait`, `ftp-bait`, `http-vuln-bait` `/.env` |
| Tool guess | `nuclei`, `sqlmap`, `mysql-scanner`, `ftp-scanner`, … |
| Tags | `cred-spray`, `redis-exploit`, `mysql-bait`, `ftp-bait`, `auth-burn` |
| Severity | 1–100 (console sorts hot dossiers) |
| Body snippet | attempted passwords / Redis cmds / MySQL auth (truncated) |
| Actions | `recorded`, later `local_firewall` if banned |

---

## 4. Encrypted email to the owner

When an attacker is recorded, ATDE can email **you** with who hit the decoy and confirmation that they were logged.

1. SMTP (TLS / STARTTLS) to your mailbox  
2. **OpenPGP encrypt** the body to your public key (recommended — set `ATDE_PGP_REQUIRE=1`)  
3. On boot, a one-time “catch-node armed” mail is sent (`ATDE_ALERT_BOOT=1`)

```bash
# in .env on the VPS
ATDE_ALERT_TO=you@example.com
ATDE_ALERT_FROM=atde@yourdomain.com
ATDE_SMTP_HOST=smtp.yourdomain.com
ATDE_SMTP_PORT=587
ATDE_SMTP_USER=...
ATDE_SMTP_PASS=...
ATDE_SMTP_TLS=starttls
ATDE_PGP_PUBLIC_KEY_FILE=/app/secrets/owner.asc
ATDE_PGP_REQUIRE=1
ATDE_CONSOLE_URL=http://YOUR_PUBLIC_IP:9091/console
ATDE_NODE_NAME=vps-catch-1
```

Mount the key file into the container (example):

```yaml
# add under volumes in catch-node.yml or override:
# - ./secrets/owner.asc:/app/secrets/owner.asc:ro
```

Export your public key (example with GnuPG):

```bash
gpg --armor --export you@example.com > secrets/owner.asc
```

Decrypt alerts with your private key in Proton Mail / Thunderbird / `gpg -d`.

Cooldown (default 15m per IP) prevents inbox floods from noisy scanners.

---

## 5. Day-2 review — abuse, STIX, OpenAPI

```bash
docker compose -f deployments/catch-node.yml exec atde /app/atde -mode caught
docker compose -f deployments/catch-node.yml exec atde /app/atde -mode dossier
docker compose -f deployments/catch-node.yml exec atde /app/atde -mode export -ip 203.0.113.10
docker compose -f deployments/catch-node.yml exec atde /app/atde -mode abuse -ip 203.0.113.10
docker compose -f deployments/catch-node.yml exec atde /app/atde -mode stix -ip 203.0.113.10
docker compose -f deployments/catch-node.yml exec atde /app/atde -mode watch
```

### Catch API (ops `:9091`)

| Path | Purpose |
|------|---------|
| `/v1/openapi.json` | OpenAPI 3 schema for the catch API |
| `/v1/capabilities` | Product capability map |
| `/v1/summary` | Dashboard stats + hot dossiers |
| `/v1/caught` | Recent events |
| `/v1/dossiers` | Ranked dossiers |
| `/v1/dossier/{ip}` | One dossier JSON |
| `/v1/export/{ip}` | Abuse Markdown package |
| `/v1/stix/{ip}` | STIX 2.1 indicator bundle |
| `/console` | Live operator UI |

```bash
curl -sS -H "X-ATDE-Token: $ATDE_OPS_TOKEN" http://YOUR_IP:9091/v1/openapi.json | head
curl -sS -H "X-ATDE-Token: $ATDE_OPS_TOKEN" http://YOUR_IP:9091/v1/export/203.0.113.10
curl -sS -H "X-ATDE-Token: $ATDE_OPS_TOKEN" http://YOUR_IP:9091/v1/stix/203.0.113.10
```
Optional Slack/Discord alerts:

```bash
export ATDE_WEBHOOK_URL='https://hooks.example/...'
docker compose -f deployments/catch-node.yml up -d
```

---

## 6. Legal boundary

Deploy only on hosts **you own**. This baits and records attackers targeting *your* decoys — it does not attack third parties. See [LEGAL.md](LEGAL.md).

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Console empty after hours | Ports not public / wrong security group / CGNAT |
| Only private IPs | You tested from localhost — wait for internet scanners or run `seed-demo` |
| Redis/Telnet/MySQL/FTP not listening | Confirm Compose ports and `redis_addr` / `telnet_addr` / `mysql_addr` / `ftp_addr` in config |
| No alert emails | Set `ATDE_ALERT_TO` + SMTP + preferably `ATDE_PGP_PUBLIC_KEY_FILE`; check spam; severity/cooldown |
| Want full CT + STIX pipeline | Use `deployments/docker-compose.yml` (`-mode all`) with NATS |

More detail: [HONEYPOT.md](HONEYPOT.md) · [OPERATOR.md](OPERATOR.md) · [DEPLOY.md](DEPLOY.md) · [CONFIGURATION.md](CONFIGURATION.md)
