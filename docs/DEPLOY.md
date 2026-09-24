# Deploy ATDE (operators)

Deploy only on infrastructure **you own or are authorized to defend**. See [LEGAL.md](LEGAL.md).

**Want the simple path?** → **[CATCH.md](CATCH.md)** (public VPS → scanners hit decoys → review `data/caught/`).

## Requirements

| Requirement | Notes |
|-------------|--------|
| Docker + Compose **or** Go 1.24+ | Compose is the fastest path |
| NATS with JetStream | Bundled in Compose |
| Public ports (recommended) | `8080`, `2222`, `8443` (and `9080` if using sinkhole listener) |
| Privileges for local firewall | Linux: `CAP_NET_ADMIN` / root; Windows: Administrator for `netsh` |

Optional: Cloudflare / AWS / AbuseIPDB credentials for cloud escalation.

## Quick start (Docker)

```bash
git clone <this-repo> && cd blind-botnet   # or renamed ATDE checkout
cp .env.example .env                      # edit if needed
docker compose -f deployments/docker-compose.yml up -d --build
```

Verify:

```bash
curl -sS http://127.0.0.1:8080/wp-login.php
docker compose -f deployments/docker-compose.yml exec atde /app/atde -mode caught
# or from host with data volume mounted:
go run ./cmd/atde -mode caught
```

Artifacts appear under `./data/caught/`:

- `events.jsonl` — append-only audit log
- `dossier_<IP>.json` — rolling per-attacker summary

## Quick start (local binary)

```bash
docker compose -f deployments/docker-compose.yml up -d nats
cp .env.example .env
# PowerShell
$env:NATS_URL="nats://127.0.0.1:4222"; $env:ATDE_LIVE="1"
go run ./cmd/atde -config configs/config.yaml -mode all
```

Build release binary:

```bash
make build
./bin/atde -version
./bin/atde -config configs/config.yaml -mode all
```

## Configuration

| Knob | Effect |
|------|--------|
| `ATDE_LIVE=1` / `app.live: true` | Real containment + API posts when keys exist |
| `ATDE_DRY_RUN=1` | Force simulation everywhere |
| `ATDE_LOCAL_FIREWALL=0` | Disable OS blocks (ledger still records) |
| `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ZONE_ID` | Owned-zone IP bans |
| `AWS_WAF_IPSET_ID` + `AWS_WAF_IPSET_NAME` | Owned WAFv2 IPSet updates |
| `ABUSEIPDB_API_KEY` | Live AbuseIPDB reports |

See `.env.example` and `configs/config.example.yaml` (dry-run template).

## Network exposure

1. Place the catcher on a VPS or lab host with a public IP
2. Forward TCP `8080`, `2222`, `8443`
3. Do **not** place production secrets behind deception routes
4. Expect internet-wide scanners within minutes of exposure

Localhost probes are **recorded** but **not** firewall-blocked (private IP safeguard).

## Linux ipset notes

On first live block, ATDE attempts:

```text
ipset create atde_honeypot_bans hash:ip timeout 86400 -exist
iptables -I INPUT -m set --match-set atde_honeypot_bans src -j DROP
ipset add atde_honeypot_bans <IP> timeout 86400 -exist
```

If `ipset` is missing, it falls back to per-IP `nft` / `iptables` rules.

## Modes

| Mode | Purpose |
|------|---------|
| `catch-node` | Public bait box: honeypot + deception + disk ledger (NATS optional) |
| `all` | Full mesh (default container entrypoint) |
| `honeypot` | Decoys + extract + active containment |
| `deception` | L7 honey-interface + active |
| `caught` | Print ledger summary / recent events (`-ip` optional) |
| `dossier` | List or show one dossier (`-ip`) |
| `export` | Write Markdown abuse package (`-ip`, optional `-out`) |
| `watch` | Tail `events.jsonl` |
| `doctor` | Preflight checks (NATS, ports, dirs, keys) |
| `status` | Config + catch summary |
| `version` | Print semver |

## Health checks

- NATS monitoring: `http://127.0.0.1:8222/healthz` (Compose maps `8222`)
- Ops / console: `http://HOST:9091/console` · `curl http://HOST:9091/healthz`
- Honeypot: `curl http://HOST:8080/`
- Deception: `curl "http://HOST:8443/api/v1/debug?cmd=id"`
- Ledger: `atde -mode caught` · `atde -mode doctor`

## Troubleshooting

| Symptom | Check |
|---------|--------|
| No catches | Ports not public; process not running; wrong data dir |
| No OS block | Need admin/`NET_ADMIN`; private IP; `ATDE_LOCAL_FIREWALL=0`; dry-run |
| Cloud ban skipped | Missing tokens — expected; local path should still work |
| NATS errors | Start Compose `nats` service first |

## Hardened binary (optional)

```bash
make build-hardened   # requires bash + garble when available
```
