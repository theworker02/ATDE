# Open-source software inventory (direct dependencies)

Generated for acquisition diligence. Run `make sbom` for a machine-readable snapshot.
Licenses below are as commonly published by upstream; **buyer should verify with SCA**.

## Direct `go.mod` require

| Module | Declared license (typical) | Role in ATDE |
|--------|----------------------------|--------------|
| `github.com/ProtonMail/gopenpgp/v3` | BSD-3-Clause / MPL components via go-crypto | OpenPGP encrypt owner alert emails |
| `github.com/aws/aws-sdk-go-v2` (+ config, wafv2) | Apache-2.0 | Optional AWS WAFv2 immunize |
| `github.com/gorilla/websocket` | BSD-2-Clause | CertStream CT websocket |
| `github.com/nats-io/nats.go` | Apache-2.0 | JetStream bus client |
| `golang.org/x/sync` | BSD-3-Clause | errgroup supervision |
| `golang.org/x/sys` | BSD-3-Clause | OS primitives (harden / platform) |
| `gopkg.in/yaml.v3` | MIT / Apache-2.0 dual | Config YAML |

## Notable indirect

| Module | Typical license | Notes |
|--------|-----------------|-------|
| `github.com/ProtonMail/go-crypto` | BSD-3-Clause | OpenPGP crypto backend |
| `github.com/cloudflare/circl` | BSD-3-Clause | Crypto primitives |
| `github.com/klauspost/compress` | Apache-2.0 / BSD | NATS compression |
| `github.com/nats-io/nkeys`, `nuid` | Apache-2.0 | NATS helpers |
| `github.com/aws/smithy-go` | Apache-2.0 | AWS SDK |
| `golang.org/x/crypto` | BSD-3-Clause | Crypto |

## Copyleft scan (seller knowledge)

| Class | Present in direct deps? |
|-------|-------------------------|
| GPL / AGPL / LGPL | **No** (seller knowledge of direct set) |
| SSPL / BUSL | **No** |
| Proprietary SDK requiring paid license | **No** for core catch-node |

## Attribution obligations

Apache-2.0 and BSD/MIT require preservation of copyright notices. ATDE ships:

- Root [`LICENSE`](../../LICENSE)
- Root [`NOTICE`](../../NOTICE)
- [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md)

## Regeneration

```bash
make sbom
# or: go list -m all
```
