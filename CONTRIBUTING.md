# Contributing

Thanks for helping improve ATDE.

## Ground rules

1. Keep the product **defensive**. Do not PR live third-party flooding, stolen-token abuse, or unauthorized network interference.
2. Prefer local-first / fail-soft patterns for any new containment channel.
3. Add or update tests for behavior changes.
4. Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes.
5. Do not commit secrets, `data/`, or real attacker dossiers.
6. Do not add GPL/AGPL/SSPL dependencies without maintainer written approval.

## Developer Certificate of Origin (DCO)

By contributing, you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/).  
Every commit in a PR must include:

```text
Signed-off-by: Your Name <your@email.example>
```

Use `git commit -s`. This affirms you have the right to submit the work under the project's Apache-2.0 license.

## Contributor License Agreement

Material or patent-sensitive contributions may additionally be asked to sign the Individual CLA:

- [`docs/data-room/CLA.md`](docs/data-room/CLA.md)

## Dev loop

```bash
go test ./...
go build -o bin/atde ./cmd/atde
```

## Docs

| Change type | Update |
|-------------|--------|
| Operator / deploy | `docs/DEPLOY.md`, `docs/OPERATOR.md`, `docs/CATCH.md` |
| Acquisition-relevant capability | `acquisition.md`, `docs/IP.md` |
| Config / env | `docs/CONFIGURATION.md`, `.env.example` |

## License

Contributions are licensed to the project under Apache-2.0 (`LICENSE`). Copyright remains with the contributor until assigned; outbound distribution is Apache-2.0. See [`docs/IP.md`](docs/IP.md).
