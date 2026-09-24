# secrets/ (local only)

Place operator secrets here on the catch-node host. **Never commit private keys or passwords.**

| File | Purpose |
|------|---------|
| `owner.asc` | Owner **OpenPGP public** key for encrypted alert emails (`ATDE_PGP_PUBLIC_KEY_FILE`) |

```bash
gpg --armor --export you@example.com > secrets/owner.asc
```

This directory should remain gitignored except this README.
