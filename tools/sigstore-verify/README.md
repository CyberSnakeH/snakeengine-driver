# sigstore-verify

Minimal Sigstore signature verifier. ~18 MB statically-linked Go binary
that performs cosign-keyless verification of release artifacts using the
Sigstore bundle (`.sigstore`) format.

This tool is shipped alongside SnakeEngine release artifacts (inside the
AppImage and the `snakedrv-updater` script) so the auto-update flow can
verify a downloaded artifact without depending on the user having
`cosign` installed.

## Build

```bash
make
# → ./sigstore-verify
```

Embed a version string for `sigstore-verify version`:

```bash
make VERSION=2.1.0
```

## Usage

```bash
sigstore-verify verify-blob \
    --bundle <file>.sigstore \
    --certificate-identity-regexp <regex> \
    --certificate-oidc-issuer <url> \
    [--offline] \
    <blob-file>
```

Example — verify a SnakeEngine driver release:

```bash
sigstore-verify verify-blob \
    --bundle snakeengine-driver-2.1.0.tar.gz.sigstore \
    --certificate-identity-regexp \
        '^https://github.com/CyberSnakeH/snakeengine-driver/.github/workflows/release.yml@refs/tags/v.*$' \
    --certificate-oidc-issuer \
        'https://token.actions.githubusercontent.com' \
    snakeengine-driver-2.1.0.tar.gz
```

Exit codes:

| Code | Meaning                                        |
|------|------------------------------------------------|
| 0    | signature valid AND identity matches the regex |
| 1    | signature invalid, identity mismatch, or error |
| 2    | bad usage / argument error                     |

## What it verifies

- The bundle's signature was produced by a Fulcio-issued certificate
  whose SAN matches `--certificate-identity-regexp`.
- That certificate's OIDC issuer is exactly `--certificate-oidc-issuer`.
- The signed timestamp falls inside the certificate's validity window.
- The artifact bytes match the bundle's signed digest.
- A Rekor transparency-log entry exists for the signature
  (skip with `--offline` if you trust the embedded inclusion proof and
  signed timestamps only).

## Why a separate verifier instead of bundling cosign?

`cosign` is ~80 MB. `sigstore-verify` does the verify-only subset of
that surface in ~18 MB, all statically linked. Smaller AppImages,
faster downloads.

## License

GPL-2.0 (same as the rest of `snakeengine-driver`).
