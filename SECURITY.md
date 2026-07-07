# Security Policy

## Reporting a vulnerability

Email **primolab.dev@proton.me**. Please include reproduction steps and,
if relevant, the miner version (`primo-arm-miner --version`) and platform.
You should get a reply within a few days. Please allow a reasonable
disclosure window before publishing details.

In scope: the miner binary and its stratum/API surfaces, the Android app,
`install.sh`, and the release/distribution pipeline (artifact or signature
tampering). The read-only monitoring API (default `127.0.0.1:4068` in the
app; configurable for the CLI) is designed to be safe to expose on a
trusted LAN — reports that assume a hostile LAN are still welcome.

## Verifying what you run

- Canonical downloads: <https://primolab.dev/dl/> — every artifact has a
  `.sha256` beside it and a combined `SHA256SUMS`; `install.sh` verifies
  the hash before installing.
- Release APK signing certificate (SHA-256, same key forever):
  `c28b614c2f6c67673ae1b1c98db914bbfb11853c0a3d49a6190ba233981cd8c3`
  — check with `apksigner verify --print-certs`.
- Mirrored release artifacts (GitLab) must be byte-identical to `/dl/`.

## Supported versions

Only the latest release is supported; there are no security backports.
