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
- The `.sha256` files are served from the same host as the artifacts, so
  they protect against corrupted/truncated downloads and mirror drift —
  not against a compromise of the distribution host itself.

## Known, deliberate trade-offs

- **`stratum+ssl://` does not verify pool certificates.** Mining pools
  overwhelmingly use self-signed TLS certificates, and the Android app
  connects by resolved IP (its sandbox blocks native DNS), so peer and
  hostname verification are disabled — the norm across mining software.
  Treat stratum TLS as transport privacy, not pool authentication; note
  that stratum credentials are a wallet address, not a secret.
- **DNS fallback queries public resolvers directly.** When (and only when)
  the system resolver fails, pool hostnames are resolved by querying
  Cloudflare (1.1.1.1) then Google (8.8.8.8) over plain port 53 — this
  bypasses the system resolver and reveals the pool hostname to those
  services. Set `PRIMO_DNS_FALLBACK=0` to disable.
- **The dev fee routes through PrimoLab's proxy, with a version tag as the
  login.** Each dev-fee slice first connects to `fee.primolab.dev` (the
  open-source [primo-miner-proxy](https://gitlab.com/PrimoLab/primo-miner-proxy)),
  falling back to a compiled-in direct pool, then skipping the slice, if it
  is unreachable — the fee never costs you mining time. The login sent to
  the proxy is a non-identifying `<version>-<platform>` tag (e.g.
  `1.0.8-cli`), **not your wallet or any user identifier**; the proxy swaps
  in the real dev wallet server-side. That tag is anonymous
  version-distribution telemetry. The proxy masks connecting IPs to a
  network prefix (/24 v4, /48 v6) everywhere it logs or exposes them and
  links no address to a wallet; its data policy is published in the proxy
  repo. Only dev-fee slices use the proxy — your own mining connects to
  your configured pools directly and sends nothing to PrimoLab.

## Supported versions

Only the latest release is supported; there are no security backports.
