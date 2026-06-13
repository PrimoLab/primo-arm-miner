# Primo ARM Miner

A minimal, pure ARM-native multi-algorithm cryptocurrency miner — no x86 compatibility layer — with a ccminer-compatible CLI and configuration surface.

## Quick Install (Linux arm64 / Termux)

```bash
curl -fsSL https://raw.githubusercontent.com/PrimoLab/primo-arm-miner/master/install.sh | sh
```

Downloads the prebuilt binary for your platform (arm64 SBC or Android/Termux),
installs runtime libraries, and prints a mining quickstart. ARMv8 crypto
extensions (AES/PMULL/SHA2) are required — standard on every 64-bit ARM SoC
of the last decade.

> **Termux note:** if launching fails with `CANNOT LINK EXECUTABLE ...
> libcurl.so`, your Termux packages are out of sync (libcurl newer than its
> ngtcp2 dependency). Run `pkg update && pkg upgrade -y` and retry.

## Features

- **Pure ARM-native, no x86 compatibility layer** — Verus, SHA256d, and scrypt paths written directly in ARM intrinsics and AArch64 assembly, not translated from SSE
- **Hardware crypto extensions** — ARMv8 PMULL, AES, and SHA2 instructions on the hot paths
- **Per-core runtime optimization** — big.LITTLE topology detected at startup; interleaved CLHash, fused-dispatch CLHash, and SoA scrypt kernels enabled per thread where they win
- **Hotplug-resilient core pinning** — pins are chosen from the platform-allowed cpuset and reconciled continuously; threads adopt cores that Android parks/wakes at runtime instead of losing their pins
- **ccminer-compatible control surface** — same CLI flags, JSON config format, and monitoring API
- **Full stratum support** — standard (SHA256d/scrypt) and Verus/equihash variants, multi-pool failover
- **Tiny footprint** — a single ~228 KB binary, two runtime libraries (libcurl, libjansson)

## Performance

Measured on RK3588 (4×Cortex-A55 @ 1.8 GHz + 4×Cortex-A76 @ 2.25–2.35 GHz):

| Algorithm | A76 single core | 8 threads (4×A55 + 4×A76) |
| --- | --- | --- |
| Verus (VerusHash v2.2) | ~1.44 MH/s | ~7.5 MH/s |
| SHA256d | ~16.3 MH/s | ~90 MH/s |
| Scrypt (N=1024) | ~4.8 kH/s | ~25.9 kH/s |

Galaxy S10+ (Exynos 9820, Termux): ~5.5-5.7 MH/s Verus across 8 threads.
Per-core optimizations (two-nonce interleaved CLHash on big cores, fused
case dispatch on ARM A75+-generation big cores, 4-lane SoA scrypt) are
selected automatically per thread at runtime.

Numbers vary with thermal headroom, governor, and per-SoC core mix.

> **Android: getting full speed from the big cores.** Android throttles apps
> that are not the *focused* foreground app, in two distinct ways:
>
> 1. **Withheld cores (cpuset).** Backgrounded or with the screen off, the OS
>    removes one or more cores from the app's `top-app` cpuset; the miner logs
>    `Platform allows this process only N of M CPUs`. With more threads than
>    allowed cores the extras share a core (`only N core(s) available; sharing
>    CPU X with thread Y`) and show up at half rate.
> 2. **Capped frequency (uclamp).** Even when every core is granted, a
>    non-foreground process can be held at a low CPU frequency, so a big core
>    delivers little-core hashrate. The miner detects this and logs `CPU n
>    (Cortex-Xn) only A/B MHz under sustained load — big cores appear
>    frequency-capped`.
>
> Both are OS policy the miner cannot override, and both have the same fix: keep
> the Termux app open on screen, or launch the miner from an **SSH or `adb shell`**
> session — shell sessions run in the all-core, unthrottled `top-app` group even
> with the screen off. A withheld core is re-adopted automatically (~20 s) once
> it returns.
>
> **MediaTek SoCs** additionally hotplug the big-core cluster *offline* under
> sustained thermal load (the kernel uses CPU hotplug as a cooling device), so
> the online-core set flaps in the log. This is firmware thermal management and
> needs root to disable — improve cooling or accept the reduced sustained rate.

## Building

```bash
# Makefile builds now track header dependencies automatically.
make

# or build with CMake into ./build and refresh the repo-root binary
./build.sh
```

If you are switching branches, changing toolchains, or recovering from an older mixed-object worktree, use:

```bash
make clean && make -j"$(nproc)"
```

**Requirements:**
- ARM CPU with crypto extensions (ARMv8+)
- `make` build defaults to `clang-16` / `clang++-16` with `lld`
- Alternate compatible Clang driver names can be selected with `CC=...`, `CXX=...`, and `PRIMO_LINKER=...`
- libcurl, libjansson

Examples:

```bash
# Default validated toolchain
make -j"$(nproc)"

# Override compiler drivers and use the toolchain's default linker
make clean
CC=clang CXX=clang++ PRIMO_LINKER= make -j"$(nproc)"
```

`./build.sh` uses the same overrides for the CMake path via `CC`, `CXX`, and `PRIMO_LINKER`. Leaving `PRIMO_LINKER` empty drops the `lld`-specific linker selection and hugetlbfs alignment flag.

### Device build profiles

`make` defaults to `PROFILE=rk3588`, which enables the Cortex-A76 hand-scheduled
assembly in the Verus hot path (validated on RK3588) plus the Cortex-A53 erratum
workaround. For **any other device** — other SBCs, phones, or a CI matrix
producing per-model binaries — use the portable profile:

```bash
make PROFILE=generic
```

`generic` drops the A76-specific hand assembly and the A53 erratum workaround and
lets the compiler schedule the portable intrinsics. It keeps the
`-mtune=cortex-a53` codegen tuning, which benchmarks fastest across heterogeneous
big.LITTLE SoCs. Per-core kernel selection (interleaved/fused CLHash, SoA scrypt)
is chosen at runtime, so it is identical under either profile.

> **Do not raise `-march` to `armv8.2-a`.** It implies the LSE atomics extension,
> which the compiler then emits inline; on an ARMv8.0 core (common in budget and
> older SoCs) those instructions fault with `SIGILL` the moment mining starts.
> The build stays on `-march=armv8-a+crypto` so one binary runs on every ARMv8 core.

## License And Provenance

- Distributed under `GPL-3.0-or-later`. See [`LICENSE`](LICENSE).
- Project-level release notice: [`NOTICE`](NOTICE).
- Known file and subsystem ancestry: [`PROVENANCE.md`](PROVENANCE.md).
- Third-party notices that remain in-tree, such as `src/algorithm/scrypt.h`, must be preserved in redistribution.

## Usage

### Command Line (ccminer-compatible)

```bash
# Basic mining
./primo-arm-miner -a verus -o stratum+tcp://pool.verus.io:9998 -u WALLET.worker

# With all options
./primo-arm-miner \
  -a verus \
  -o stratum+tcp://pool.verus.io:9998 \
  -u RWallet123.worker \
  -p x \
  -t 8

# Benchmark mode
./primo-arm-miner --benchmark -t 4

# Benchmark scrypt
./primo-arm-miner -a scrypt --benchmark -t 4

# Benchmark sha256d
./primo-arm-miner -a sha256d --benchmark -t 4
```

### JSON Config File (ccminer-compatible)

```bash
# Auto-load local ./config.json when present
./primo-arm-miner

# Or load an explicit config path
./primo-arm-miner -c config.json
```

**config.json:**
```json
{
  "algo": "verus",
  "url": "stratum+tcp://pool.verus.io:9998",
  "user": "RWallet123.worker",
  "pass": "x",
  "threads": 8,
  "api-bind": "127.0.0.1:4068",
  "quiet": false,
  "debug": false
}
```

Explicit CLI flags override values from the config file. That lets `config.json` act as a default profile while still allowing one-off overrides such as `-t 2` or `-a sha256d`. When `pools[]` is present, `-o/--url` switches the run into single-pool mode and ignores the configured pool array for that invocation.

See [`CONFIG_EXAMPLES.md`](CONFIG_EXAMPLES.md) for quick copy-paste examples and [`CONFIG_JSON.md`](CONFIG_JSON.md) for the full `config.json` reference, including `api-bind`, multi-pool keys, and precedence rules.

### Multi-Pool Config (ccminer pools.json compatible)

```json
{
  "user": "wallet.worker",
  "pass": "x",
  "pools": [
    {
      "name": "Primary",
      "url": "stratum+tcp://pool1.verus.io:9998",
      "timeout": 180,
      "disabled": 0
    },
    {
      "name": "Backup",
      "url": "stratum+tcp://pool2.verus.io:9998",
      "timeout": 180,
      "disabled": 0
    }
  ],
  "threads": 8
}
```

Top-level `user` and `pass` act as defaults for every pool entry. The miner skips `disabled` pools for startup and failover, and a pool-local `timeout` overrides the global `timeout` only for that pool.
CLI `-u`, `-p`, `-O`, and `-T` still apply as global overrides in multi-pool mode. CLI `-o` also remains valid: it switches that invocation into single-pool mode and ignores the configured `pools[]` array.

## Configuration Compatibility

This miner is intended to accept the same common config files and command-line arguments used by ccminer:

```bash
# Use your existing ccminer config
./primo-arm-miner -c /path/to/ccminer.conf

# Or just replace the binary and rely on local ./config.json
cp primo-arm-miner ccminer
```

### Supported Options

**Mining:**
- `-a, --algo` - Algorithm (`verus`, `sha256d`, `scrypt`)
- `-o, --url` - Pool URL
- `-u, --user` - Wallet + worker
- `-p, --pass` - Password
- `-O, --userpass` - User:pass format
- `-t, --threads` - Thread count
- `-c, --config` - Config file

**Network:**
- `-r, --retries` - Retry count
- `-R, --retry-pause` - Retry delay
- `-T, --timeout` - Timeout

Startup uses the same retry policy as steady-state reconnects. With `-r -1`, the miner keeps retrying until interrupted.

**Display:**
- `-D, --debug` - Debug output
- `-P, --protocol-dump` - Protocol dump without requiring `-D`
- `-q, --quiet` - Quiet mode
- `-N, --statsavg` - Stats window

**Misc:**
- `--benchmark` - Offline synthetic benchmark mode for all supported algorithms
- `-b, --api-bind` - API endpoint
- `-V, --version` - Version
- `-h, --help` - Help

## Dev Fee

The miner includes a small development fee, taken as one 60-second time
slice per cycle of mining on the developer's pool/wallet for the active
algorithm:

- **Verus: 2%** (60s per 50 minutes) — reflecting that this miner is
  ~10%+ faster on Verus than the ccminer ARM builds it replaces
- **SHA256d / Scrypt: 1%** (60s per 100 minutes)

The first slice lands at a random point within the first cycle (re-drawn
every start, so the fee can't be skipped with scheduled restarts); very
short sessions usually pay nothing. If the dev pool is ever unreachable,
the slice is skipped immediately — your mining time is never held up by it.
Implemented in `src/dev_fee.cpp`; the fee and the donations below are the
project's only funding, and forks are of course free to change it (GPL).

## Donations

If this miner earns you something and you'd like to support it, donations
go directly toward acquiring ARMv9 test hardware (SVE2-capable boards and
phones) so future optimization work can target the next generation of ARM
cores the same way this release was tuned on real ARMv8 silicon:

- **VRSC**: `RDArJkrPSKPhX8zwUJHLu2SJWrL4GwCgKz`
- **BTC**: `15nR6PuUkjTyjv9dnkYd2GbjbgiMxs4dLi`
- **LTC**: `ltc1qguj48xprktyeqm4dqrje5cr7f8g76e0mvrdjh6`

## Validation

- Startup self-tests verify the scrypt SoA path against a reference
  implementation on every launch; `VERUS_X2_SELFTEST=1` cross-checks the
  interleaved Verus path hash-for-hash.
- Live share acceptance verified on pool.verus.io (Verus, 100% over 350+
  shares), public-pool.io (SHA256d), and litecoinpool.org (scrypt).

## Project Structure

```
primo-arm-miner/
├── src/
│   ├── main.cpp               # Entry point, benchmark mode
│   ├── config.cpp             # Config parser (ccminer compatible)
│   ├── api.cpp                # Compatibility API service
│   ├── miner.cpp              # Mining coordinator, threading
│   ├── stratum.cpp            # Protocol dispatch + shared helpers
│   ├── stratum_internal.h     # Protocol-ops struct, internal API
│   ├── stratum_handshake.cpp  # Subscribe/authorize flow
│   ├── stratum_transport.cpp  # Socket I/O: connect, send/recv, shutdown
│   ├── stratum_session.cpp    # Message loop, session lifecycle, failover
│   ├── stratum_standard.cpp   # Standard stratum (SHA256d, Scrypt)
│   ├── stratum_verus.cpp      # Verus/Equihash stratum
│   ├── stratum_rpc.cpp        # JSON-RPC build/dispatch, difficulty
│   ├── stratum_state.cpp      # Shared work/runtime state, share stats
│   ├── stratum_job.cpp        # Job commit / work building
│   ├── dev_fee.cpp            # Time-slice dev fee scheduler (2% verus, 1% rest)
│   ├── algorithm/
│   │   ├── verus.cpp          # VerusHash v2.2 (CLHash + Haraka512)
│   │   ├── clhash_native.c    # Native CLHash (PMULL)
│   │   ├── haraka_native.c    # Native Haraka (AES)
│   │   ├── sha256_neon.c      # SHA256d (ARMv8 SHA2 + NEON fallback)
│   │   ├── sha256_ce_asm.S    # Hand-tuned dual-nonce SHA256d asm
│   │   ├── scrypt_neon.c      # Scrypt (scalar Salsa20/8)
│   │   ├── scrypt_blockmix_asm.S # Fused BlockMix asm
│   │   └── cpu_features.c     # CPU detection, topology, temp
│   └── utils/
│       └── log.cpp            # Logging
├── include/                   # miner.h + per-algorithm API headers
├── Makefile                   # Primary build (clang-16, per-file rules)
├── CMakeLists.txt             # Alternative CMake build
├── build.sh                   # CMake helper build script
├── build_termux.sh            # Native Termux (Android) build
├── install.sh                 # Prebuilt-binary installer
└── README.md
```

## Credits

**Project Contributors:**
- Verus implementation by Monkins1010
- ARM optimization by Mixed-Nuts

**Release Notes:**
- Project release ancestry is documented in [`PROVENANCE.md`](PROVENANCE.md)
- Project redistribution notice is in [`NOTICE`](NOTICE)
- Built with substantial contributor assistance during the rewrite/compliance passes

## Disclaimer

This software is provided **as-is, without warranty of any kind**, and you
install and run it **entirely at your own risk**. The authors and
contributors accept **no responsibility for any damage** resulting from its
use.

Cryptocurrency mining is one of the most demanding workloads a device can
run. Be aware that sustained mining will:

- run your CPU at or near 100% load for extended periods, generating
  **significant heat** — especially on passively cooled phones and SBCs;
- accelerate **battery wear** on mobile devices (mine plugged in, ideally
  with the battery between charge limits, and never under a pillow or in
  direct sun);
- increase **power consumption** and may shorten the lifespan of hardware
  that is run hot for long periods.

Monitor your device temperatures, ensure adequate cooling, and stop mining
if a device gets too hot to touch comfortably. You are also responsible for
ensuring that mining complies with local regulations, your electricity
arrangements, and the terms of any pool you connect to. Double-check wallet
addresses — shares mined to a mistyped address are unrecoverable.

Use responsibly.

## License

This repository is released under `GPL-3.0-or-later`.

See:
- [`LICENSE`](LICENSE) for the full license text
- [`NOTICE`](NOTICE) for project-level release notice
- [`PROVENANCE.md`](PROVENANCE.md) for known ancestry and compliance notes
