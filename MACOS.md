# Building on macOS (Apple Silicon)

`primo-arm-miner` targets ARM64 Linux/Android SBCs (Rockchip rk3588 and
similar) by default. This document covers building and running it on macOS
for local development and — since Apple Silicon is itself ARMv8 — actual
mining, with Verus (VRSC) validated end-to-end on an Apple M1 Max.

## Prerequisites

- Xcode Command Line Tools (`xcode-select --install`) — provides Apple
  clang/clang++ and the system libcurl used below.
- Homebrew.
- `brew install cmake jansson`

libcurl does **not** need a brew install; it's picked up from the macOS SDK
(`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib/libcurl.tbd`).

## Build

```bash
CC=clang CXX=clang++ PRIMO_LINKER= ./build.sh
```

Both overrides are required:

- **`CC=clang CXX=clang++`** — the build defaults to `clang-16`/`clang++-16`
  (`CMakeLists.txt`), which don't exist on macOS unless you've separately
  installed LLVM 16 via Homebrew. Pointing at the system Apple clang works
  fine; the codebase already treats compiler-driver overrides as a supported
  path (see `README.md`'s "Alternate compatible Clang driver names" note).
- **`PRIMO_LINKER=`** (empty) — the build defaults to `-fuse-ld=lld`, which
  isn't installed on macOS and fails the link step outright (`invalid
  linker name`). This is also an already-supported override, just needs
  setting explicitly here — leaving it empty drops both the `lld` selection
  and the Linux/Android-only hugetlbfs alignment flag.

`make` (the alternative, non-CMake build path) takes the same two overrides.

## What was patched to make this compile at all

The codebase is written for Linux/Android and Clang's ELF assembler; a
handful of things don't exist on macOS/Mach-O:

- **`include/sched_compat.h`** (new) — macOS has no `sched_setaffinity(2)`
  family (Apple's scheduler doesn't expose per-thread core pinning or
  placement at all). This header provides drop-in, always-"unsupported"
  stand-ins for `cpu_set_t`/`CPU_ZERO`/`CPU_SET`/`CPU_ISSET`/`sched_getcpu`/
  `sched_setaffinity`/`sched_getaffinity` so the existing affinity code in
  `src/miner.cpp`, `src/algorithm/scrypt_neon.c`, `src/algorithm/verus.cpp`,
  and `src/algorithm/randomx_algo.cpp` compiles unchanged. Every call site
  already treats a failed pin/query as "run unpinned" (this is exactly how
  Android's cpuset denial is already handled), so this is a
  correctness-preserving no-op, not new behavior.
- **`src/algorithm/sha256_ce_asm.S`, `src/algorithm/scrypt_blockmix_asm.S`**
  — hand-written ARMv8 assembly using GNU/ELF-only syntax:
  - `.type`/`.size`/`.section .note.GNU-stack` directives don't exist on
    Mach-O; dropped under `#if !defined(__APPLE__)`.
  - `adrp x7, SYM` / `add x7, x7, :lo12:SYM` GNU-style page addressing
    becomes `adrp x7, SYM@PAGE` / `add x7, x7, SYM@PAGEOFF` on Mach-O.
  - `.section .rodata` becomes `.section __TEXT,__const`.
  - Mach-O prefixes C-callable symbols with `_` (ELF doesn't); a small
    `C_SYM(x)` macro handles this for `sha256d_dual_asm` and
    `scrypt_blockmix_asm`, the two symbols called from C++.
- **`src/algorithm/randomx_algo.cpp`** — a per-thread priority demotion
  during RandomX dataset init uses `syscall(SYS_gettid)`, which is
  Linux-only (and deprecated on macOS); guarded behind `#if
  defined(__linux__)` and simply skipped elsewhere (best-effort already,
  per the existing comment).
- **`build.sh`** — used `nproc` for the parallel build job count, which
  doesn't exist on macOS/BSD. Now falls back through
  `sysctl -n hw.ncpu` / `getconf _NPROCESSORS_ONLN`, mirroring the fallback
  the Makefile already had.

## Verus on Apple Silicon

Verus needed one more fix beyond "compiles": macOS's crypto-capability
detection unconditionally reported no AES/PMULL support
(`src/algorithm/cpu_features.c`'s non-Linux fallback said "assume no crypto
support for safety"), and Verus refuses to run without ARMv8 crypto
extensions. Fixed by adding a macOS branch to `detect_cpu_features()` that
queries the equivalent sysctl flags (`hw.optional.arm.FEAT_AES`,
`hw.optional.arm.FEAT_PMULL`, `hw.optional.neon`) instead of Linux's
`getauxval()`/`HWCAP_*`.

Beyond just running, Verus is also **tuned** for Apple Silicon out of the
box. One of its performance heuristics (fused 64-way dispatch vs. the
per-chain path) normally picks per-core based on `sched_getcpu()` — which
macOS doesn't support, so it silently fell back to the slower path. Measured
on an Apple M1 Max (8 P-cores + 2 E-cores):

| Config | Threads | Hashrate | Δ |
|---|---|---|---|
| fused off (old default) | 8 (P-cores) | 13.82 MH/s | — |
| fused on | 8 (P-cores) | 16.44 MH/s | **+19%** |
| fused off (old default) | 10 (P+E) | 15.33 MH/s | — |
| fused on | 10 (P+E) | 17.47 MH/s | **+14%** |

Fused wins uniformly across both core types (unlike some Android/Linux
cores already in the codebase's tuning table, e.g. Samsung Mongoose M4:
−24%), so `src/algorithm/verus.cpp` now defaults fused **on** for
`__APPLE__` builds. Correctness was checked with the codebase's own
built-in cross-check, not just throughput:

```bash
VERUS_X2_SELFTEST=1 ./primo-arm-miner --algo=verus --benchmark --threads=8
```

This hashes every nonce pair through both the fast path and the trusted
reference path and `abort()`s on any mismatch — it ran clean.

Overrides, same as on Linux:
- `VERUS_FUSE=0` / `VERUS_FUSE=1` — force the dispatch mode.
- `VERUS_X2=0` / `VERUS_X2=1` — force single- vs. dual-nonce interleaving
  (already defaults to `1`/on for unknown topologies, which is independently
  correct for Apple Silicon — both P- and E-cores are out-of-order, unlike
  RK3588's in-order Cortex-A55 "LITTLE" cores).

## Known limitations

- **No CPU pinning / topology tuning.** Affinity calls are no-ops (see
  `sched_compat.h` above) — macOS doesn't expose a pinning API at all, so
  this isn't a regression from some other working state, just a ceiling.
- **rk3588-tuned codegen flags still apply by default.**
  `-mtune=cortex-a53 -mfix-cortex-a53-835769` (from `PRIMO_PROFILE=rk3588`,
  the CMake default) are harmless on Apple Silicon but not tuned for it
  either. Use `cmake -DPRIMO_PROFILE=generic` (or set it via `build.sh`'s
  underlying CMake invocation) to drop the erratum workaround if desired —
  it doesn't change codegen otherwise, since the CLHash hand-asm dispatch is
  already runtime-selected per core.
- **`sha256d` and `scrypt`** were validated for correctness (internal
  self-tests pass, hashrate reported) but not tuned — they use the same
  codegen flags as everywhere else and weren't benchmarked against
  alternate settings the way Verus was.

## Verifying a build

```bash
./primo-arm-miner --algo=sha256d --benchmark --threads=1   # "SHA256d self-test passed"
./primo-arm-miner --algo=scrypt  --benchmark --threads=1   # "Scrypt self-test passed"
./primo-arm-miner --algo=randomx --benchmark --threads=1   # "RandomX self-test passed"
./primo-arm-miner --algo=verus   --benchmark --threads=8   # "Using pure ARM NEON Verus path"
```
