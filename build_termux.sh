#!/usr/bin/env bash
# Build primo-arm-miner natively in Termux on Android.
# Run from the repo root: bash build_termux.sh
set -euo pipefail

BINARY="primo-arm-miner"
MAKEFILE_ORIG="Makefile.termux-orig"

die()  { echo "Error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────

[ -f Makefile ] && [ -f src/miner.cpp ] \
    || die "Run this script from the primo-arm-miner repo root"

# ── Dependencies ──────────────────────────────────────────────────────────────

info "Installing build dependencies..."
pkg update -y
pkg install -y clang lld make curl libjansson openssl

# ── Resolve compiler ──────────────────────────────────────────────────────────
#
# If CLANG_PREFIX is set (e.g. from build_clang16_termux.sh), use that clang.
# Otherwise fall back to whatever 'clang' is on PATH (Termux default).

if [ -n "${CLANG_PREFIX:-}" ]; then
    CLANG_BIN="$CLANG_PREFIX/bin/clang"
    CLANGXX_BIN="$CLANG_PREFIX/bin/clang++"
    LLD_BIN="$CLANG_PREFIX/bin/ld.lld"
    [ -x "$CLANG_BIN" ] || die "CLANG_PREFIX set but $CLANG_BIN not found"
    info "Using CLANG_PREFIX: $CLANG_PREFIX"

    # A clang built from source doesn't have the Termux sysroot path baked in.
    # Wrap it so every invocation gets --sysroot automatically.
    TERMUX_USR="${PREFIX:-/data/data/com.termux/files/usr}"
    WRAPPER_DIR="$(pwd)/.clang16-wrappers"
    mkdir -p "$WRAPPER_DIR"
    printf '#!/bin/sh\nexec "%s" --sysroot="%s" "$@"\n' \
        "$CLANG_BIN" "$TERMUX_USR" > "$WRAPPER_DIR/clang"
    printf '#!/bin/sh\nexec "%s" --sysroot="%s" "$@"\n' \
        "$CLANGXX_BIN" "$TERMUX_USR" > "$WRAPPER_DIR/clang++"
    chmod +x "$WRAPPER_DIR/clang" "$WRAPPER_DIR/clang++"
    CLANG_BIN="$WRAPPER_DIR/clang"
    CLANGXX_BIN="$WRAPPER_DIR/clang++"
else
    CLANG_BIN=clang
    CLANGXX_BIN=clang++
    LLD_BIN=lld
fi

CLANG_MAJOR=$("$CLANG_BIN" --version 2>/dev/null \
    | grep -oE 'clang version [0-9]+' \
    | grep -oE '[0-9]+$' \
    || echo 0)
info "Detected clang $CLANG_MAJOR"

# ── Patch Makefile for Android/Termux ────────────────────────────────────────
#
# Two things need fixing vs the default Makefile:
#
#   1. -Wl,-hugetlbfs-align  — Linux hugetlbfs page-alignment hint; the
#      Android kernel does not support hugetlbfs so the linker rejects it.
#
#   2. -ffinite-loops         — Needs clang 13+. Termux ships 17+ today but
#      guard it anyway.
#
# The Makefile's CC/CXX are overridden on the make command line (it uses
# $(origin) guards), so no patching is needed for the compiler name.
# PRIMO_LINKER=lld is passed explicitly to keep LTO working via lld.

# Save the original once (idempotent — subsequent runs regenerate from it)
[ -f "$MAKEFILE_ORIG" ] || cp Makefile "$MAKEFILE_ORIG"

info "Patching Makefile for Termux..."
sed \
    -e '/-Wl,-hugetlbfs-align/d' \
    -e 's/-march=armv8-a+crypto/-march=armv8-a+crypto+sha2+crc/' \
    -e 's/-O3/-Ofast/' \
    -e 's/-falign-functions=16/-falign-functions=64 -finline-functions/' \
    "$MAKEFILE_ORIG" > Makefile

if [ "$CLANG_MAJOR" -lt 13 ]; then
    info "clang $CLANG_MAJOR: removing unsupported -ffinite-loops"
    sed -i 's/-ffinite-loops[[:space:]]*//' Makefile
fi

# ── Build ─────────────────────────────────────────────────────────────────────

JOBS=$(nproc 2>/dev/null || echo 4)
info "Building with $JOBS parallel jobs..."

make clean
make -j"$JOBS" CC="$CLANG_BIN" CXX="$CLANGXX_BIN" PRIMO_LINKER="$LLD_BIN"

# ── Done ──────────────────────────────────────────────────────────────────────

SIZE=$(du -h "$BINARY" 2>/dev/null | cut -f1 || echo "?")
echo ""
info "Build complete: ./$BINARY  ($SIZE)"
echo ""
echo "Example commands:"
echo "  Verus:   ./$BINARY -a verus   -o stratum+tcp://pool.verus.io:9998 -u WALLET.worker -t $JOBS"
echo "  SHA256d: ./$BINARY -a sha256d -o stratum+tcp://POOL:PORT -u USER.worker -t $JOBS"
echo "  Scrypt:  ./$BINARY -a scrypt  -o stratum+tcp://POOL:PORT -u USER.worker -t $JOBS"
echo ""
echo "Note: -mtune=cortex-a53 is in the Makefile — validated for heterogeneous SoCs"
echo "(RK3588, SD855). Edit BASE_ARCH_FLAGS to change tuning."
echo ""
echo "To use clang-16 (recommended — empirically faster on ARM):"
echo "  CLANG_PREFIX=\$HOME/clang-16 bash build_termux.sh"
echo "Build clang-16 from source: bash build_clang16_termux.sh  (~2-4 hours)"
