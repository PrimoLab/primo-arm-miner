#!/bin/sh
# primo-arm-miner installer — Linux arm64 SBCs and Termux (Android).
#
#   curl -fsSL https://raw.githubusercontent.com/PrimoLab/primo-arm-miner/master/install.sh | sh
#
# Downloads the latest release binary for this platform, installs runtime
# dependencies where a known package manager is available, and prints a
# mining quickstart. POSIX sh — no bash required (Termux ships bash, but
# minimal SBC images may not).
#
# Environment overrides:
#   PRIMO_REPO          GitHub repo slug (default below)
#   PRIMO_INSTALL_DIR   Target directory for the binary
#   PRIMO_DOWNLOAD_URL  Full tarball URL (testing / mirrors)
set -eu

PRIMO_REPO="${PRIMO_REPO:-PrimoLab/primo-arm-miner}"
BINARY="primo-arm-miner"

info() { printf '==> %s\n' "$*"; }
warn() { printf 'Warning: %s\n' "$*" >&2; }
die()  { printf 'Error: %s\n' "$*" >&2; exit 1; }

# ── Platform detection ───────────────────────────────────────────────────────

ARCH="$(uname -m)"
case "$ARCH" in
    aarch64|arm64) ;;
    armv7*|armv6*)
        die "32-bit ARM is not supported: primo-arm-miner requires ARMv8 crypto extensions (AES/PMULL/SHA2). A 64-bit OS on an ARMv8 CPU is required." ;;
    *)
        die "Unsupported architecture '$ARCH' — primo-arm-miner is ARM64-only." ;;
esac

IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ]; then
    IS_TERMUX=1
else
    case "${PREFIX:-}" in
        */com.termux/*) IS_TERMUX=1 ;;
    esac
fi

# Crypto-extension sanity check (warn-only: some kernels hide the Features
# line for offline cores, and the miner re-checks properly at startup).
if [ -r /proc/cpuinfo ] && ! grep -iqw aes /proc/cpuinfo; then
    warn "/proc/cpuinfo does not list the 'aes' feature — if this CPU lacks ARMv8 crypto extensions the miner will refuse to start."
fi

if [ "$IS_TERMUX" = 1 ]; then
    ASSET="primo-arm-miner-android-arm64.tar.gz"
    DEFAULT_DIR="${PREFIX:-/data/data/com.termux/files/usr}/bin"
else
    ASSET="primo-arm-miner-linux-arm64.tar.gz"
    DEFAULT_DIR="/usr/local/bin"
fi
INSTALL_DIR="${PRIMO_INSTALL_DIR:-$DEFAULT_DIR}"
URL="${PRIMO_DOWNLOAD_URL:-https://github.com/$PRIMO_REPO/releases/latest/download/$ASSET}"

# ── Runtime dependencies ─────────────────────────────────────────────────────

install_deps() {
    if [ "$IS_TERMUX" = 1 ]; then
        info "Installing runtime libraries (libcurl, libjansson, openssl)..."
        pkg install -y --no-upgrade libcurl libjansson openssl \
            || warn "pkg install failed — if the miner won't start, run: pkg install libcurl libjansson openssl"
        return
    fi

    if command -v apt-get >/dev/null 2>&1; then
        info "Installing runtime libraries via apt..."
        SUDO=""
        [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
        $SUDO apt-get install -y libcurl4 libjansson4 \
            || warn "apt install failed — if the miner won't start, install libcurl4 and libjansson4 manually"
    else
        warn "No supported package manager found. The miner needs runtime libraries: libcurl, libjansson, libssl/libcrypto."
    fi
}

# ── Download and install ─────────────────────────────────────────────────────

TMPDIR_DL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_DL"' EXIT

info "Downloading $ASSET..."
info "  from: $URL"
# Enforce https for the default GitHub URL; an explicit PRIMO_DOWNLOAD_URL
# override (testing, local mirrors) is the user's own transport choice.
if [ -n "${PRIMO_DOWNLOAD_URL:-}" ]; then
    CURL_PROTO=""
else
    CURL_PROTO="--proto =https"
fi
# shellcheck disable=SC2086 — CURL_PROTO is intentionally word-split
curl -fL $CURL_PROTO --retry 3 -o "$TMPDIR_DL/$ASSET" "$URL" \
    || die "Download failed. Check the URL above (no release published yet?) or set PRIMO_DOWNLOAD_URL."

tar -xzf "$TMPDIR_DL/$ASSET" -C "$TMPDIR_DL" || die "Failed to extract $ASSET"
[ -f "$TMPDIR_DL/$BINARY" ] || die "Archive did not contain the $BINARY binary"

install_deps

info "Installing to $INSTALL_DIR/$BINARY..."
if mkdir -p "$INSTALL_DIR" 2>/dev/null && [ -w "$INSTALL_DIR" ]; then
    install -m 755 "$TMPDIR_DL/$BINARY" "$INSTALL_DIR/$BINARY"
elif command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p "$INSTALL_DIR"
    sudo install -m 755 "$TMPDIR_DL/$BINARY" "$INSTALL_DIR/$BINARY"
else
    INSTALL_DIR="$HOME/.local/bin"
    warn "No write access to the default location — installing to $INSTALL_DIR instead (make sure it is on your PATH)"
    mkdir -p "$INSTALL_DIR"
    install -m 755 "$TMPDIR_DL/$BINARY" "$INSTALL_DIR/$BINARY"
fi

"$INSTALL_DIR/$BINARY" --version >/dev/null 2>&1 \
    || die "Installed binary failed to run — likely missing runtime libraries (see warnings above)."

VERSION_LINE="$("$INSTALL_DIR/$BINARY" --version 2>/dev/null | head -1)"
info "Installed: $VERSION_LINE"

# ── Quickstart ───────────────────────────────────────────────────────────────

cat <<EOF

  Quickstart — mine Verus (replace the wallet address with yours):

    $BINARY -a verus -o stratum+tcp://pool.verus.io:9998 \\
        -u YOUR_VRSC_ADDRESS.worker -p x

  Other algorithms:  -a sha256d (Bitcoin)   -a scrypt (Litecoin)
  Benchmark:         $BINARY --benchmark
  Config file:       $BINARY -c config.json   (ccminer-compatible format;
                     see CONFIG_EXAMPLES.md in the release archive)

  Threads, big/LITTLE core pinning, and per-core optimizations are
  auto-detected — no tuning flags needed.
EOF
