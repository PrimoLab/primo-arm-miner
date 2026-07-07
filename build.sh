#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
ROOT_BINARY="$SCRIPT_DIR/primo-arm-miner"
CMAKE_BIN="${CMAKE:-cmake}"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

cmake_args=(
    -S "$SCRIPT_DIR"
    -B "$BUILD_DIR"
    -DCMAKE_BUILD_TYPE=Release
)

if [[ -n "${CC:-}" ]]; then
    cmake_args+=("-DCMAKE_C_COMPILER=$CC")
fi

if [[ -n "${CXX:-}" ]]; then
    cmake_args+=("-DCMAKE_CXX_COMPILER=$CXX")
fi

if [[ "${PRIMO_LINKER+x}" == "x" ]]; then
    cmake_args+=("-DPRIMO_LINKER=$PRIMO_LINKER")
fi

"$CMAKE_BIN" "${cmake_args[@]}"

NPROC="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
"$CMAKE_BIN" --build "$BUILD_DIR" -j"$NPROC"

install -m 755 "$BUILD_DIR/primo-arm-miner" "$ROOT_BINARY"

echo "Build complete! Binary: $ROOT_BINARY"
echo "Size: $(ls -lh "$ROOT_BINARY" | awk '{print $5}')"
