#!/data/data/com.termux/files/usr/bin/bash
#
# Build a SELF-CONTAINED Android miner binary for the APK and stage it (+ libc++)
# into jniLibs. The stock build_termux.sh binary dynamically links Termux's
# libcurl/libjansson/libc++ — none present in the app sandbox. This relinks the
# miner against STATIC curl + jansson (build_static_deps_termux.sh) so the only
# remaining dynamic deps are bionic system libs + libc++, which we bundle.
#
# Run from anywhere; resolves the repo root itself. Verified on a rooted S10+:
# resulting binary mines in-app at ~30-39 MH/s sha256d.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
SDEPS="${SDEPS:-$HOME/primo-sdeps}"
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
JNI="$ROOT/android/app/src/main/jniLibs/arm64-v8a"

# 1. static curl + jansson
bash "$ROOT/android/build_static_deps_termux.sh"

# 2. sysroot-aware clang-16 wrappers (minted by build_termux.sh on first run)
W="$ROOT/.clang16-wrappers"
if [ ! -x "$W/clang++" ]; then
  echo "==> minting clang-16 wrappers via build_termux.sh"
  CLANG_PREFIX="${CLANG_PREFIX:-$HOME/clang-16}" bash "$ROOT/build_termux.sh"
fi

# 3. compile against the static-dep headers (the make link step is a throwaway —
#    it links dynamically and may fail; we relink static next). A nonzero make
#    is tolerated ONLY for the link step: verify below that every source
#    actually produced its object, so a real compile error fails loudly here
#    instead of surfacing as a confusing relink failure.
echo "==> compiling miner objects"
make clean >/dev/null 2>&1 || true
make -j"$(nproc)" \
  CC="$W/clang" CXX="$W/clang++" PRIMO_LINKER=lld \
  PRIMO_HUGETLBFS=0 PRIMO_A53_ERRATA=0 \
  PRIMO_EXTRA_CFLAGS="-I$SDEPS/include -DCURL_STATICLIB" \
  PRIMO_EXTRA_CXXFLAGS="-I$SDEPS/include -DCURL_STATICLIB" \
  || echo "==> make exited nonzero (OK if only the throwaway link failed) — verifying objects"
missing=0
for s in src/*.cpp src/utils/*.cpp src/algorithm/*.c src/algorithm/*.S; do
  [ -e "$s" ] || continue
  o="${s%.*}.o"
  if [ ! -f "$o" ]; then
    echo "ERROR: compile failed — missing $o" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 1

# 4. relink explicitly against the static archives. (The Makefile's
#    PRIMO_LDLIBS_OVERRIDE didn't survive being passed over SSH; an explicit
#    relink is unambiguous. Objects are LTO bitcode — lld links them fine.)
echo "==> relinking static"
"$W/clang++" $(ls src/*.o src/utils/*.o src/algorithm/*.o) \
  -flto -pthread -fuse-ld=lld \
  "$SDEPS/lib/libcurl.a" "$SDEPS/lib/libjansson.a" -lm \
  -o primo-arm-miner

echo "==> NEEDED (want only libm/libc++/libdl/libc):"
readelf -d primo-arm-miner | grep NEEDED

# 5. stage libprimo.so + libc++.so (bundled under the NEEDED name) into jniLibs
mkdir -p "$JNI"
cp primo-arm-miner "$JNI/libprimo.so"
cp "$PREFIX/lib/libc++_shared.so" "$JNI/libc++.so"
echo "==> staged $JNI/{libprimo.so,libc++.so}"
echo "==> now: cd android && bash build_apk_termux.sh"
