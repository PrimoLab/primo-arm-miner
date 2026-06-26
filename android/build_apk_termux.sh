#!/data/data/com.termux/files/usr/bin/bash
#
# Build the Primo ARM Miner APK *on an Android phone in Termux* (aarch64-native),
# bypassing Gradle/AGP entirely with the raw aapt2 -> kotlinc -> d8 -> apksigner
# pipeline. AGP in Termux is painful (it pulls x86 aapt2/d8 + wants a full SDK);
# this uses Termux's native tools directly.
#
# One-time deps:
#   pkg install openjdk-17 kotlin aapt2 d8 apksigner android-tools zip
#
# Inputs you must stage first:
#   1. Build the native miner (Android/bionic arm64) with the repo's
#      build_termux.sh, then copy it in renamed as a .so:
#        cp ../primo-arm-miner app/src/main/jniLibs/arm64-v8a/libprimo.so
#   2. android.jar (API 33) — NOT a Termux package; fetched automatically below
#      from a public platforms mirror into ~/.primo-android-sdk/ (override with
#      ANDROID_JAR=/path/to/android.jar).
#
# Output: build/primo-arm-miner.apk (debug-signed; install with `adb install` or tap).
set -euo pipefail

API=33
PKG=dev.primolab.miner
HERE=$(cd "$(dirname "$0")" && pwd)
APP="$HERE/app/src/main"
OUT="$HERE/build"
GEN="$OUT/gen"
CLASSES="$OUT/classes"
SDK_CACHE="${SDK_CACHE:-$HOME/.primo-android-sdk}"
ANDROID_JAR="${ANDROID_JAR:-$SDK_CACHE/android-$API/android.jar}"
JNILIB="$APP/jniLibs/arm64-v8a/libprimo.so"
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight ---------------------------------------------------------------
for t in aapt2 d8 apksigner zipalign kotlinc keytool javac zip; do
  command -v "$t" >/dev/null 2>&1 || die "missing '$t' — run: pkg install openjdk-17 kotlin aapt2 d8 apksigner android-tools zip"
done
[ -f "$JNILIB" ] || die "native miner not staged at $JNILIB (see header step 1)"

# kotlin-stdlib must be on the dex; locate the Termux copy.
KOTLIN_STDLIB=$(find "$PREFIX" -name 'kotlin-stdlib.jar' 2>/dev/null | head -1)
[ -n "$KOTLIN_STDLIB" ] || die "kotlin-stdlib.jar not found under \$PREFIX (pkg install kotlin)"

# --- android.jar (platform stub) --------------------------------------------
if [ ! -f "$ANDROID_JAR" ]; then
  say "fetching android.jar API $API (one-time)…"
  mkdir -p "$(dirname "$ANDROID_JAR")"
  URL="https://raw.githubusercontent.com/Sable/android-platforms/master/android-$API/android.jar"
  curl -fSL "$URL" -o "$ANDROID_JAR" || die "could not download android.jar — set ANDROID_JAR=/path/to/android.jar"
fi

# --- clean -------------------------------------------------------------------
rm -rf "$OUT"
mkdir -p "$GEN" "$CLASSES" "$OUT/apk"

# --- 1. resources: compile + link (emits R.java + a resources-only APK) ------
say "aapt2: compiling resources"
aapt2 compile --dir "$APP/res" -o "$OUT/res.zip"

say "aapt2: linking"
aapt2 link \
  -I "$ANDROID_JAR" \
  --manifest "$APP/AndroidManifest.xml" \
  --java "$GEN" \
  --min-sdk-version 24 \
  --target-sdk-version "$API" \
  -o "$OUT/base.apk" \
  "$OUT/res.zip"

# --- 2. compile R.java (javac) + Kotlin sources (kotlinc) --------------------
# NB: Termux's default JDK is 21 and d8 (build-tools 33) only fully supports
# Java 11 bytecode (class 55), so pin both compilers to 11.
say "javac: R.java"
javac --release 11 -d "$CLASSES" -classpath "$ANDROID_JAR" $(find "$GEN" -name '*.java')

say "kotlinc: app sources"
kotlinc \
  -classpath "$ANDROID_JAR:$CLASSES" \
  -d "$CLASSES" \
  -jvm-target 11 \
  $(find "$APP/kotlin" -name '*.kt')

# --- 3. dex (d8) -------------------------------------------------------------
say "d8: classes -> dex"
d8 --min-api 24 --lib "$ANDROID_JAR" --output "$OUT/apk" \
  "$KOTLIN_STDLIB" \
  $(find "$CLASSES" -name '*.class')

# --- 4. assemble APK: base resources + dex + native libs ---------------------
say "assembling apk"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
( cd "$OUT/apk" && zip -q "$OUT/unsigned.apk" classes.dex )
# Bundle EVERY lib*.so staged in jniLibs/arm64-v8a (libprimo.so + its remaining
# dynamic deps, e.g. libc++.so). Must be named lib*.so to be APK-packageable.
JNILIB_DIR="$APP/jniLibs/arm64-v8a"
mkdir -p "$OUT/lib/arm64-v8a"
cp "$JNILIB_DIR"/*.so "$OUT/lib/arm64-v8a/"
( cd "$OUT" && zip -q "$OUT/unsigned.apk" lib/arm64-v8a/*.so )

# --- 5. align + sign ---------------------------------------------------------
KEYSTORE="$SDK_CACHE/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
  say "generating debug keystore"
  keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android \
    -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Primo Debug,O=PrimoLab,C=US"
fi

say "zipalign"
zipalign -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"

say "apksigner"
apksigner sign \
  --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
  --out "$OUT/primo-arm-miner.apk" "$OUT/aligned.apk"

say "done -> $OUT/primo-arm-miner.apk"
apksigner verify --print-certs "$OUT/primo-arm-miner.apk" >/dev/null && say "signature OK"
