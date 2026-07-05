#!/data/data/com.termux/files/usr/bin/bash
#
# Build minimal STATIC libjansson + mbedTLS + libcurl on an Android phone
# (Termux) so the miner can be relinked into a self-contained binary for the
# APK. The Termux .so builds drag in libcurl's whole shared tree
# (libcrypto.so.3 etc., ~8 MB, versioned SONAMEs that can't be packaged in an
# APK). Static avoids all of that. TLS comes from a static mbedTLS (small,
# cross-friendly) so stratum+ssl:// pools work in-app; NOT OpenSSL — the
# no-OpenSSL rule stands, and no CA bundle is needed because the miner does
# not verify pool certificates (self-signed everywhere; see INTERNALS.md).
#
# Output: static archives + headers under $SDEPS (default ~/primo-sdeps).
#   $SDEPS/lib/libcurl.a libjansson.a libmbedtls.a libmbedx509.a libmbedcrypto.a
set -euo pipefail

SDEPS="${SDEPS:-$HOME/primo-sdeps}"
SRC="${SRC:-$HOME/primo-sdeps-src}"
JANSSON_VER="${JANSSON_VER:-2.14}"
CURL_VER="${CURL_VER:-8.11.1}"
MBEDTLS_VER="${MBEDTLS_VER:-3.6.2}"
JOBS="$(nproc 2>/dev/null || echo 4)"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
mkdir -p "$SDEPS" "$SRC"

# --- jansson (static) --------------------------------------------------------
if [ ! -f "$SDEPS/lib/libjansson.a" ]; then
  say "building jansson $JANSSON_VER (static)"
  cd "$SRC"
  [ -f "jansson-$JANSSON_VER.tar.gz" ] || \
    wget -q "https://github.com/akheron/jansson/releases/download/v$JANSSON_VER/jansson-$JANSSON_VER.tar.gz"
  rm -rf "jansson-$JANSSON_VER"; tar xf "jansson-$JANSSON_VER.tar.gz"
  cd "jansson-$JANSSON_VER"
  ./configure --prefix="$SDEPS" --enable-static --disable-shared >/dev/null
  make -j"$JOBS" >/dev/null && make install >/dev/null
fi

# --- mbedTLS (static) ---------------------------------------------------------
if [ ! -f "$SDEPS/lib/libmbedtls.a" ]; then
  say "building mbedTLS $MBEDTLS_VER (static)"
  command -v cmake >/dev/null 2>&1 || { echo "ERROR: cmake needed for mbedTLS (pkg install cmake)" >&2; exit 1; }
  cd "$SRC"
  [ -f "mbedtls-$MBEDTLS_VER.tar.bz2" ] || \
    wget -q "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$MBEDTLS_VER/mbedtls-$MBEDTLS_VER.tar.bz2"
  rm -rf "mbedtls-$MBEDTLS_VER"; tar xf "mbedtls-$MBEDTLS_VER.tar.bz2"
  cd "mbedtls-$MBEDTLS_VER"
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$SDEPS" \
    -DENABLE_TESTING=Off -DENABLE_PROGRAMS=Off \
    -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DUSE_STATIC_MBEDTLS_LIBRARY=On >/dev/null
  cmake --build build -j"$JOBS" >/dev/null
  cmake --install build >/dev/null
fi

# --- curl (static, mbedTLS, no http2/ssh/ldap) --------------------------------
# Rebuild an existing TCP-only libcurl.a from before the TLS change: the .pc
# records mbedtls in Libs.private only when curl was configured with it.
if [ ! -f "$SDEPS/lib/libcurl.a" ] || \
   ! grep -q mbedtls "$SDEPS/lib/pkgconfig/libcurl.pc" 2>/dev/null; then
  say "building curl $CURL_VER (static, mbedTLS)"
  cd "$SRC"
  [ -f "curl-$CURL_VER.tar.gz" ] || \
    wget -q "https://curl.se/download/curl-$CURL_VER.tar.gz"
  rm -rf "curl-$CURL_VER"; tar xf "curl-$CURL_VER.tar.gz"
  cd "curl-$CURL_VER"
  ./configure --prefix="$SDEPS" \
    --enable-static --disable-shared \
    --without-ssl --without-gnutls --with-mbedtls="$SDEPS" \
    --without-ca-bundle --without-ca-path \
    --without-nghttp2 --without-ngtcp2 --without-libssh2 --without-librtmp \
    --without-brotli --without-zstd --without-zlib \
    --without-libidn2 --without-libpsl \
    --disable-ldap --disable-ldaps --disable-rtsp --disable-dict \
    --disable-telnet --disable-tftp --disable-pop3 --disable-imap \
    --disable-smtp --disable-gopher --disable-mqtt --disable-smb \
    --disable-manual --disable-docs >/dev/null
  make -j"$JOBS" >/dev/null && make install >/dev/null
fi

say "done:"
ls -l "$SDEPS/lib/libcurl.a" "$SDEPS/lib/libjansson.a" \
      "$SDEPS/lib/libmbedtls.a" "$SDEPS/lib/libmbedx509.a" "$SDEPS/lib/libmbedcrypto.a"
