#!/data/data/com.termux/files/usr/bin/bash
#
# Build minimal STATIC libjansson + libcurl on an Android phone (Termux) so the
# miner can be relinked into a self-contained binary for the APK. The Termux
# .so builds drag in libcurl's whole shared tree (libcrypto.so.3 etc., ~8 MB,
# versioned SONAMEs that can't be packaged in an APK). Static + TCP-only avoids
# all of that: pools are stratum+tcp:// so no TLS/http2/ssh/ldap is needed.
#
# Output: static archives + headers under $SDEPS (default ~/primo-sdeps).
#   $SDEPS/lib/libcurl.a  $SDEPS/lib/libjansson.a  $SDEPS/include/...
set -euo pipefail

SDEPS="${SDEPS:-$HOME/primo-sdeps}"
SRC="${SRC:-$HOME/primo-sdeps-src}"
JANSSON_VER="${JANSSON_VER:-2.14}"
CURL_VER="${CURL_VER:-8.11.1}"
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

# --- curl (static, TCP-only, no TLS/http2/ssh/ldap) --------------------------
if [ ! -f "$SDEPS/lib/libcurl.a" ]; then
  say "building curl $CURL_VER (static, minimal)"
  cd "$SRC"
  [ -f "curl-$CURL_VER.tar.gz" ] || \
    wget -q "https://curl.se/download/curl-$CURL_VER.tar.gz"
  rm -rf "curl-$CURL_VER"; tar xf "curl-$CURL_VER.tar.gz"
  cd "curl-$CURL_VER"
  ./configure --prefix="$SDEPS" \
    --enable-static --disable-shared \
    --without-ssl --without-gnutls --without-mbedtls \
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
ls -l "$SDEPS/lib/libcurl.a" "$SDEPS/lib/libjansson.a"
