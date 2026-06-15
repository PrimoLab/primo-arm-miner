#!/usr/bin/env bash
# Best-effort no-root Android performance setup for Termux mining.
#
# Run from a desktop/host with adb connected to the phone. Every command is
# best-effort: vendors differ and some Android builds reject individual shell
# app-ops, so failures are logged and skipped rather than fatal.
#
# What this DOES (no root needed): whitelist the app from Doze/background
# restrictions, allow background execution + wake-lock, and keep the screen on
# while charging. What this CANNOT do: remove vendor scheduler/thermal policy.
# Android still places a non-top-app process in a restricted cpuset and can
# uclamp-cap the big cores (see docs: foreground-vs-top-app core withholding).
# The reliable fix for full big-core clocks remains launching the miner from a
# session that lives in top-app — i.e. an `adb shell` / ssh session, or keeping
# the Termux activity focused on screen.
set -u

ADB=${ADB:-adb}
PKG=${TERMUX_PACKAGE:-com.termux}
KEEP_SCREEN_ON=${KEEP_SCREEN_ON:-1}

try() {
  printf '+ %s\n' "$*"
  "$@" || printf '  warning: command failed; continuing\n' >&2
}

command -v "$ADB" >/dev/null 2>&1 || {
  echo "adb not found. Install Android platform-tools or set ADB=/path/to/adb." >&2
  exit 1
}

try "$ADB" devices
try "$ADB" shell cmd deviceidle whitelist "+$PKG"
try "$ADB" shell cmd appops set "$PKG" RUN_IN_BACKGROUND allow
try "$ADB" shell cmd appops set "$PKG" RUN_ANY_IN_BACKGROUND allow
try "$ADB" shell cmd appops set "$PKG" WAKE_LOCK allow
try "$ADB" shell dumpsys deviceidle whitelist

if [ "$KEEP_SCREEN_ON" = "1" ]; then
  # 3 = AC + USB. Shell-writable on many devices; does not require root.
  try "$ADB" shell settings put global stay_on_while_plugged_in 3
fi

try "$ADB" shell am start -n "$PKG/.app.TermuxActivity"

cat <<'EOF'

On the phone, also run inside Termux before starting the miner:
  termux-wake-lock

For full big-core clocks, start the miner from a top-app session (adb shell or
ssh into Termux), or keep the Termux activity visible while benchmarking. This
script whitelists Doze/background execution but cannot override vendor
scheduler/thermal policy.
EOF
