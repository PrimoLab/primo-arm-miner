# Primo ARM Miner — Android APK (Milestone 1)

A thin Android wrapper around the existing native miner. **No miner rewrite** —
the same C++ binary runs as a foreground-service subprocess, and the UI just
talks to its read-only API on `127.0.0.1:4068`.

## Architecture

```
┌─────────────────────────────────────────────┐
│  APK                                          │
│  ┌─────────────┐   ┌──────────────────────┐  │
│  │ MiningActivity│  │ ConfigActivity        │ │
│  │ start/stop +  │  │ algo/url/user/pass/   │ │
│  │ live stats    │  │ threads -> config.json│ │
│  └──────┬──────┘   └──────────┬───────────┘  │
│         │ poll 4068           │ write          │
│         ▼                     ▼               │
│  ┌──────────────────────────────────────┐    │
│  │ MinerService (foreground + wakelock)  │    │
│  │   exec nativeLibDir/libprimo.so       │    │
│  │       -c config.json --api-bind ...   │    │
│  └──────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

- The miner ships **inside the APK as `lib/arm64-v8a/libprimo.so`**. Naming it
  `lib*.so` + `extractNativeLibs="true"` lands it in `nativeLibraryDir`, the one
  app directory Android mounts executable — so we can `exec()` it directly.
  This sidesteps W^X / exec-from-data restrictions on modern targetSdk.
- UI is **plain Android framework Views (no Jetpack Compose / no AndroidX)** so
  the whole thing builds on-device in Termux without Gradle/AGP.

## Build (on an Android phone, over SSH, in Termux)

This is the intended build host — Termux ships native-aarch64 versions of the
whole APK toolchain, whereas the standard NDK/aapt2/d8 are x86_64-only.

```bash
# 1. one-time toolchain
pkg install openjdk-17 kotlin aapt2 d8 apksigner android-tools zip

# 2. build a SELF-CONTAINED native miner (static curl+jansson) and stage it +
#    libc++ into jniLibs. The stock build_termux.sh binary is NOT usable in the
#    APK — it dynamically links Termux's libcurl/jansson/libc++ (see notes below).
bash android/build_native_termux.sh

# 3. build + sign the APK
cd android && bash build_apk_termux.sh
# -> android/build/primo-arm-miner.apk  (debug-signed)
```

### Why the native build is special
- The APK binary must depend only on **bionic system libs** (+ a bundled
  `libc++.so`). `build_native_termux.sh` builds **static** libcurl (TCP-only:
  `--without-ssl` etc. — pools are `stratum+tcp://`) + static libjansson via
  `build_static_deps_termux.sh`, then relinks the miner against them.
- **DNS:** the app sandbox blocks `getaddrinfo` from a raw native subprocess
  ("Could not resolve host"), even though TCP works. `MinerService` resolves the
  pool host on the JVM side and launches the miner with the IP
  (`config.runtime.json`); `stratum+tcp` needs no hostname.

Install: `adb install -r android/build/primo-arm-miner.apk`, or copy to the
phone and tap it (enable "install unknown apps").

## Pool configuration notes

### Merged mining (Litecoin + Dogecoin, scrypt)

LTC+DOGE merged mining is handled **entirely by the pool** (AuxPoW) — the scrypt
miner needs no special mode and there is no separate "merge mining" field in the
app. You enable it purely through **the pool you point at and your login / worker
name**:

1. Choose a pool that does LTC+DOGE merged mining (e.g. litecoinpool.org,
   prohashing, aikapool, or any "scrypt merge" pool).
2. In **Config**, set algorithm = `scrypt` and the pool's `stratum+tcp://…` URL.
3. Put your credentials in **WALLET / USER.WORKER** exactly how that pool wants
   them — this is where merged mining is actually configured:
   - **Account-based pools** (litecoinpool.org, prohashing): the user field is
     your *site username*, e.g. `myaccount.worker1`. Your LTC **and** DOGE payout
     addresses are set on the pool's website; both coins are credited
     automatically from the same scrypt shares.
   - **Address-based pools**: the user field is your LTC address plus a worker,
     e.g. `Lxxxxxxxx.rig1`. If the pool also wants a DOGE address it's typically
     given on their site or appended to the worker/password per their docs.

The miner just submits scrypt shares; the pool splits the reward across LTC and
DOGE. So "set it up correctly on the pool side, mine normally" is the whole flow.

### Network monitoring (API on the LAN)

The dashboard always reads the miner's read-only status API on `127.0.0.1:4068`.
The **Allow network monitoring** checkbox in Config controls the *bind address*:

- **off** (default): API binds `127.0.0.1` — reachable only from this phone.
- **on**: API binds `0.0.0.0` — other devices on the same wifi can query it,
  e.g. a desktop ccminer-compatible monitor at `http://<phone-ip>:4068`. It stays
  **read-only** (summary / threads / pool / hwinfo, etc. — no control commands).

Takes effect the next time mining starts.

## Status / TODO

**Core path validated end-to-end on a rooted Galaxy S10+ (Exynos 9820, 2026-06-25)
— mines in-app at ~30-39 MH/s sha256d with the API live.**
- [x] Scaffold: manifest, 2 activities, foreground service, API client, build script
- [x] On-device build pipeline (aapt2 → javac → kotlinc → d8 → zipalign →
      apksigner). Needed: JDK-11 bytecode (`--release 11` / `-jvm-target 11`, since
      Termux defaults to JDK 21 and d8/build-tools 33 only supports Java 11) + `zip`.
- [x] APK installs; foreground service execs the binary from `nativeLibraryDir`.
- [x] **Self-contained native binary** via static curl+jansson + bundled libc++
      (`build_native_termux.sh`). NEEDED = libm/libc++/libdl/libc only.
- [x] **DNS** resolved JVM-side, miner launched with pool IP.
- [x] Config UX: algorithm is a **dropdown**; each algo keeps its own
      pool/user/pass/threads (`profiles.json`) so switching algos repopulates that
      algo's data. Existing config.json auto-migrated. Miner unchanged (still reads
      one flat config.json, written from the active algo on SAVE).
- [x] **Dark dashboard home page** (custom theme, teal accent): big hashrate,
      algo/pool, live per-thread chips (from `threads`), stat grid (accepted/
      rejected/difficulty/uptime/max-hash/temp/battery/charge), Start/Stop pill.
      Config moved to a **cog in the action bar** (no more button). Battery/charge
      from Android `BatteryManager`; everything else from the 4068 API.
- [x] Mining confirmed: stratum connect/authorize/work + 4068 API summary.
- [x] minSdk 24 (Android 7+), arm64-v8a only — installs on essentially any ARMv8 phone.
- [x] **Full-speed-while-foreground (no root):** the mining screen sets
      `FLAG_KEEP_SCREEN_ON`, so a focused on-screen app stays `top-app` = all cores
      + uclamp boost. This is the no-root performance ceiling.
- [x] Battery-optimization exemption request (so OEMs don't reap the service).
- [x] **Root booster (STUB):** `RootBooster` moves the miner into the `top-app`
      cpuset on rooted devices = full cores even backgrounded/screen-off. No-op
      without root. Confirmed working on the magisk S10+. TODO: periodic re-assert
      + a UI toggle.
- [x] **App icon** — teal CPU-chip + bolt, authored as a vector (no bitmaps):
      adaptive icon (`mipmap-anydpi-v26`) + layer-list fallback (`mipmap-anydpi`)
      so it works API 24+. Verified rendering on-device.
- [ ] POST_NOTIFICATIONS runtime request (Android 13+) so the notification shows
- [ ] targetSdk 34 needs a real `foregroundServiceType` justification (currently
      `dataSync` at targetSdk 33)
- [ ] **First-launch disclaimer dialog**: state what the app does (a cryptocurrency
      CPU miner) and that it takes a **dev fee** (2% verus / 1% sha256d+scrypt,
      time-sliced — see `src/dev_fee.cpp`), with a **"Don't show again"** checkbox
      (persist a flag like `lanApi`; show from `MiningActivity` until dismissed).
      For honesty + sideload/Play-Protect trust + fee disclosure.
- [ ] Test on a NON-rooted device (Note 20 Ultra; debug-signed APK ready) —
      install by tap, start via the UI button (the root `pm install`/`am` path was
      just the test harness). Expect background throttling ("N of M CPUs" + uclamp);
      full speed only while on-screen.
- [x] Per-thread / temp view (poll `threads` + `hwinfo` API commands)
- [x] **Thread chips wrap to centered rows** for >8-thread phones (10/12-core),
      with status as a colored pill (mining/connecting) and threshold-colored temp.
- [x] **Optional LAN API** — a Config checkbox binds the status API to `0.0.0.0`
      for remote ccminer-compatible monitoring (default stays `127.0.0.1`).
- [x] **Settings cog** replaces the framework wrench in the action bar (vector).
- [x] **In-app log viewer** (`LogActivity`): read-only tail of the miner's
      `miner.log` (drained native stdout), ANSI-stripped, 2s auto-refresh, opened
      from a log icon beside the cog. Useful for diagnosing on non-rooted devices
      without `adb logcat`.
- [x] **IPv6 pool fix**: pool hosts that resolve to IPv6 were producing an
      unparseable `stratum+tcp://<v6>:port` URL (silent connect-retry loop, UI
      stuck "connecting"). `MinerService` now prefers an IPv4 address, bracketing
      IPv6 (`[addr]:port`) only when that's all a host offers.
- [ ] Release signing keystore (separate from the debug one) for distribution
- [ ] Optional later: Gradle/AGP project for x86 CI builds; JNI in-process variant
      if any device rejects subprocess exec

## Distribution

Play Store bans mining → GitHub Releases / F-Droid / sideload. Remember APK
signing (release keystore must be stable across versions).
```
