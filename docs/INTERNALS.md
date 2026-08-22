# Internals

Architecture and invariants for contributors. This is the committed
distillation of knowledge that previously lived only in local notes; if you
change behavior described here, change this file in the same commit.

## Threading model

Three kinds of threads:

1. **One stratum service thread** (`stratum_session.cpp:stratum_service_thread`)
   owns the pool connection lifecycle: connect → handshake → message loop →
   failover/dev-fee switching. There is only ever one, no matter how many
   pools are configured; on failover it migrates to the next pool's
   `stratum_ctx` (transferring join ownership so shutdown joins the context
   the thread is actually blocked on).
2. **N mining threads** (`miner.cpp:miner_thread`) copy published work, scan
   an adaptive ~5 s nonce chunk, and submit shares directly from their own
   thread via `stratum_submit()`.
3. **Optional API thread** (`api.cpp`) serving the read-only
   ccminer-compatible protocol on 127.0.0.1:4068. It only reads snapshots
   (`miner_get_api_snapshot`, `stratum_get_api_pool_snapshot`) — it must
   never reach into live state.

### Work flow

```
pool → service thread → protocol notify handler
     → stratum_commit_job_update()          [applies job + builds work under lock]
     → stratum_publish_work()               [g_runtime_state.current_work + generation bump]
     → mining threads: stratum_copy_work()  [per-chunk copy]
     → scanhash_<algo>()                    [find nonces]
     → submit_ready_share() → stratum_submit() → pool
```

New-work signaling is a single atomic generation counter
(`g_miner_work_generation`): threads snapshot it and poll
`miner_work_restart_requested(local_gen)` each chunk (RandomX: each hash).
There is no per-thread restart flag array.

### Locks (ordering matters)

| Lock | Protects | Notes |
| --- | --- | --- |
| `stratum_work_lock` | `g_runtime_state` (current work, job data, share/session counters), `pools[]` runtime fields | |
| `stratum_sock_lock` | socket sends; for TLS also **all** `curl_easy_send/recv` calls | never held together with `work_lock` |
| `stats_lock` | global hashrate aggregation | may nest `g_topology_lock` inside (that order only) |
| `g_topology_lock` (static, miner.cpp) | `g_cpu_cores[]`, `g_num_cpus`, `g_core_order[]` | every reader takes it; exception: per-chunk algorithm policy reads (scrypt SoA pick, verus x2/fused/asm) are deliberately unlocked — worst case is one chunk on the suboptimal-but-bit-identical variant during a hotplug event |
| `sctx->submit_lock` | submit-id ↔ pending-share correlation | |

## Stratum layer

Split into focused modules behind a vtable (`stratum_internal.h`):

```
stratum.cpp            protocol dispatch (stratum_protocol_ops), shared helpers
stratum_handshake.cpp  subscribe/authorize (+ Monero single-call login)
stratum_transport.cpp  connect, TLS, line I/O, shutdown
stratum_session.cpp    message loop, failover, dev-fee switching
stratum_standard.cpp   SHA256d/scrypt notify + submit
stratum_verus.cpp      Verus/equihash notify + submit
stratum_xmr.cpp        Monero job/submit/keepalived
stratum_rpc.cpp        JSON-RPC plumbing, submit-id tracking, diff conversion
stratum_state.cpp      published work, share stats, API snapshots
stratum_job.cpp        atomic job-apply → work-build → publish
```

Ops selection (`stratum_get_protocol_ops`): RandomX → `xmr_protocol_ops`
(the only ops with `idle_keepalive`, pinged after 60 s of pool silence);
Verus (or a session that validated a `mining.set_target`) →
`verus_protocol_ops`; otherwise standard.

### Contracts that have each caused (or nearly caused) real bugs

- **Every `build_*_work()` must stamp `new_work->pooln = sctx->pooln`.**
  `submit_ready_share()` routes through `pools[work->pooln]`; a builder that
  forgets publishes work as pool 0 and every share found while any other
  pool is active is silently dropped through a disconnected context.
- **Job IDs are used verbatim.** Verus pools send short IDs (4–6 chars); the
  historical ccminer `job_id + 8` skip causes 100 % rejection. Pool job IDs
  ≥ 128 chars are rejected outright (`stratum_check_job_id_length`) rather
  than truncated into a submit/track mismatch.
- **Duplicate-share prevention compares `job_id` strings, not raw bytes** —
  coinbase refreshes keep the job_id and must not reset the scan position.
- **`struct work` must be zeroed before use** (`miner_work_init`), and the
  Verus payload pointer (`work->verus`) survives `miner_work_reset`/copy.
- **Submit-id correlation:** ids < 10 are reserved for handshake/keepalive
  requests and ignored by the response dispatcher; share submits start at 10
  and live in `pending_submits` until the pool answers or they are reaped
  (reaping forces a reconnect — it means the pool stopped answering).
- **extranonce2 is always zero.** The nonce space is partitioned across
  threads (each owns 1/N of 2^32) and threads wait for fresh work on
  exhaustion; nothing rolls extranonce2. If that is ever added,
  `apply_standard_job_locked` is where the counter goes.

### TLS (`stratum+ssl://`)

TLS rides the system libcurl (the binary links no TLS library — a 2026-06
decision to escape the libssl 1.1/3 SONAME split, do not re-add
`-lssl -lcrypto`). The CONNECT_ONLY handle is built with an `https://` URL,
so libcurl performs the handshake, and I/O goes through
`curl_easy_send/recv`. Two things are load-bearing:

- Both calls run under `stratum_sock_lock`: TLS session state is not
  full-duplex-safe across threads (miner threads submit while the service
  thread receives). Both are non-blocking; socket waits happen unlocked.
- The receive loop calls `curl_easy_recv` **before** polling: decrypted
  bytes can be buffered in the TLS layer with nothing pending on the socket.

Certificates are not verified (pool certs are self-signed;
ecosystem-standard behavior). TLS-less libcurl builds (e.g. the Android
static TCP-only curl) fail a `stratum+ssl` request with an explicit error.

## Algorithms

Uniform interface:
`int scanhash_<algo>(int thr_id, struct work *work, uint32_t max_hashes, unsigned long *hashes_done)`
— return found-nonce count, report *exactly* how many hashes were done
(`miner_thread` aborts the process if a backend overshoots its chunk), use
`while` not `do…while` (the range can be exhausted on entry), and check
`miner_work_restart_requested()` at least once per small batch.

| | Verus | SHA256d | scrypt | RandomX |
| --- | --- | --- | --- | --- |
| nonce location | `data[30]` | `data[19]` | `data[19]` | blob byte 39 (counter in a spare word) |
| target format | `diff_to_target_verus` (equihash order) | `diff_to_target` | `diff_to_target`, pool diff ÷ 65536 | 64-bit boundary on hash's top 8 bytes |
| hash vs target | word-7 prefilter, then a real LE 256-bit compare on the win path (see below) | LE 256-bit compare | LE 256-bit compare | top-64-bit compare |

Per-algo facts that are easy to get wrong:

- **Verus: the scan produces only hash word 7; the win path re-hashes in
  full.** `haraka512_keyed_native` computes just the 4 bytes the difficulty
  prefilter needs, so words 0–6 of a *scanned* candidate are the buffer's
  zero-init — never compare or log them. That is enough to reject all but
  ~1 in `2^32/target[7]` hashes, but not enough to decide the 256-bit
  comparison or report a share difficulty, so `try_record_share` re-hashes
  every candidate that clears the prefilter through
  `haraka512_keyed_full_native` and uses *that* hash for both
  `hash_le_target` and the share difficulty.
  The recompute is exact because CLHash restores every key slot it mutates,
  so replaying a nonce reproduces its hash. It cannot re-finalize in place:
  `restore_cl_key_slots` runs immediately after the keyed Haraka, so the
  round constants are already gone. Cold path — measured a wash.
- **Verus share difficulty is absolute.** `bn_store_share_difficulty` returns
  `targetdiff × (target / hash)`, matching the RandomX back end; it once
  stored the bare ratio and ignored `targetdiff`, making every reported diff
  read ~1.0 regardless of pool difficulty.
- **Triage hook for reject reports:** `PRIMO_VERUS_SUBMIT_VERIFY=1` logs each
  submission's wire fields and recomputes the hash from those exact bytes, so
  you can tell "the miner submits bad work" from "the pool disagrees with a
  sound payload". Measured baseline: 0.38 % rejects over 3919 live
  submissions, against a pool operator's stated 0–5 % normal range.
- **Verus CLHash entry points are `noinline`** (LTO inlining them
  miscompiles under strict aliasing), and `prand`/`prandex` may alias
  (~6 % of hashes) — never `__restrict` them.
- **SHA256d byte order:** the word-7 prefilter must byte-swap the *hash*
  side (`bswap32(state[7]) <= ptarget[7]`); swapping the target instead is a
  different inequality that silently rejects true winners at diff < 1.
- **scrypt** is hardwired to Litecoin's N=1024/r=1/p=1; the only Salsa
  implementations are the fused scalar in `scrypt_blockmix_asm.S` and the
  4-lane `salsa208_soa`. `scanhash_scrypt` must `break` immediately on a
  found nonce (shares go stale in seconds).
- **AArch64 asm ABI:** never use `x18` (Android reserves it) — history:
  `scrypt_blockmix_asm.S` once did; use `w17`/callee-saved with save/restore.

### Runtime variant selection (one universal binary)

Per-thread, by core type at scan time: Verus picks x1 vs x2-interleaved
CLHash (big cores), the fused 64-way dispatch (allowlisted ARM A75+-lineage
parts + Oryon; Samsung Mongoose regresses −24 %), and hand-asm vs portable-C
helpers (`VERUS_ASM/VERUS_X2/VERUS_FUSE=0/1` force); scrypt picks SoA-4 vs
dual-scalar ROMix (`SCRYPT_SOA=0/1`). All variants are bit-identical and
cross-checked (below).

### Self-test matrix (all gate mining at startup)

| Algo | At init | Under load |
| --- | --- | --- |
| Verus | crypto-extension check | `VERUS_X2_SELFTEST=1`: every pair vs portable x1 (validates x2, fused, asm) |
| SHA256d | "abc" vectors + `sha256d_scan_selftest` (dual asm **and** portable dual vs full-header reference) | — |
| scrypt | consistency + dual + SoA-4 vs single-path reference | — |
| RandomX | reference vectors (refuses on JIT/fast-math miscompiles) | — |

`make test` (tests/run_tests.sh) runs the init self-tests, the Verus
under-load cross-check, and end-to-end share round-trips against
`tests/mock_pool.py` over plain TCP and TLS.

## CPU pinning and Android reality

Pinning is **reconciled, not one-shot** (`miner_thread_repin_tick`, called
per chunk, 20 s rate limit): the kernel resets *every* task's affinity to
the full online set whenever *any* core onlines, so the tick compares the
effective mask, not the current CPU. Topology is re-detected on hotplug
(Android parks/wakes cores under load). Pin targets are a uniform
round-robin over the *platform-allowed* cpuset in big-first topology order —
Android cpuset cgroups withhold cores from non-focused apps, and the
withheld-core set changes with screen state. A startup-captured policy mask
honors external `taskset` on Linux; that capture is **deliberately skipped
on Android** (the startup cpuset is transient there, and freezing it exiled
big cores in the field). A one-shot diagnostic detects uclamp/cpuset
frequency caps (big core far below max under sustained load) and says so.

## Dev fee

xmrig-style time slice on the existing connection machinery: a hidden,
`disabled`-flagged pool slot above the user pools (index `MAX_USER_POOLS`)
that failover and startup selection skip; the scheduler switches to it by
index for one 60 s slice per cycle (cycle length set by the per-algo percent
in `k_dev_fee_targets`). Hard guarantee: if the dev pool is unreachable or
drops mid-slice, the slice is abandoned immediately and rescheduled a full
cycle out — the fee can never cost the user mining time. First slice lands
at a uniformly random point in the first cycle (anti-gaming; never logged in
advance). `PRIMO_DEVFEE_TEST=1` accelerates timing only.

## Build flags that are correctness- or performance-critical

- `-fno-strict-aliasing` must stay **out** of CPPFLAGS (+1.1 % Verus).
- `clhash_native.c` / `haraka_native.c`: `-fno-unroll-loops` (I-cache).
- `scrypt_neon.c`: `-fno-slp-vectorize` (NEON→scalar store-forwarding).
- RandomX builds via its own cmake so our `-ffast-math` cannot touch its
  consensus-critical FP.
- `-mtune=cortex-a53` beats big-core tuning across heterogeneous SoCs.
- Keep `-march=armv8-a+crypto` — v8.2 emits LSE atomics that SIGILL on
  ARMv8.0 phones.
