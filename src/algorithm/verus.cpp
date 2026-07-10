/*
 * VerusHash mining and verification path for Primo ARM Miner.
 * Copyright (C) 2026 primo-arm-miner contributors.
 *
 * This translation unit contains the native ARM integration used by the
 * coordinator while preserving the existing high-performance scan flow.
 * Substantially rewritten on 2026-03-16 from earlier GPL-licensed mining
 * software ancestry. See LICENSE and PROVENANCE.md.
 */

#include <stdlib.h>
#include <string.h>

#define VERUS_KEY_SIZE 8832
#define VERUS_KEY_SIZE128 552
#define VERUS_CLHASH_MUT_SLOTS 32

#ifndef VERUS_KEY_VECTORS
#define VERUS_KEY_VECTORS VERUS_KEY_SIZE128
#endif

#ifndef VERUS_GPRAND_SLOTS
// Sized to the logical mutation count. The historical 512-vector padding
// ("stable A76 stack layout") was re-measured 2026-07-10 (RK3588, interleaved
// 90s brackets): 32 slots is +0.3% on 4T A55 (2263->2270 kH/s, smaller frame
// helps the in-order core) and a wash on 4T A76 x2f (5577 vs 5576 kH/s
// medians) — and it cuts ~30 KB of stack per mining thread.
#define VERUS_GPRAND_SLOTS VERUS_CLHASH_MUT_SLOTS
#endif

// Historical name: predates the runtime variant dispatch. Variants are now
// selected per thread via function pointers (see scanhash_verus); the x1
// loop's call site is constant-folded to a direct BL via its always_inline
// helper. This define only gates the native haraka/clhash code paths.
#ifndef USE_DIRECT_NATIVE_CALL
#define USE_DIRECT_NATIVE_CALL 1
#endif

#include "miner.h"

extern "C" {
#include "cpu_features.h"
#include "haraka_native.h"
#include "clhash_native.h"
}

#if defined(__GNUC__) || defined(__clang__)
#define VERUS_ALWAYS_INLINE __attribute__((always_inline)) inline
#else
#define VERUS_ALWAYS_INLINE inline
#endif

static bool native_initialized = false;
static bool native_available = false;
static pthread_once_t native_init_once = PTHREAD_ONCE_INIT;

using verus_vec128_t = uint8x16_t;

namespace {
constexpr size_t kHashStateBytes = 64;
constexpr size_t kHarakaChunkBytes = 32;
constexpr uint32_t kChainKeyBlocks = VERUS_KEY_SIZE / kHarakaChunkBytes;
constexpr uint32_t kClHashKeyMask = 511;
constexpr uint32_t kNonceWordIndex = 30;
constexpr size_t kHeaderBytes = 140;
constexpr size_t kMergedMiningPrefixBytes = 3;
constexpr size_t kSolutionBytes = 1344;
constexpr size_t kSerializedJobBytes = kHeaderBytes + kMergedMiningPrefixBytes + kSolutionBytes;
constexpr size_t kStoredSolutionBytes = kMergedMiningPrefixBytes + kSolutionBytes;
constexpr size_t kSolutionNonceOffset = 1332;
constexpr size_t kNonceBytes = 15;
const unsigned char kMergedMiningPrefix[kMergedMiningPrefixBytes] = { 0xfd, 0x40, 0x05 };
}  // namespace

static void init_native_functions()
{
    init_cpu_features();

    if (!has_armv8_crypto_support()) {
        applog(LOG_ERR, "Verus native path requires ARMv8 crypto extensions (AES + PMULL)");
        native_initialized = true;
        native_available = false;
        return;
    }

    applog(LOG_INFO, "Using pure ARM NEON Verus path");
    load_constants_native();
    native_initialized = true;
    native_available = true;
}

extern "C" bool verus_init_runtime(void)
{
    pthread_once(&native_init_once, init_native_functions);
    return native_available;
}

/* Decide whether this thread should run the two-nonce interleaved CLHash.
 * The win comes from out-of-order execution overlapping the two serial
 * dependency chains; in-order little cores can't do that (measured ±1%,
 * SoC-dependent: +1.4% RK3588 A55, −0.9% Exynos 9820 A55 — x1 stays the
 * LITTLE default). Unknown/homogeneous topologies default to x2 because the
 * payoff is asymmetric (+24% on OoO vs ~±1% on in-order). */
static bool verus_use_x2_for_current_cpu(void)
{
	const char *e = getenv("VERUS_X2");
	if (e && e[0])
		return e[0] != '0';

	if (g_num_big_cores > 0 && g_num_little_cores > 0) {
		int cpu = sched_getcpu();
		if (cpu >= 0) {
			for (int i = 0; i < g_num_cpus; i++) {
				if (g_cpu_cores[i].cpu_id == cpu)
					return g_cpu_cores[i].is_big;
			}
		}
	}
	return true;
}

/* Decide whether this thread's x2 loop should use the fused 64-way dispatch.
 * The win (one mispredict bubble per pair-iteration instead of two serialized
 * ones) depends on the front-end swallowing a ~37KB jump-table body: measured
 * +5.9% on Cortex-A76 and +9% on Cortex-A75, but -24% on Samsung Mongoose M4.
 * Default fused only on ARM-designed big cores of the A75+ generation; custom
 * cores (Samsung M-series, Kryo-stamped) and older ARM parts (A73 and earlier)
 * stay on the per-chain dispatch. VERUS_FUSE=0/1 forces.
 * NOTE: when ARM ships a new big-core part, add it BOTH here and to
 * is_big_core() in cpu_features.c — the lists overlap but serve different
 * policies (big-core classification spans Samsung/Qualcomm parts too). */
static bool verus_use_fused_for_current_cpu(void)
{
	const char *e = getenv("VERUS_FUSE");
	if (e && e[0])
		return e[0] != '0';

	int cpu = sched_getcpu();
	if (cpu < 0)
		return false;
	for (int i = 0; i < g_num_cpus; i++) {
		if (g_cpu_cores[i].cpu_id != cpu)
			continue;
		/* Qualcomm Oryon (Snapdragon X Elite / 8 Elite, MIDR 0x51/0x001):
		 * measured +3.3% with fused on a 12-core X Elite (24.12 vs 23.36 MH/s,
		 * Darktron 2026-06-15) — a custom core that, unlike the Samsung Mongoose
		 * M4 (-24%), has a wide enough front-end to swallow the jump table.
		 * Checked implementer-first because part 0x001 collides with the Samsung
		 * Exynos M1 (0x53/0x001), which must stay on per-chain dispatch. */
		if (g_cpu_cores[i].implementer == 0x51 &&
		    g_cpu_cores[i].part_number == 0x001)
			return true;
		switch (g_cpu_cores[i].part_number) {
		case 0xD0A: /* Cortex-A75 — measured +9% */
		case 0xD0B: /* Cortex-A76 — measured +5.9% */
		case 0xD0D: /* Cortex-A77  */
		case 0xD41: /* Cortex-A78  */
		case 0xD4B: /* Cortex-A78C */
		case 0xD44: /* Cortex-X1   */
		case 0xD4C: /* Cortex-X1C  */
		case 0xD47: /* Cortex-A710 */
		case 0xD48: /* Cortex-X2   */
		case 0xD4D: /* Cortex-A715 */
		case 0xD4E: /* Cortex-X3   */
		case 0xD81: /* Cortex-A720 */
		case 0xD82: /* Cortex-X4 (0xD84 was a mislabel — that is Neoverse-V3) */
		case 0xD87: /* Cortex-A725 */
		case 0xD85: /* Cortex-X925 */
		case 0xD8B: /* C1-Pro     */
		case 0xD8C: /* C1-Ultra   */
		case 0xD90: /* C1-Premium */
		/* NOTE: newest ARM A75-descendants (A725/X925/C1) are added on the
		 * design-lineage rationale, not yet per-core measured. Verus fused
		 * self-test (VERUS_X2_SELFTEST=1) still guards correctness; if a tester
		 * device shows a regression, drop its part here (cf. Mongoose M4). */
			return true;
		default:
			return false;
		}
	}
	return false;
}

/* Function-pointer types for the runtime-selected CLHash variants. Top-level
 * __restrict on the underlying functions' params is not part of the function
 * type, so these unqualified signatures bind to the _asm/_noasm symbols. */
typedef uint64_t (*verus_clhash_x1_fn)(void *, const unsigned char *, uint64_t,
	uint16_t *, uint16_t *, uint64x2_t *, uint64x2_t *);
typedef void (*verus_clhash_x2_fn)(void *, void *, const unsigned char *, const unsigned char *,
	uint64_t, uint16_t *, uint16_t *, uint64x2_t *, uint64x2_t *,
	uint16_t *, uint16_t *, uint64x2_t *, uint64x2_t *, uint64_t *, uint64_t *);

/* Select the hand-asm CLHash variant. It is bit-exact with the portable C path
 * (verified by VERUS_X2_SELFTEST, which references _noasm) and measured
 * net-positive on every core tested — Cortex-A76 (+4%), Samsung Mongoose M4
 * (+3-4%), AND the in-order Cortex-A55 (asm-all 7.46 > asm-big-only 7.38 >
 * C-all 7.19 MH/s, 8T RK3588). So enable it on ALL cores by default; this
 * reproduces the old rk3588-profile behaviour in a single binary (no separate
 * generic build) while keeping a runtime escape. If a future core regresses on
 * the asm (cf. the fused-dispatch Mongoose case), add a MIDR check here to fall
 * back to _noasm for that part. VERUS_ASM=0/1 forces. */
static bool verus_use_asm_for_current_cpu(void)
{
	const char *e = getenv("VERUS_ASM");
	if (e && e[0])
		return e[0] != '0';

	/* No core has shown an asm regression yet, so the blocklist is empty.
	 * Example future fallback:
	 *   int cpu = sched_getcpu();
	 *   if (cpu >= 0) for (int i = 0; i < g_num_cpus; i++)
	 *       if (g_cpu_cores[i].cpu_id == cpu && is_asm_regressing_part(...))
	 *           return false;
	 */
	return true;
}

static void generate_cl_key(unsigned char *seed_bytes_32, verus_vec128_t *key_buffer)
{
	// Expand the 64-byte half-hash into the CLHash key schedule used by Verus.
	unsigned char *key_ptr = (unsigned char *)key_buffer;
	unsigned char *source_ptr = seed_bytes_32;
	
#pragma clang loop unroll(full) vectorize(enable)
	for (uint32_t block_index = 0; block_index < kChainKeyBlocks; block_index++)
	{
		haraka256_native(key_ptr, source_ptr);

		source_ptr = key_ptr;
		key_ptr += kHarakaChunkBytes;
	}
}

static VERUS_ALWAYS_INLINE void restore_cl_key_slots(uint16_t * __restrict mutated_slots,
	uint16_t * __restrict mirrored_slots, verus_vec128_t * __restrict key_buffer,
	verus_vec128_t * __restrict preserved_values, verus_vec128_t * __restrict preserved_values_mirror)
{
	// Full unroll + hoisting both slot indices into locals before the stores:
	// measured part of the big-core asm win, neutral elsewhere, so unconditional.
#pragma clang loop unroll(full)
	for (uint64_t i = 32; i--; )
	{
		const uint16_t slot = mutated_slots[i];
		const uint16_t mirror_slot = mirrored_slots[i];
		key_buffer[slot] = preserved_values[i];
		key_buffer[mirror_slot] = preserved_values_mirror[i];
	}
}


static void build_blockhash_half(void *output_hash, unsigned char *input_data, size_t input_len)
{
	alignas(16) unsigned char buffer_a[kHashStateBytes] = { 0 };
	unsigned char buffer_b[kHashStateBytes];
	unsigned char *current_buffer = buffer_a;
	unsigned char *next_buffer = buffer_b;
	size_t curPos = 0;

	unsigned char *swap_buffer;

	// Haraka consumes the trailing 32-byte half of the 64-byte state.
	for (size_t input_offset = 0; input_offset < input_len; )
	{
		size_t room = kHarakaChunkBytes - curPos;

		if (input_len - input_offset >= room)
		{
			memcpy(current_buffer + kHarakaChunkBytes + curPos, input_data + input_offset, room);
			haraka512_native(next_buffer, current_buffer);
			swap_buffer = current_buffer;
			current_buffer = next_buffer;
			next_buffer = swap_buffer;
			input_offset += room;
			curPos = 0;
		}
		else
		{
			memcpy(current_buffer + kHarakaChunkBytes + curPos, input_data + input_offset,
			       input_len - input_offset);
			curPos += input_len - input_offset;
			input_offset = input_len;
		}
	}

	memcpy(current_buffer + 47, current_buffer, 16);
	memcpy(current_buffer + 63, current_buffer, 1);
	memcpy(output_hash, current_buffer, kHashStateBytes);
}

/* Rebuild the volatile tail of the 64-byte CLHash input: bytes 47..63 are
 * clobbered by the previous hash's intermediate writes, and 32..46 carry the
 * per-hash nonce. Bytes 0..31 stay fixed for the whole job. */
static VERUS_ALWAYS_INLINE void prepare_hash_buf(unsigned char *cur_buf,
	const unsigned char *nonce_bytes)
{
	memcpy(cur_buf + 47, cur_buf, 16);
	memcpy(cur_buf + 63, cur_buf, 1);
	memcpy(cur_buf + 32, nonce_bytes, kNonceBytes);
}

/* Post-CLHash half: fold the intermediate back into the buffer, run the keyed
 * Haraka finalizer, then restore the key slots CLHash mutated. */
static VERUS_ALWAYS_INLINE void finalize_verus_hash(unsigned char *hash, unsigned char *cur_buf,
	uint64_t intermediate, verus_vec128_t * __restrict key_buffer,
	uint16_t * __restrict mutated_slots, uint16_t * __restrict mirrored_slots,
	verus_vec128_t * __restrict preserved_values,
	verus_vec128_t * __restrict preserved_values_mirror)
{
	memcpy(cur_buf + 47, &intermediate, 8);
	memcpy(cur_buf + 55, &intermediate, 8);
	memcpy(cur_buf + 63, &intermediate, 1);
	haraka512_keyed_native(hash, cur_buf, key_buffer + (intermediate & kClHashKeyMask));

	restore_cl_key_slots(mutated_slots, mirrored_slots, key_buffer, preserved_values,
	                     preserved_values_mirror);
}

static VERUS_ALWAYS_INLINE void compute_verus_hash(verus_clhash_x1_fn clhash_x1,
	unsigned char *hash, unsigned char *cur_buf,
	unsigned char *nonce_bytes, verus_vec128_t * __restrict key_buffer,
	uint16_t * __restrict mutated_slots, uint16_t * __restrict mirrored_slots,
	verus_vec128_t * __restrict preserved_values,
	verus_vec128_t * __restrict preserved_values_mirror)
{
	prepare_hash_buf(cur_buf, nonce_bytes);

	const uint64_t intermediate = clhash_x1(key_buffer, cur_buf, kClHashKeyMask,
	                                          mutated_slots, mirrored_slots,
	                                          reinterpret_cast<uint64x2_t *>(preserved_values),
	                                          reinterpret_cast<uint64x2_t *>(preserved_values_mirror));

	finalize_verus_hash(hash, cur_buf, intermediate, key_buffer, mutated_slots, mirrored_slots,
	                    preserved_values, preserved_values_mirror);
}

extern "C" int scanhash_verus(int thr_id, struct work *work, uint32_t max_hashes, unsigned long *hashes_done)
{
	(void)thr_id;

	// miner_init_algorithm_runtime() initializes the Verus runtime before worker
	// threads start; keep a cold fallback here in case a future caller bypasses it.
	if (__builtin_expect(!native_initialized, 0))
		pthread_once(&native_init_once, init_native_functions);
	if (!native_available) {
		*hashes_done = 0;
		return 0;
	}

	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	uint8_t blockhash_half[kHashStateBytes] = { 0 };

	// Defaults are right-sized, but macros allow controlled A/B on stack layout.
	verus_vec128_t key_buffer[VERUS_KEY_VECTORS] __attribute__ ((aligned(64)));
	verus_vec128_t preserved_values[VERUS_GPRAND_SLOTS] __attribute__ ((aligned(64)));
	verus_vec128_t preserved_values_mirror[VERUS_GPRAND_SLOTS] __attribute__ ((aligned(64)));

	uint32_t nonce_buf = pdata[kNonceWordIndex];
	unsigned long scanned_hashes = 0;
	uint16_t mutated_slots[VERUS_CLHASH_MUT_SLOTS] __attribute__ ((aligned(64)));
	uint16_t mirrored_slots[VERUS_CLHASH_MUT_SLOTS] __attribute__ ((aligned(64)));

	// Chain-B state for the two-nonce interleaved CLHash path (VERUS_X2).
	// Both chains hash against byte-identical pristine keys; each mutates and
	// restores its own copy, so the buffers stay interchangeable.
	verus_vec128_t key_buffer2[VERUS_KEY_VECTORS] __attribute__ ((aligned(64)));
	verus_vec128_t preserved_values2[VERUS_GPRAND_SLOTS] __attribute__ ((aligned(64)));
	verus_vec128_t preserved_values_mirror2[VERUS_GPRAND_SLOTS] __attribute__ ((aligned(64)));
	uint16_t mutated_slots2[VERUS_CLHASH_MUT_SLOTS] __attribute__ ((aligned(64)));
	uint16_t mirrored_slots2[VERUS_CLHASH_MUT_SLOTS] __attribute__ ((aligned(64)));

	uint8_t serialized_job[kSerializedJobBytes] = { 0 };
	uint8_t *solution_bytes = &serialized_job[kHeaderBytes];
	uint8_t *work_solution = miner_work_solution(work);
	uint8_t *work_extra = miner_work_extra(work);

	if (!work_solution || !work_extra)
		return 0;

	memcpy(serialized_job, pdata, kHeaderBytes);
	memcpy(solution_bytes, kMergedMiningPrefix, kMergedMiningPrefixBytes);
	memcpy(solution_bytes + kMergedMiningPrefixBytes, work_solution, kSolutionBytes);
	uint8_t version = work_solution[0];
	uint8_t nonce_space[kNonceBytes] = { 0 };

	if (version >= 7 && work_solution[5] > 0) {
		// Clear non-canonical header fields before hashing merged-mined payloads.
		memset(serialized_job + 4, 0, 96);
		memset(serialized_job + 4 + 32 + 32 + 32 + 4, 0, 4);
		memset(serialized_job + 4 + 32 + 32 + 32 + 4 + 4, 0, 32);
		memset(solution_bytes + kMergedMiningPrefixBytes + 8, 0, 64);
		memcpy(nonce_space, &pdata[kNonceWordIndex - 3], 7);
		memcpy(nonce_space + 7, &pdata[kNonceWordIndex + 2], 4);
	}

	uint32_t candidate_hash[8] = { 0 };

	build_blockhash_half(blockhash_half, (unsigned char *)serialized_job, kSerializedJobBytes);
	generate_cl_key((unsigned char *)blockhash_half, key_buffer);


	const uint32_t target_word_high = ptarget[7];

	/* Validate a candidate hash and record it as a share. Returns true when
	 * the comparison passed — i.e. the scan should stop (mirrors the
	 * original goto-out semantics, including the slots-full case).
	 * NOTE: only chash[7] is real. haraka512_keyed_native computes just the
	 * 4 bytes the difficulty check needs, so words 0-6 hold the buffer's
	 * zero-init, and the hash_le_target below effectively degenerates to
	 * chash[7] <= target[7] (its lower words compare stale zeros against
	 * the target's 0xff filler). Correctness holds because the pool
	 * recomputes the full hash from the submitted nonce+solution; at worst
	 * a share with word 7 exactly equal to target[7] can be submitted when
	 * the true lower words would have failed (~2^-32-scale reject risk). */
	auto try_record_share = [&](uint32_t *chash, const uint8_t *nspace) -> bool {
		/* Cheap word-7 prefilter (hoisted target) rejects almost every
		 * hash before the full compare; only near-solutions reach it. */
		if (chash[7] > target_word_high)
			return false;
		if (!hash_le_target(chash, ptarget))
			return false;
		if (work->valid_nonces < MAX_NONCES) {
			work->valid_nonces++;
			memcpy(work->data, serialized_job, kHeaderBytes);
			int nonce = work->valid_nonces - 1;
			memcpy(work_extra, solution_bytes, kStoredSolutionBytes);
			memcpy(work_extra + kSolutionNonceOffset, nspace, kNonceBytes);
			bn_store_share_difficulty(chash, work->target, work, nonce);
			/* The header nonce field (word 30) is constant within a
			 * scanhash call by design: blockhash_half is Haraka'd once
			 * before the loop, and the per-hash search counter rides in
			 * nonce_space[11..14] -> work_extra (the submitted solution),
			 * not the header word. So work->nonces[] correctly captures
			 * the header field, not the search counter. Do not "fix"
			 * this to nonce_buf — both are independent fields of the
			 * validated preimage. */
			work->nonces[work->valid_nonces - 1] =
				((uint32_t *)serialized_job)[kNonceWordIndex];
		}
		return true;
	};

	/* Two-nonce interleaved path: hash nonce pairs through the x2 CLHash so
	 * the core overlaps the two serial latency chains (+24% on A76, ~±1% on
	 * in-order A55) — default x2 on big cores, x1 on LITTLE, re-checked each
	 * scan chunk in case the thread migrated. ARM A75+ big cores additionally
	 * route the pair through the fused-dispatch variant (use_fused below).
	 * VERUS_X2=0/1 forces; VERUS_X2_SELFTEST=1 cross-checks every pair
	 * against the x1 path (covers the fused variant too). */
	const bool use_x2 = verus_use_x2_for_current_cpu();
	const char *x2_st_env = getenv("VERUS_X2_SELFTEST");
	const bool x2_selftest = x2_st_env && x2_st_env[0] == '1';
	const bool use_fused = verus_use_fused_for_current_cpu();
	const bool use_asm = verus_use_asm_for_current_cpu();

	/* Per-thread CLHash variant: hand-asm on big cores, portable C otherwise.
	 * The selftest below always references the portable _noasm x1, so
	 * VERUS_X2_SELFTEST=1 also validates _asm == _noasm at runtime. */
	const verus_clhash_x2_fn clhash_x2 = use_asm
		? (use_fused ? verusclhash_port2_2_x2f_native_asm : verusclhash_port2_2_x2_native_asm)
		: (use_fused ? verusclhash_port2_2_x2f_native_noasm : verusclhash_port2_2_x2_native_noasm);

	if (use_x2) {
		alignas(16) uint8_t cur_a[kHashStateBytes];
		alignas(16) uint8_t cur_b[kHashStateBytes];
		uint8_t nonce_space_b[kNonceBytes];
		uint32_t candidate_b[8] = { 0 };

		memcpy(key_buffer2, key_buffer, sizeof(key_buffer2));
		memcpy(cur_a, blockhash_half, kHashStateBytes);
		memcpy(cur_b, blockhash_half, kHashStateBytes);
		memcpy(nonce_space_b, nonce_space, kNonceBytes);

		while (scanned_hashes + 2 <= max_hashes &&
		       !miner_work_restart_requested(work->restart_generation) &&
		       !miner_should_abort()) {
			((uint32_t *)(&nonce_space[11]))[0] = nonce_buf;
			((uint32_t *)(&nonce_space_b[11]))[0] = nonce_buf + 1;

			prepare_hash_buf(cur_a, nonce_space);
			prepare_hash_buf(cur_b, nonce_space_b);

			uint64_t inter_a, inter_b;
			clhash_x2(
				key_buffer, key_buffer2, cur_a, cur_b,
				kClHashKeyMask,
				mutated_slots, mirrored_slots,
				reinterpret_cast<uint64x2_t *>(preserved_values),
				reinterpret_cast<uint64x2_t *>(preserved_values_mirror),
				mutated_slots2, mirrored_slots2,
				reinterpret_cast<uint64x2_t *>(preserved_values2),
				reinterpret_cast<uint64x2_t *>(preserved_values_mirror2),
				&inter_a, &inter_b);

			finalize_verus_hash((unsigned char *)candidate_hash, cur_a, inter_a,
				key_buffer, mutated_slots, mirrored_slots,
				preserved_values, preserved_values_mirror);
			finalize_verus_hash((unsigned char *)candidate_b, cur_b, inter_b,
				key_buffer2, mutated_slots2, mirrored_slots2,
				preserved_values2, preserved_values_mirror2);
			scanned_hashes += 2;

			if (x2_selftest) {
				/* Compare ONLY word 7: haraka512_keyed_native computes just
				 * the 4 bytes needed for the difficulty check (the oink70
				 * truncated-output optimization), so words 0-6 of any hash
				 * buffer are never written. The old full-32-byte memcmp
				 * passed only because this stack slot happened to hold
				 * zeros, matching candidate_hash's zero-init — a compiler
				 * stack-layout change would have made it abort() spuriously.
				 * Word 7 still discriminates fully: the CLHash intermediate
				 * feeds the keyed-Haraka input AND the key selection, so any
				 * divergence upstream changes word 7 with 1-2^-32 per hash. */
				alignas(16) uint8_t scratch[kHashStateBytes];
				uint32_t ref_hash[8];
				memcpy(scratch, blockhash_half, kHashStateBytes);
				compute_verus_hash(verusclhash_port2_2_native_noasm,
					(unsigned char *)ref_hash, scratch, nonce_space,
					key_buffer, mutated_slots, mirrored_slots,
					preserved_values, preserved_values_mirror);
				if (ref_hash[7] != candidate_hash[7]) {
					applog(LOG_ERR, "VERUS_X2 selftest FAILED chain A (nonce 0x%08x)", nonce_buf);
					abort();
				}
				memcpy(scratch, blockhash_half, kHashStateBytes);
				compute_verus_hash(verusclhash_port2_2_native_noasm,
					(unsigned char *)ref_hash, scratch, nonce_space_b,
					key_buffer, mutated_slots, mirrored_slots,
					preserved_values, preserved_values_mirror);
				if (ref_hash[7] != candidate_b[7]) {
					applog(LOG_ERR, "VERUS_X2 selftest FAILED chain B (nonce 0x%08x)", nonce_buf + 1);
					abort();
				}
			}

			/* Check BOTH chains before deciding to stop - MAX_NONCES is 2,
			 * so a pair can legitimately have two winners. Short-circuiting
			 * on chain A alone (the old `if (...) goto out;` shape) would
			 * silently drop chain B's already-computed hash whenever both
			 * won in the same pair. */
			bool found_a = try_record_share(candidate_hash, nonce_space);
			bool found_b = try_record_share(candidate_b, nonce_space_b);
			if (found_a || found_b) {
				/* Keep nonce_buf = next-to-hash on this exit too: one past
				 * chain B when B won; at chain B when only A won (re-scans
				 * the non-winning B — the pre-existing, deliberate
				 * behavior; see the x2 both-chains note in CLAUDE.md). */
				nonce_buf += found_b ? 2 : 1;
				goto out;
			}
			nonce_buf += 2;
		}
	}

	/* Single-nonce path: handles VERUS_X2=0 and the odd remainder hash.
	 * Two A55-oriented micro-optimizations (this is the LITTLE-core path —
	 * big cores take the x2 loop above, which is unchanged):
	 * - The restart/abort flags are checked once per 8 hashes instead of
	 *   every hash: both are acquire loads (LDAR), which on in-order A55
	 *   issue only from slot 0. Worst-case extra restart latency is 8
	 *   hashes (~15 us on A55) — irrelevant.
	 * - The loop body lives in an always_inline lambda invoked with LITERAL
	 *   function symbols, so clang constant-folds the CLHash call into a
	 *   direct BL. The loop-invariant `clhash_x1` pointer still compiled to
	 *   a per-hash BLR, which A55 issues only from slot 1 (BL dual-issues).
	 *   The CLHash entries keep their own noinline (see clhash_native.c —
	 *   LTO inlining them miscompiles under strict aliasing); only the call
	 *   SITE becomes static. */
	{
		auto run_x1_loop = [&](verus_clhash_x1_fn fn) __attribute__((always_inline)) {
			uint32_t flag_check_ctr = 0;
			while (scanned_hashes < max_hashes) {
				if ((flag_check_ctr++ & 7u) == 0 &&
				    (miner_work_restart_requested(work->restart_generation) ||
				     miner_should_abort()))
					break;
				((uint32_t *)(&nonce_space[11]))[0] = nonce_buf;

				compute_verus_hash(fn, (unsigned char *)candidate_hash,
					(unsigned char *)blockhash_half, nonce_space, key_buffer,
					mutated_slots, mirrored_slots, preserved_values,
					preserved_values_mirror);
				scanned_hashes++;
				nonce_buf++;

				if (try_record_share(candidate_hash, nonce_space))
					break;   /* == goto out: the label directly follows */
			}
		};
		if (use_asm)
			run_x1_loop(verusclhash_port2_2_native_asm);
		else
			run_x1_loop(verusclhash_port2_2_native_noasm);
	}

out:

	// Report per-call work delta (not absolute nonce space position).
	// miner.cpp accumulates this value to compute hashrate.
	*hashes_done = scanned_hashes;
	// nonce_buf is maintained as "next nonce to hash" on EVERY exit path
	// (share found, chunk complete, restart/abort), so it is the exact
	// resume point. Only the benchmark loop consumes this readback — live
	// mining tracks next_nonce_index in miner_thread — but the previous
	// `nonce_buf + 1` skipped one nonce whenever the x2 loop (or a
	// restart) exited with nonce_buf already advanced past the last hash.
	pdata[kNonceWordIndex] = nonce_buf;

	return work->valid_nonces;
}
