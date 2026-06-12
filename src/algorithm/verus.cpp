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
// Keep this scratch region padded (historical 512 vectors) for stable A76
// stack layout and throughput. Logical mutation count remains 32.
#define VERUS_GPRAND_SLOTS (VERUS_CLHASH_MUT_SLOTS * 16)
#endif

// OPTIMIZATION: Enable direct native calls (bypass function pointers)
// Set to 0 for portable build, 1 for native build
#ifndef USE_DIRECT_NATIVE_CALL
#define USE_DIRECT_NATIVE_CALL 1
#endif

#ifndef USE_A76_FIXKEY_UNROLL
#define USE_A76_FIXKEY_UNROLL 1
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
		switch (g_cpu_cores[i].part_number) {
		case 0xD0A: /* Cortex-A75 — measured +9% */
		case 0xD0B: /* Cortex-A76 — measured +5.9% */
		case 0xD0D: /* Cortex-A77  */
		case 0xD41: /* Cortex-A78  */
		case 0xD44: /* Cortex-X1   */
		case 0xD47: /* Cortex-A710 */
		case 0xD48: /* Cortex-X2   */
		case 0xD4D: /* Cortex-A715 */
		case 0xD4E: /* Cortex-X3   */
		case 0xD81: /* Cortex-A720 */
		case 0xD84: /* Cortex-X4   */
			return true;
		default:
			return false;
		}
	}
	return false;
}

static void generate_cl_key(unsigned char *seed_bytes_32, verus_vec128_t *key_buffer)
{
	// Expand the 64-byte half-hash into the CLHash key schedule used by Verus.
	unsigned char *key_ptr = (unsigned char *)key_buffer;
	unsigned char *source_ptr = seed_bytes_32;
	
#pragma clang unroll(full) vectorize(enable)
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
#if USE_A76_FIXKEY_UNROLL
#pragma clang loop unroll(full)
#endif
	for (uint64_t i = 32; i--; )
	{
#if USE_A76_FIXKEY_UNROLL
		const uint16_t slot = mutated_slots[i];
		const uint16_t mirror_slot = mirrored_slots[i];
		key_buffer[slot] = preserved_values[i];
		key_buffer[mirror_slot] = preserved_values_mirror[i];
#else
		key_buffer[mutated_slots[i]] = preserved_values[i];
		key_buffer[mirrored_slots[i]] = preserved_values_mirror[i];
#endif
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

static VERUS_ALWAYS_INLINE void compute_verus_hash(unsigned char *hash, unsigned char *cur_buf,
	unsigned char *nonce_bytes, verus_vec128_t * __restrict key_buffer,
	uint16_t * __restrict mutated_slots, uint16_t * __restrict mirrored_slots,
	verus_vec128_t * __restrict preserved_values,
	verus_vec128_t * __restrict preserved_values_mirror)
{
	prepare_hash_buf(cur_buf, nonce_bytes);

	const uint64_t intermediate = verusclhash_port2_2_native(key_buffer, cur_buf, kClHashKeyMask,
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
	 * the full 8-word comparison passed — i.e. the scan should stop (mirrors
	 * the original goto-out semantics, including the slots-full case). */
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
			(use_fused ? verusclhash_port2_2_x2f_native
			           : verusclhash_port2_2_x2_native)(
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
				alignas(16) uint8_t scratch[kHashStateBytes];
				uint32_t ref_hash[8];
				memcpy(scratch, blockhash_half, kHashStateBytes);
				compute_verus_hash((unsigned char *)ref_hash, scratch, nonce_space,
					key_buffer, mutated_slots, mirrored_slots,
					preserved_values, preserved_values_mirror);
				if (memcmp(ref_hash, candidate_hash, sizeof(ref_hash))) {
					applog(LOG_ERR, "VERUS_X2 selftest FAILED chain A (nonce 0x%08x)", nonce_buf);
					abort();
				}
				memcpy(scratch, blockhash_half, kHashStateBytes);
				compute_verus_hash((unsigned char *)ref_hash, scratch, nonce_space_b,
					key_buffer, mutated_slots, mirrored_slots,
					preserved_values, preserved_values_mirror);
				if (memcmp(ref_hash, candidate_b, sizeof(ref_hash))) {
					applog(LOG_ERR, "VERUS_X2 selftest FAILED chain B (nonce 0x%08x)", nonce_buf + 1);
					abort();
				}
			}

			if (try_record_share(candidate_hash, nonce_space))
				goto out;
			if (try_record_share(candidate_b, nonce_space_b)) {
				nonce_buf++;
				goto out;
			}
			nonce_buf += 2;
		}
	}

	/* Single-nonce path: handles VERUS_X2=0 and the odd remainder hash. */
	while (scanned_hashes < max_hashes &&
	       !miner_work_restart_requested(work->restart_generation) &&
	       !miner_should_abort()) {
		((uint32_t *)(&nonce_space[11]))[0] = nonce_buf;

		compute_verus_hash((unsigned char *)candidate_hash, (unsigned char *)blockhash_half,
			nonce_space, key_buffer, mutated_slots, mirrored_slots, preserved_values,
			preserved_values_mirror);
		scanned_hashes++;

		if (try_record_share(candidate_hash, nonce_space))
			goto out;

		if (scanned_hashes >= max_hashes) {
			break;
		}
		nonce_buf++;
	}


out:

	// Report per-call work delta (not absolute nonce space position).
	// miner.cpp accumulates this value to compute hashrate.
	*hashes_done = scanned_hashes;
	pdata[kNonceWordIndex] = scanned_hashes > 0 ? nonce_buf + 1 : nonce_buf;

	return work->valid_nonces;
}
