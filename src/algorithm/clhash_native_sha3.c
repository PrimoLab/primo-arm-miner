// This TU recompiles clhash_native.c, whose hashing core carries Apache-2.0
// translation ancestry (Copyright (c) 2018 Michael Toutonghi; CLHash
// Copyright (c) 2017, 2018 Daniel Lemire and Owen Kaser) — see the header
// of clhash_native.c and LICENSES/Apache-2.0.txt.
//
// EOR3 (FEAT_SHA3) build of the CLHash hot loop. Identical source to the
// default _asm variant (hand-asm helpers stay ON — this isolates ONE axis:
// sha3+asm vs asm), but compiled -march=armv8-a+crypto+sha3 so clang fuses
// the accumulator XOR chains into EOR3 (three-way XOR, one instruction):
// measured on this source with clang-16, ~119 eor3 land in the hot kernels
// (~98 in x2f, ~14 in x2, ~7 in x1) — expectation is +1-3% on FEAT_SHA3
// cores, nothing anywhere else. The +sha3 stays on the armv8-a BASE
// deliberately: bumping the base (armv8.2-a etc.) would leak LSE atomics
// and friends into code that must still run on ARMv8.0 phones (see the
// Termux SIGILL history).
//
// Runtime-gated in verus.cpp (verus_use_sha3(), FEAT_SHA3 detection in
// cpu_features.c: Linux HWCAP_SHA3 / macOS hw.optional.arm.FEAT_SHA3) —
// these symbols are NEVER called on silicon without the extension, they
// just occupy ~40 KB. VERUS_SHA3=0 forces off; VERUS_SHA3=1 is only
// honored when the hardware reports FEAT_SHA3 (executing this TU without
// it is guaranteed SIGILL, so the env can't force-enable it).
#define CLHASH_SYM_SUFFIX _sha3

#include "clhash_native.c"
