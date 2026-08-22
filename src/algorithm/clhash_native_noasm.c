// This TU recompiles clhash_native.c, whose hashing core carries Apache-2.0
// translation ancestry (Copyright (c) 2018 Michael Toutonghi; CLHash
// Copyright (c) 2017, 2018 Daniel Lemire and Owen Kaser) — see the header
// of clhash_native.c and LICENSES/Apache-2.0.txt.
//
// Portable (no-asm) build of the CLHash hot loop. Compiled alongside the asm
// build (plain clhash_native.c, which defaults CLHASH_SYM_SUFFIX to _asm).
// verus.cpp picks per thread at runtime and currently selects _asm on every
// core; this build is the forced VERUS_ASM=0 path and the bit-exactness
// reference the selftest and the per-share full-hash check compare against.
// See include/clhash_native.h for the dispatch contract.
//
// Setting the CLHASH_ASM_* macros to 0 before the include makes clhash_native.h's
// #ifndef guards keep them off, so this TU compiles the pure-C fallbacks.
#define CLHASH_SYM_SUFFIX _noasm
#define CLHASH_ASM_AES_MIX2 0
#define CLHASH_ASM_CASE18_CLMUL 0
#define CLHASH_ASM_XOR_LOW32 0
#define CLHASH_ASM_CASE18_FIXEDCOUNT 0
#define CLHASH_ASM_CASE18_MASK_PTRS 0

#include "clhash_native.c"
