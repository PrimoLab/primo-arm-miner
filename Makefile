# Primo ARM Miner Makefile

PRIMO_LINKER ?= lld

ifeq ($(origin CC), default)
CC = clang-16
endif

ifeq ($(origin CXX), default)
CXX = clang++-16
endif

CC_VERSION_LINE := $(shell $(CC) --version 2>/dev/null | head -1 | tr '[:upper:]' '[:lower:]')
CC_IS_CLANG := $(findstring clang,$(CC_VERSION_LINE))

# Device profile selector:
#   rk3588  (default) — validated on RK3588 (A55+A76): A76 hand-scheduled asm
#                       in the Verus hot path plus A53-style codegen tuning.
#   generic           — portable build for other cores (phones, other SBCs).
#                       Disables the A76 hand-asm / fixed-unroll paths and the
#                       A53 errata workaround, but keeps the a53 tune (bench
#                       data: it generalises better than -mtune=native). Lets
#                       the compiler schedule the portable intrinsics:
#                         make PROFILE=generic
PROFILE ?= rk3588

COMMON_CPPFLAGS = -flax-vector-conversions -I./include -I./src
DEPFLAGS = -MMD -MP
COMMON_OPT_FLAGS = -O3 -ffinite-loops -ffast-math
COMMON_OPT_FLAGS += -D_REENTRANT -DUSE_DIRECT_NATIVE_CALL=1
COMMON_OPT_FLAGS += -falign-functions=16 -fomit-frame-pointer -fpic
COMMON_OPT_FLAGS += -pthread -flto -fno-stack-protector -Wall

# ISA and scheduling baseline. These default to the validated winner
# (-march=armv8-a+crypto, -mtune=cortex-a53 — see notes below) but are exposed
# as overridable knobs so CI can A/B build flags per device WITHOUT editing the
# Makefile. `?=` means an env var or a `make PRIMO_MARCH=...` arg wins; the
# default is unchanged when nothing is passed. Do NOT default-bump these to
# armv8.2-a (LSE atomics SIGILL on ARMv8.0 cores — see the Termux build).
PRIMO_MARCH ?= armv8-a+crypto
PRIMO_MTUNE ?= cortex-a53

ifeq ($(PROFILE),generic)
# Portable intrinsics for unknown / non-A76 cores. The A76 hand-scheduled asm
# is frozen to one microarch and is only a ~2-4% win even where it helps, so it
# is dropped here in favour of compiler-scheduled intrinsics. The a53 tune is
# kept on purpose: bench data shows conservative -mtune=cortex-a53 generalises
# better than -mtune=native even on the A76, so it is the safest default across
# heterogeneous cores. The a53 errata workaround is dropped (not an A53).
BASE_ARCH_FLAGS = -march=$(PRIMO_MARCH) -mtune=$(PRIMO_MTUNE)
COMMON_OPT_FLAGS += -DUSE_A76_ASM_AES_MIX2=0 -DUSE_A76_ASM_CASE18_CLMUL=0
COMMON_OPT_FLAGS += -DUSE_A76_ASM_XOR_LOW32=0 -DUSE_A76_CASE18_FIXEDCOUNT=0
COMMON_OPT_FLAGS += -DUSE_A76_CASE18_MASK_PTRS=0 -DUSE_A76_FIXKEY_UNROLL=0
else
# Match the promoted ccminer baseline profile on this device.
# The validated winner tuned for A55/A53-style codegen, not the earlier A76 profile.
BASE_ARCH_FLAGS = -march=$(PRIMO_MARCH) -mtune=$(PRIMO_MTUNE)
COMMON_OPT_FLAGS += -mfix-cortex-a53-835769
endif

# Last-resort full replacement of the arch/tune flags for a one-off CI probe.
ifneq ($(strip $(PRIMO_ARCH_FLAGS_OVERRIDE)),)
BASE_ARCH_FLAGS = $(PRIMO_ARCH_FLAGS_OVERRIDE)
endif

# Additive per-build extra flags (empty by default — append, never replace).
PRIMO_CPPFLAGS = $(COMMON_CPPFLAGS) $(PRIMO_EXTRA_CPPFLAGS)
PRIMO_CFLAGS = $(BASE_ARCH_FLAGS) $(COMMON_OPT_FLAGS) -std=gnu11 $(PRIMO_EXTRA_CFLAGS)
PRIMO_CXXFLAGS = $(BASE_ARCH_FLAGS) $(COMMON_OPT_FLAGS) -funroll-loops -std=c++14 $(PRIMO_EXTRA_CXXFLAGS)
PRIMO_LDFLAGS = -flto -pthread $(PRIMO_EXTRA_LDFLAGS)
PRIMO_LDLIBS = -lcurl -ljansson -lm
ifneq ($(strip $(PRIMO_LDLIBS_OVERRIDE)),)
PRIMO_LDLIBS = $(PRIMO_LDLIBS_OVERRIDE)
endif

ifneq ($(CC_IS_CLANG),)
PRIMO_CFLAGS += -mllvm -enable-loop-distribute
SCRYPT_NOSLP_FLAG = -fno-slp-vectorize
else
SCRYPT_NOSLP_FLAG = -fno-tree-slp-vectorize
endif

ifneq ($(strip $(PRIMO_LINKER)),)
PRIMO_LDFLAGS += -fuse-ld=$(PRIMO_LINKER)
endif

ifeq ($(strip $(PRIMO_LINKER)),lld)
PRIMO_LDFLAGS += -Wl,-hugetlbfs-align
endif

CPPFLAGS += $(PRIMO_CPPFLAGS)
CFLAGS += $(PRIMO_CFLAGS)
CXXFLAGS += $(PRIMO_CXXFLAGS)
LDFLAGS += $(PRIMO_LDFLAGS)
LDLIBS += $(PRIMO_LDLIBS)

# Optional per-file override for CLHash experiments, e.g.
# make CLHASH_EXTRA_FLAGS="-DUSE_A76_CASE18_MASK_PTRS=0"
CLHASH_EXTRA_FLAGS ?=

SOURCES_C = \
	src/algorithm/clhash_native.c \
	src/algorithm/haraka_native.c \
	src/algorithm/cpu_features.c \
	src/algorithm/scrypt_neon.c \
	src/algorithm/sha256_neon.c

SOURCES_CPP = \
	src/main.cpp \
	src/config.cpp \
	src/api.cpp \
	src/miner.cpp \
	src/dev_fee.cpp \
	src/stratum.cpp \
	src/stratum_state.cpp \
	src/stratum_job.cpp \
	src/stratum_rpc.cpp \
	src/stratum_handshake.cpp \
	src/stratum_transport.cpp \
	src/stratum_session.cpp \
	src/stratum_standard.cpp \
	src/stratum_verus.cpp \
	src/algorithm/verus.cpp \
	src/utils/log.cpp

SOURCES_ASM = \
	src/algorithm/sha256_ce_asm.S \
	src/algorithm/scrypt_blockmix_asm.S

OBJECTS = $(SOURCES_C:.c=.o) $(SOURCES_CPP:.cpp=.o) $(SOURCES_ASM:.S=.o)

TARGET = primo-arm-miner

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $(TARGET)
	@echo "Build complete!"
	@ls -lh $(TARGET)

# Scrypt needs -fno-slp-vectorize: the in-place XOR loops get SLP-vectorized
# to NEON, causing NEON→scalar store forwarding penalty when scalar Salsa reads B
src/algorithm/scrypt_neon.o: src/algorithm/scrypt_neon.c
	@echo "Compiling $< (no SLP vectorize)..."
	$(CC) $(CPPFLAGS) $(DEPFLAGS) $(CFLAGS) $(SCRYPT_NOSLP_FLAG) -c $< -o $@

# Verus hot-path C files: match ccminer's exact compile environment.
# -fno-unroll-loops: ccminer CFLAGS omits -funroll-loops for C files; these
#   hand-tuned NEON/PMULL/AES intrinsics benefit from no extra unrolling.
# Global CPPFLAGS already provide:
#   -flax-vector-conversions
# NOTE: -fno-strict-aliasing is intentionally NOT set — its removal gives
#   +1.1-1.2% on Verus (CLHash mixed pointer types benefit from strict
#   aliasing letting the compiler reorder loads/stores). See CLAUDE.md.
src/algorithm/clhash_native.o: src/algorithm/clhash_native.c
	@echo "Compiling $< (no unroll-loops)..."
	$(CC) $(CPPFLAGS) $(DEPFLAGS) $(CFLAGS) -fno-unroll-loops $(CLHASH_EXTRA_FLAGS) -c $< -o $@

src/algorithm/haraka_native.o: src/algorithm/haraka_native.c
	@echo "Compiling $< (no unroll-loops)..."
	$(CC) $(CPPFLAGS) $(DEPFLAGS) $(CFLAGS) -fno-unroll-loops -c $< -o $@

%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CPPFLAGS) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	@echo "Compiling $<..."
	$(CXX) $(CPPFLAGS) $(DEPFLAGS) $(CXXFLAGS) -c $< -o $@

%.o: %.S
	@echo "Assembling $<..."
	$(CC) $(CPPFLAGS) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) $(TARGET)
	@echo "Clean complete"

-include $(OBJECTS:.o=.d)
