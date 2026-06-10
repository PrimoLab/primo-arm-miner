cmake_minimum_required(VERSION 3.10)
project(primo-arm-miner VERSION 1.0.5 LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(PRIMO_LINKER "lld" CACHE STRING "Linker driver name for -fuse-ld=<name>; set empty to use the compiler default")

# Device profile selector — mirrors the Makefile's PROFILE variable:
#   rk3588  (default) — validated on RK3588 (A55+A76): A76 hand-scheduled asm
#                       in the Verus hot path plus the A53 errata workaround.
#   generic           — portable build for other cores (phones, other SBCs).
#                       Disables the A76 hand-asm / fixed-unroll paths and the
#                       A53 errata workaround, but keeps the a53 tune (bench
#                       data: it generalises better than -mtune=native):
#                         cmake -DPRIMO_PROFILE=generic ..
set(PRIMO_PROFILE "rk3588" CACHE STRING "Device profile: rk3588 or generic")

# Match the promoted ccminer baseline profile on this device.
# The validated winner tuned for A55/A53-style codegen, not the earlier A76 profile.
set(PRIMO_BASE_ARCH_FLAGS "-march=armv8-a+crypto -mtune=cortex-a53")
set(PRIMO_COMMON_FLAGS "-O3 -ffinite-loops -ffast-math -D_REENTRANT -DUSE_DIRECT_NATIVE_CALL=1 -falign-functions=16 -fomit-frame-pointer -fpic -pthread -flto -fno-stack-protector -flax-vector-conversions -Wall")
if(PRIMO_PROFILE STREQUAL "generic")
    string(APPEND PRIMO_COMMON_FLAGS
        " -DUSE_A76_ASM_AES_MIX2=0 -DUSE_A76_ASM_CASE18_CLMUL=0"
        " -DUSE_A76_ASM_XOR_LOW32=0 -DUSE_A76_CASE18_FIXEDCOUNT=0"
        " -DUSE_A76_CASE18_MASK_PTRS=0 -DUSE_A76_FIXKEY_UNROLL=0")
elseif(PRIMO_PROFILE STREQUAL "rk3588")
    string(APPEND PRIMO_COMMON_FLAGS " -mfix-cortex-a53-835769")
else()
    message(FATAL_ERROR "Unknown PRIMO_PROFILE '${PRIMO_PROFILE}' (expected rk3588 or generic)")
endif()
set(PRIMO_C_ONLY_FLAGS "")
set(PRIMO_SCRYPT_NOSLP_FLAG "-fno-tree-slp-vectorize")
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(PRIMO_C_ONLY_FLAGS "-mllvm -enable-loop-distribute")
    set(PRIMO_SCRYPT_NOSLP_FLAG "-fno-slp-vectorize")
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${PRIMO_BASE_ARCH_FLAGS} ${PRIMO_COMMON_FLAGS} ${PRIMO_C_ONLY_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PRIMO_BASE_ARCH_FLAGS} ${PRIMO_COMMON_FLAGS} -funroll-loops")

# Find required libraries
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

# Find jansson (JSON library)
find_library(JANSSON_LIBRARY NAMES jansson)
find_path(JANSSON_INCLUDE_DIR jansson.h)

if(NOT JANSSON_LIBRARY OR NOT JANSSON_INCLUDE_DIR)
    message(FATAL_ERROR "jansson library not found. Install with: sudo apt-get install libjansson-dev")
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CURL_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIR}
)

# Source files
set(SOURCES
    src/main.cpp
    src/config.cpp
    src/api.cpp
    src/miner.cpp
    src/dev_fee.cpp
    src/stratum.cpp
    src/stratum_state.cpp
    src/stratum_job.cpp
    src/stratum_rpc.cpp
    src/stratum_handshake.cpp
    src/stratum_session.cpp
    src/stratum_transport.cpp
    src/stratum_standard.cpp
    src/stratum_verus.cpp
    src/algorithm/verus.cpp
    src/algorithm/clhash_native.c
    src/algorithm/haraka_native.c
    src/algorithm/cpu_features.c
    src/algorithm/sha256_neon.c
    src/algorithm/scrypt_neon.c
    src/algorithm/sha256_ce_asm.S
    src/algorithm/scrypt_blockmix_asm.S
    src/utils/log.cpp
)

# Executable
add_executable(primo-arm-miner ${SOURCES})

# Match Makefile behavior for per-file hot-path tuning.
set_source_files_properties(
    src/algorithm/scrypt_neon.c
    PROPERTIES COMPILE_OPTIONS "${PRIMO_SCRYPT_NOSLP_FLAG}"
)
set_source_files_properties(
    src/algorithm/clhash_native.c
    src/algorithm/haraka_native.c
    PROPERTIES COMPILE_OPTIONS "-fno-unroll-loops"
)

# Link libraries
target_link_libraries(primo-arm-miner
    ${CURL_LIBRARIES}
    ${JANSSON_LIBRARY}
    Threads::Threads
    m
)

# Match the promoted ccminer baseline linker shape.
if(PRIMO_LINKER)
    target_link_options(primo-arm-miner PRIVATE "-flto" "-fuse-ld=${PRIMO_LINKER}")
else()
    target_link_options(primo-arm-miner PRIVATE "-flto")
endif()

if(PRIMO_LINKER STREQUAL "lld")
    target_link_options(primo-arm-miner PRIVATE "-Wl,-hugetlbfs-align")
endif()

# Installation
install(TARGETS primo-arm-miner DESTINATION bin)
