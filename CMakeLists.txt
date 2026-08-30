cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(mldsa-native-provider LANGUAGES C)

#
# An external OpenSSL 3.2+ provider implementing ML-DSA (FIPS 204) signatures
# ONLY, using the mldsa-native implementation (git submodule) directly. No KEM,
# no delegation to OpenSSL's own ML-DSA.
#

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# The provider itself only needs 3.0-era provider APIs; 3.2 is the tested floor
# (matching oqs-provider). Interop against the *default* provider's ML-DSA needs
# 3.5 and self-skips below that.
find_package(OpenSSL 3.2 REQUIRED)

# Where to load the provider .so from during tests, and the runtime lib path.
get_filename_component(OPENSSL_LIB_DIR "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)

# ---- mldsa-native (git submodule, multi-level monolithic build) ----
# The crypto comes from a pinned submodule; only small integration glue (the
# multi-level wrapper and our config) lives in this repo. The submodule stays
# pristine -- configuration is injected via -DMLD_CONFIG_FILE.
set(MLDSA_SUBMODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mldsa-native")
set(MLDSA_SRC_DIR "${MLDSA_SUBMODULE_DIR}/mldsa")
set(MLDSA_GLUE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mldsa_glue")
set(MLDSA_NATIVE_SRC "${MLDSA_GLUE_DIR}/mldsa_native_all.c")

if(NOT EXISTS "${MLDSA_SRC_DIR}/mldsa_native.c")
    message(FATAL_ERROR
        "mldsa-native submodule not found at ${MLDSA_SRC_DIR}.\n"
        "Run: git submodule update --init --recursive")
endif()

# mldsa-native ships optimized assembly backends for x86_64 (AVX2) and AArch64;
# elsewhere it falls back to portable C (like OpenSSL's cross-platform ML-DSA).
# AUTO enables the native backend on supported CPUs, PORTABLE forces C.
set(MLDSA_NATIVE_BACKEND "AUTO" CACHE STRING
    "mldsa-native arithmetic/FIPS202 backend: AUTO, NATIVE, or PORTABLE")

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _mld_arch)
set(_mld_asm "")
set(MLDSA_BACKEND_DESC "portable C")
if(NOT MLDSA_NATIVE_BACKEND STREQUAL "PORTABLE")
    if(_mld_arch MATCHES "x86_64|amd64|aarch64|arm64")
        enable_language(ASM)
        set(_mld_asm "${MLDSA_SRC_DIR}/mldsa_native_asm.S")
        set(MLDSA_BACKEND_DESC "native (${_mld_arch} asm)")
    elseif(MLDSA_NATIVE_BACKEND STREQUAL "NATIVE")
        message(FATAL_ERROR
            "MLDSA_NATIVE_BACKEND=NATIVE but no asm backend for ${_mld_arch}")
    endif()
endif()
message(STATUS "mldsa-native backend: ${MLDSA_BACKEND_DESC}")

# Native-backend switches apply only to the amalgamation and the asm; the
# out-of-tree config (MLD_CONFIG_FILE) is injected target-wide below, since every
# TU that includes the mldsa-native headers needs the multi-level config.
set(_mld_native_defs "")
if(_mld_asm)
    set(_mld_native_defs
        MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
        MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202)
endif()

# Architecture flags the native backend needs to ACTUALLY emit its optimized
# code. On x86_64 both the AVX2 assembly bodies and the C dispatch that calls
# them are gated on __AVX2__ (Keccak/arith) and use BMI2; without -mavx2 -mbmi2
# on *both* the amalgamation and the assembly, mldsa-native silently falls back
# to portable C -- roughly 4x slower -- while still advertising "native asm".
# These flags are scoped to the mldsa-native sources; the provider's own C stays
# architecture-neutral.
#
# Consequence: a native x86_64 build requires an AVX2-capable CPU at run time.
# Use MLDSA_NATIVE_BACKEND=PORTABLE for a universal binary. On AArch64 the NEON
# backend needs no extra flags (NEON is ARMv8-A baseline, __ARM_NEON predefined).
set(_mld_native_flags "")
if(_mld_asm AND _mld_arch MATCHES "x86_64|amd64")
    set(_mld_native_flags -mavx2 -mbmi2)
endif()

# Compile the amalgamation without our stricter provider warnings, plus any
# native flags. (list(APPEND ...) with empty flags is a no-op, so PORTABLE and
# AArch64 builds get a clean "-w" with no stray empty compiler argument.)
set(_mld_amalg_opts -w)
list(APPEND _mld_amalg_opts ${_mld_native_flags})
set_source_files_properties(${MLDSA_NATIVE_SRC} PROPERTIES
    COMPILE_OPTIONS "${_mld_amalg_opts}"
    COMPILE_DEFINITIONS "${_mld_native_defs}")
if(_mld_asm)
    set_source_files_properties(${_mld_asm} PROPERTIES
        COMPILE_DEFINITIONS "${_mld_native_defs};MLD_CONFIG_MULTILEVEL_WITH_SHARED")
    if(_mld_native_flags)
        set_source_files_properties(${_mld_asm} PROPERTIES
            COMPILE_OPTIONS "${_mld_native_flags}")
    endif()
endif()

set(PROVIDER_SOURCES
    mldsa_native_prov.c
    mldsa_native_keymgmt.c
    mldsa_native_sig.c
    mldsa_native_encoder.c
    mldsa_native_decoder.c
    ${MLDSA_NATIVE_SRC}
    ${_mld_asm}
)

add_library(mldsanative MODULE ${PROVIDER_SOURCES})

# Inject our config into every TU (the submodule stays pristine) and expose the
# active backend via the provider's build-info string.
target_compile_definitions(mldsanative PRIVATE
    "MLD_CONFIG_FILE=\"mldsa_provider_config.h\""
    "MLDSANATIVE_BACKEND_STR=\"${MLDSA_BACKEND_DESC}\"")

target_include_directories(mldsanative PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MLDSA_GLUE_DIR}
    ${MLDSA_SRC_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(mldsanative PRIVATE OpenSSL::Crypto)

# A provider is loaded by filename: mldsanative.so (no "lib" prefix).
set_target_properties(mldsanative PROPERTIES
    PREFIX ""
    OUTPUT_NAME "mldsanative"
)
if(APPLE)
    set_target_properties(mldsanative PROPERTIES SUFFIX ".dylib")
else()
    set_target_properties(mldsanative PROPERTIES SUFFIX ".so")
endif()

target_compile_options(mldsanative PRIVATE -Wall -Wextra)

# ---- tests ----
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()
