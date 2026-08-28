cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(mldsa-native-provider LANGUAGES C)

#
# An external OpenSSL 3.5+ provider implementing ML-DSA (FIPS 204) signatures
# ONLY, using the vendored mldsa-native implementation directly. No KEM, no
# delegation to OpenSSL's own ML-DSA.
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

# ---- vendored mldsa-native (multi-level monolithic build) ----
set(MLDSA_NATIVE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor")
set(MLDSA_NATIVE_SRC "${MLDSA_NATIVE_DIR}/mldsa_native_all.c")

# Compile the amalgamation without our stricter provider warnings.
set_source_files_properties(${MLDSA_NATIVE_SRC} PROPERTIES
    COMPILE_OPTIONS "-w")

set(PROVIDER_SOURCES
    mldsa_native_prov.c
    mldsa_native_keymgmt.c
    mldsa_native_sig.c
    mldsa_native_encoder.c
    mldsa_native_decoder.c
    ${MLDSA_NATIVE_SRC}
)

add_library(mldsanative MODULE ${PROVIDER_SOURCES})

target_include_directories(mldsanative PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MLDSA_NATIVE_DIR}
    ${MLDSA_NATIVE_DIR}/mldsa_native
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
