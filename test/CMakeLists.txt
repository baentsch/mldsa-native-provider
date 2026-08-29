# Tests for the mldsa-native provider. Each test loads the provider from the
# build directory (OPENSSL_MODULES) and the default provider from the OpenSSL
# install used to build (LD_LIBRARY_PATH).

set(TEST_ENV
    "OPENSSL_MODULES=$<TARGET_FILE_DIR:mldsanative>"
    "LD_LIBRARY_PATH=${OPENSSL_LIB_DIR}"
)

# KAT vectors come from the pinned mldsa-native submodule example directory.
set(MLDSA_KAT_VECTORS_DIR
    "${CMAKE_SOURCE_DIR}/third_party/mldsa-native/examples/monolithic_build_multilevel")

add_executable(mldsa_kat_test mldsa_kat_test.c)
target_include_directories(mldsa_kat_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}
    ${MLDSA_KAT_VECTORS_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(mldsa_kat_test PRIVATE OpenSSL::Crypto)

add_executable(mldsa_interop_test mldsa_interop_test.c)
target_include_directories(mldsa_interop_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(mldsa_interop_test PRIVATE OpenSSL::Crypto)

add_executable(mldsa_tls_test mldsa_tls_test.c)
target_include_directories(mldsa_tls_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(mldsa_tls_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_test(NAME kat COMMAND mldsa_kat_test)
add_test(NAME interop COMMAND mldsa_interop_test)
add_test(NAME tls COMMAND mldsa_tls_test)

set_tests_properties(kat interop PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    DEPENDS mldsanative)
# tls self-skips (77) on OpenSSL >= 3.5 (capability inactive) or if SSL_CTX
# init is unavailable; CI's fresh openssl-3.2 build exercises the real handshake.
set_tests_properties(tls PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    SKIP_RETURN_CODE 77
    DEPENDS mldsanative)

# IETF pqc-certificates cross-implementation interop (self-skips w/o network).
get_filename_component(OPENSSL_BIN_DIR "${OPENSSL_LIB_DIR}/../bin" ABSOLUTE)
find_program(OPENSSL_APP openssl HINTS "${OPENSSL_BIN_DIR}" NO_DEFAULT_PATH)
if(NOT OPENSSL_APP)
    find_program(OPENSSL_APP openssl)
endif()

add_test(NAME ietf_interop
    COMMAND ${CMAKE_COMMAND} -E env
        "OPENSSL=${OPENSSL_APP}"
        "OPENSSL_LIBPATH=${OPENSSL_LIB_DIR}"
        "MODULE_DIR=$<TARGET_FILE_DIR:mldsanative>"
        bash "${CMAKE_CURRENT_SOURCE_DIR}/ietf_pqc_interop.sh")
set_tests_properties(ietf_interop PROPERTIES SKIP_RETURN_CODE 77)
