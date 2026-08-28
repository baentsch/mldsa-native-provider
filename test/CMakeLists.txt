# Tests for the mldsa-native provider. Each test loads the provider from the
# build directory (OPENSSL_MODULES) and the default provider from the OpenSSL
# install used to build (LD_LIBRARY_PATH).

set(TEST_ENV
    "OPENSSL_MODULES=$<TARGET_FILE_DIR:mldsanative>"
    "LD_LIBRARY_PATH=${OPENSSL_LIB_DIR}"
)

add_executable(mldsa_kat_test mldsa_kat_test.c)
target_include_directories(mldsa_kat_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(mldsa_kat_test PRIVATE OpenSSL::Crypto)

add_executable(mldsa_interop_test mldsa_interop_test.c)
target_include_directories(mldsa_interop_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(mldsa_interop_test PRIVATE OpenSSL::Crypto)

add_test(NAME kat COMMAND mldsa_kat_test)
add_test(NAME interop COMMAND mldsa_interop_test)

set_tests_properties(kat interop PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    DEPENDS mldsanative)
