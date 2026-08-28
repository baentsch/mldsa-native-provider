/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Known-answer test for the mldsa-native provider.
 *
 * Drives the provider through the public EVP API and checks its output against
 * the FIPS 204 test vectors shipped with mldsa-native:
 *   - deterministic keygen from a seed reproduces the expected public key;
 *   - deterministic signing (fixed rnd via TEST_ENTROPY, ctx "test_context_123")
 *     reproduces the expected signature;
 *   - the expected signature verifies.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

#include "mldsa_native_compat.h"
#include "mldsa_kat_vectors.h"

static int failures = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);    \
            ERR_print_errors_fp(stderr);                                       \
            failures++;                                                        \
            goto done;                                                         \
        }                                                                      \
    } while (0)

static EVP_PKEY *key_from_seed(OSSL_LIB_CTX *libctx, const char *name,
                               const uint8_t *seed)
{
    EVP_PKEY_CTX *cctx =
        EVP_PKEY_CTX_new_from_name(libctx, name, "provider=mldsanative");
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                  (void *)seed, 32);
    params[1] = OSSL_PARAM_construct_end();
    if (cctx == NULL
        || EVP_PKEY_fromdata_init(cctx) <= 0
        || EVP_PKEY_fromdata(cctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(cctx);
    return pkey;
}

static int kat_level(OSSL_LIB_CTX *libctx, const char *name,
                     const uint8_t *seed,
                     const uint8_t *exp_pub, size_t exp_pub_len,
                     const uint8_t *exp_sig, size_t exp_sig_len)
{
    int ok = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    unsigned char pub[4096];
    size_t publen = 0;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    OSSL_PARAM sparams[3];

    pkey = key_from_seed(libctx, name, seed);
    CHECK(pkey != NULL, "keygen-from-seed");

    /* (1) keygen KAT: derived public key matches the vector. */
    CHECK(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                          pub, sizeof(pub), &publen),
          "get pub");
    CHECK(publen == exp_pub_len && memcmp(pub, exp_pub, exp_pub_len) == 0,
          "public key KAT mismatch");

    /* (2) sign KAT: deterministic signature (fixed rnd) matches the vector.
     * Use EVP_PKEY_sign with explicit ctx params (version-robust across
     * OpenSSL 3.2-3.5, unlike EVP_DigestSign init-time params). */
    sctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=mldsanative");
    CHECK(sctx != NULL, "sign ctx");
    CHECK(EVP_PKEY_sign_init(sctx) > 0, "sign init");
    sparams[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)TEST_VECTOR_CTX,
        TEST_VECTOR_CTX_LEN);
    sparams[1] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_TEST_ENTROPY, (void *)seed, 32);
    sparams[2] = OSSL_PARAM_construct_end();
    CHECK(EVP_PKEY_CTX_set_params(sctx, sparams) > 0, "set sign params");
    CHECK(EVP_PKEY_sign(sctx, NULL, &siglen,
                        (const unsigned char *)TEST_VECTOR_MSG,
                        TEST_VECTOR_MSG_LEN) > 0, "sign size");
    sig = OPENSSL_malloc(siglen);
    CHECK(sig != NULL, "malloc sig");
    CHECK(EVP_PKEY_sign(sctx, sig, &siglen,
                        (const unsigned char *)TEST_VECTOR_MSG,
                        TEST_VECTOR_MSG_LEN) > 0, "sign");
    CHECK(siglen == exp_sig_len && memcmp(sig, exp_sig, exp_sig_len) == 0,
          "signature KAT mismatch");

    /* (3) verify KAT: expected signature verifies under the derived key. */
    vctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=mldsanative");
    CHECK(vctx != NULL, "verify ctx");
    CHECK(EVP_PKEY_verify_init(vctx) > 0, "verify init");
    sparams[1] = OSSL_PARAM_construct_end();  /* context only, no entropy */
    CHECK(EVP_PKEY_CTX_set_params(vctx, sparams) > 0, "set verify params");
    CHECK(EVP_PKEY_verify(vctx, exp_sig, exp_sig_len,
                          (const unsigned char *)TEST_VECTOR_MSG,
                          TEST_VECTOR_MSG_LEN) > 0, "verify KAT");

    printf("  %-10s KAT OK (pub=%zu sig=%zu)\n", name, publen, siglen);
    ok = 1;
 done:
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    EVP_PKEY_free(pkey);
    return ok;
}

int main(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *dflt = NULL, *mld = NULL;

    if (libctx == NULL)
        return 1;
    dflt = OSSL_PROVIDER_load(libctx, "default");
    mld = OSSL_PROVIDER_load(libctx, "mldsanative");
    if (dflt == NULL || mld == NULL) {
        fprintf(stderr, "provider load failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("mldsa-native provider KAT:\n");
    kat_level(libctx, "ML-DSA-44", test_vector_rnd,
              test_vector_pk_44, sizeof(test_vector_pk_44),
              test_vector_sig_44, sizeof(test_vector_sig_44));
    kat_level(libctx, "ML-DSA-65", test_vector_rnd,
              test_vector_pk_65, sizeof(test_vector_pk_65),
              test_vector_sig_65, sizeof(test_vector_sig_65));
    kat_level(libctx, "ML-DSA-87", test_vector_rnd,
              test_vector_pk_87, sizeof(test_vector_pk_87),
              test_vector_sig_87, sizeof(test_vector_sig_87));

    OSSL_PROVIDER_unload(mld);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);

    if (failures == 0)
        printf("ALL KAT PASSED\n");
    else
        printf("%d KAT FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}
