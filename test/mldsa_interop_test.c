/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Interoperability tests between the mldsa-native provider and the OpenSSL
 * default provider's ML-DSA, in a single library context (disambiguated by
 * "provider=" property queries):
 *
 *   1. seed expansion parity  - importing the same 32-byte seed into both
 *                               providers yields the identical public key;
 *   2. cross sign/verify      - a signature made by one provider verifies with
 *                               the other (both directions);
 *   3. key-file interop       - SPKI/PKCS8 PEM written by one provider is read
 *                               by the other (both directions), then used.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define OURS  "provider=mldsanative"
#define DEFLT "provider=default"

static int failures = 0;
static const char MSG[] = "interop message for ML-DSA cross sign/verify";

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);    \
            ERR_print_errors_fp(stderr);                                       \
            rv = 0;                                                            \
            goto done;                                                         \
        }                                                                      \
    } while (0)

static EVP_PKEY *key_from_seed(OSSL_LIB_CTX *libctx, const char *name,
                               const char *prov, const uint8_t *seed)
{
    EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_name(libctx, name, prov);
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                  (void *)seed, 32);
    params[1] = OSSL_PARAM_construct_end();
    if (cctx == NULL || EVP_PKEY_fromdata_init(cctx) <= 0
        || EVP_PKEY_fromdata(cctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(cctx);
    return pkey;
}

static EVP_PKEY *keygen(OSSL_LIB_CTX *libctx, const char *name, const char *prov)
{
    EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_name(libctx, name, prov);
    EVP_PKEY *pkey = NULL;

    if (cctx == NULL || EVP_PKEY_keygen_init(cctx) <= 0
        || EVP_PKEY_keygen(cctx, &pkey) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(cctx);
    return pkey;
}

static EVP_PKEY *pub_from_raw(OSSL_LIB_CTX *libctx, const char *name,
                              const char *prov, const unsigned char *pub,
                              size_t publen)
{
    EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_name(libctx, name, prov);
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (void *)pub, publen);
    params[1] = OSSL_PARAM_construct_end();
    if (cctx == NULL || EVP_PKEY_fromdata_init(cctx) <= 0
        || EVP_PKEY_fromdata(cctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(cctx);
    return pkey;
}

static int get_pub(EVP_PKEY *k, unsigned char *buf, size_t buflen, size_t *out)
{
    return EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, buf,
                                           buflen, out);
}

static int sign_msg(OSSL_LIB_CTX *libctx, EVP_PKEY *key, const char *prov,
                    unsigned char **sig, size_t *siglen)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int ok = 0;

    *sig = NULL;
    if (mdctx == NULL
        || EVP_DigestSignInit_ex(mdctx, NULL, NULL, libctx, prov, key,
                                 NULL) <= 0
        || EVP_DigestSign(mdctx, NULL, siglen, (const unsigned char *)MSG,
                          sizeof(MSG) - 1) <= 0)
        goto end;
    *sig = OPENSSL_malloc(*siglen);
    if (*sig == NULL
        || EVP_DigestSign(mdctx, *sig, siglen, (const unsigned char *)MSG,
                          sizeof(MSG) - 1) <= 0)
        goto end;
    ok = 1;
 end:
    EVP_MD_CTX_free(mdctx);
    return ok;
}

static int verify_msg(OSSL_LIB_CTX *libctx, EVP_PKEY *key, const char *prov,
                      const unsigned char *sig, size_t siglen)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int ok = 0;

    if (mdctx != NULL
        && EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, libctx, prov, key,
                                   NULL) > 0
        && EVP_DigestVerify(mdctx, sig, siglen, (const unsigned char *)MSG,
                            sizeof(MSG) - 1) > 0)
        ok = 1;
    EVP_MD_CTX_free(mdctx);
    return ok;
}

static int pkey_to_pem(EVP_PKEY *key, int selection, const char *structure,
                       const char *prov, unsigned char **pem, size_t *pemlen)
{
    BIO *mem = BIO_new(BIO_s_mem());
    OSSL_ENCODER_CTX *ectx;
    const unsigned char *data;
    long len;
    int ok = 0;

    ectx = OSSL_ENCODER_CTX_new_for_pkey(key, selection, "PEM", structure,
                                         prov);
    if (mem == NULL || ectx == NULL || OSSL_ENCODER_CTX_get_num_encoders(ectx) == 0)
        goto end;
    if (OSSL_ENCODER_to_bio(ectx, mem) <= 0)
        goto end;
    len = BIO_get_mem_data(mem, &data);
    if (len <= 0)
        goto end;
    *pem = OPENSSL_memdup(data, (size_t)len);
    if (*pem == NULL)
        goto end;
    *pemlen = (size_t)len;
    ok = 1;
 end:
    OSSL_ENCODER_CTX_free(ectx);
    BIO_free(mem);
    return ok;
}

static EVP_PKEY *pem_to_pkey(OSSL_LIB_CTX *libctx, const char *name,
                             const char *structure, int selection,
                             const char *prov, const unsigned char *pem,
                             size_t pemlen)
{
    BIO *mem = BIO_new_mem_buf(pem, (int)pemlen);
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", structure, name,
                                         selection, libctx, prov);
    if (mem != NULL && dctx != NULL)
        (void)OSSL_DECODER_from_bio(dctx, mem);
    OSSL_DECODER_CTX_free(dctx);
    BIO_free(mem);
    return pkey;
}

static int interop_level(OSSL_LIB_CTX *libctx, const char *name)
{
    int rv = 1;
    uint8_t seed[32];
    EVP_PKEY *ko = NULL, *kd = NULL, *tmp = NULL;
    unsigned char pub_o[4096], pub_d[4096];
    size_t publen_o = 0, publen_d = 0;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    unsigned char *pem = NULL;
    size_t pemlen = 0;

    /* ---- 1. seed expansion parity ---- */
    CHECK(RAND_bytes(seed, sizeof(seed)) > 0, "RAND_bytes");
    ko = key_from_seed(libctx, name, OURS, seed);
    kd = key_from_seed(libctx, name, DEFLT, seed);
    CHECK(ko != NULL, "seed->key (ours)");
    CHECK(kd != NULL, "seed->key (default)");
    CHECK(get_pub(ko, pub_o, sizeof(pub_o), &publen_o), "pub (ours)");
    CHECK(get_pub(kd, pub_d, sizeof(pub_d), &publen_d), "pub (default)");
    CHECK(publen_o == publen_d && memcmp(pub_o, pub_d, publen_o) == 0,
          "seed-expansion parity: public keys differ");

    /* ---- 2. cross sign/verify ---- */
    /* ours signs -> default verifies */
    CHECK(sign_msg(libctx, ko, OURS, &sig, &siglen), "sign (ours)");
    tmp = pub_from_raw(libctx, name, DEFLT, pub_o, publen_o);
    CHECK(tmp != NULL, "import pub into default");
    CHECK(verify_msg(libctx, tmp, DEFLT, sig, siglen),
          "default failed to verify our signature");
    EVP_PKEY_free(tmp);
    tmp = NULL;
    OPENSSL_free(sig);
    sig = NULL;

    /* default signs -> ours verifies */
    CHECK(sign_msg(libctx, kd, DEFLT, &sig, &siglen), "sign (default)");
    tmp = pub_from_raw(libctx, name, OURS, pub_d, publen_d);
    CHECK(tmp != NULL, "import pub into ours");
    CHECK(verify_msg(libctx, tmp, OURS, sig, siglen),
          "ours failed to verify default's signature");
    EVP_PKEY_free(tmp);
    tmp = NULL;
    OPENSSL_free(sig);
    sig = NULL;

    /* ---- 3a. our SPKI PEM -> default reads it -> verifies our signature ---- */
    CHECK(sign_msg(libctx, ko, OURS, &sig, &siglen), "sign (ours) for spki");
    CHECK(pkey_to_pem(ko, EVP_PKEY_PUBLIC_KEY, "SubjectPublicKeyInfo", OURS,
                      &pem, &pemlen), "encode our SPKI PEM");
    tmp = pem_to_pkey(libctx, name, "SubjectPublicKeyInfo",
                      EVP_PKEY_PUBLIC_KEY, DEFLT, pem, pemlen);
    CHECK(tmp != NULL, "default decode our SPKI PEM");
    CHECK(verify_msg(libctx, tmp, DEFLT, sig, siglen),
          "default verify via our SPKI PEM");
    EVP_PKEY_free(tmp);
    tmp = NULL;
    OPENSSL_free(pem);
    pem = NULL;
    OPENSSL_free(sig);
    sig = NULL;

    /* ---- 3b. our PKCS8 PEM -> default reads it -> signs -> ours verifies ---- */
    CHECK(pkey_to_pem(ko, EVP_PKEY_KEYPAIR, "PrivateKeyInfo", OURS,
                      &pem, &pemlen), "encode our PKCS8 PEM");
    tmp = pem_to_pkey(libctx, name, "PrivateKeyInfo", EVP_PKEY_KEYPAIR,
                      DEFLT, pem, pemlen);
    CHECK(tmp != NULL, "default decode our PKCS8 PEM");
    CHECK(sign_msg(libctx, tmp, DEFLT, &sig, &siglen),
          "default sign via our PKCS8 PEM");
    CHECK(verify_msg(libctx, ko, OURS, sig, siglen),
          "ours verify default sig from our PKCS8 PEM");
    EVP_PKEY_free(tmp);
    tmp = NULL;
    OPENSSL_free(pem);
    pem = NULL;
    OPENSSL_free(sig);
    sig = NULL;

    /* ---- 3c. default's PKCS8 PEM -> ours reads it -> signs -> default verifies -- */
    CHECK(pkey_to_pem(kd, EVP_PKEY_KEYPAIR, "PrivateKeyInfo", DEFLT,
                      &pem, &pemlen), "encode default PKCS8 PEM");
    tmp = pem_to_pkey(libctx, name, "PrivateKeyInfo", EVP_PKEY_KEYPAIR,
                      OURS, pem, pemlen);
    CHECK(tmp != NULL, "ours decode default PKCS8 PEM");
    CHECK(sign_msg(libctx, tmp, OURS, &sig, &siglen),
          "ours sign via default PKCS8 PEM");
    CHECK(verify_msg(libctx, kd, DEFLT, sig, siglen),
          "default verify ours sig from default PKCS8 PEM");

    printf("  %-10s interop OK\n", name);
 done:
    EVP_PKEY_free(tmp);
    EVP_PKEY_free(ko);
    EVP_PKEY_free(kd);
    OPENSSL_free(sig);
    OPENSSL_free(pem);
    if (!rv)
        failures++;
    return rv;
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

    printf("mldsa-native <-> default provider interop:\n");
    interop_level(libctx, "ML-DSA-44");
    interop_level(libctx, "ML-DSA-65");
    interop_level(libctx, "ML-DSA-87");

    OSSL_PROVIDER_unload(mld);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);

    if (failures == 0)
        printf("ALL INTEROP PASSED\n");
    else
        printf("%d INTEROP FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}
