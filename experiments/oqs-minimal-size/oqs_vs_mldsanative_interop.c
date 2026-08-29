/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Interop between this provider (mldsanative, "ML-DSA-44/65/87") and a
 * minimal ML-DSA-only oqs-provider ("mldsa44/65/87", backed by a minimal
 * liboqs). Cross sign/verify in both directions via raw public-key exchange.
 *
 * Run on OpenSSL < 3.5 (e.g. 3.4.x): there the default provider has no ML-DSA
 * and oqs-provider does NOT cede ML-DSA, so both external providers serve it.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

static int fails = 0;
static const char MSG[] = "oqs<->mldsanative interop message";

static EVP_PKEY *keygen(OSSL_LIB_CTX *c, const char *name, const char *prov)
{
    EVP_PKEY_CTX *x = EVP_PKEY_CTX_new_from_name(c, name, prov);
    EVP_PKEY *k = NULL;
    if (x && EVP_PKEY_keygen_init(x) > 0)
        EVP_PKEY_keygen(x, &k);
    EVP_PKEY_CTX_free(x);
    return k;
}

static int getpub(EVP_PKEY *k, unsigned char *b, size_t n, size_t *o)
{
    return EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, b, n, o);
}

static EVP_PKEY *pub_from_raw(OSSL_LIB_CTX *c, const char *name,
                             const char *prov, const unsigned char *p, size_t n)
{
    EVP_PKEY_CTX *x = EVP_PKEY_CTX_new_from_name(c, name, prov);
    EVP_PKEY *k = NULL;
    OSSL_PARAM pr[2] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)p, n),
        OSSL_PARAM_construct_end()
    };
    if (x && EVP_PKEY_fromdata_init(x) > 0)
        EVP_PKEY_fromdata(x, &k, EVP_PKEY_PUBLIC_KEY, pr);
    EVP_PKEY_CTX_free(x);
    return k;
}

static int sign(OSSL_LIB_CTX *c, EVP_PKEY *k, const char *prov,
                unsigned char **sig, size_t *slen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = 0;
    *sig = NULL;
    if (m && EVP_DigestSignInit_ex(m, NULL, NULL, c, prov, k, NULL) > 0
        && EVP_DigestSign(m, NULL, slen, (const unsigned char *)MSG,
                          sizeof(MSG) - 1) > 0
        && (*sig = OPENSSL_malloc(*slen)) != NULL
        && EVP_DigestSign(m, *sig, slen, (const unsigned char *)MSG,
                          sizeof(MSG) - 1) > 0)
        ok = 1;
    EVP_MD_CTX_free(m);
    return ok;
}

static int verify(OSSL_LIB_CTX *c, EVP_PKEY *k, const char *prov,
                  const unsigned char *sig, size_t slen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = m
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, c, prov, k, NULL) > 0
        && EVP_DigestVerify(m, sig, slen, (const unsigned char *)MSG,
                            sizeof(MSG) - 1) > 0;
    EVP_MD_CTX_free(m);
    return ok;
}

static void one_way(OSSL_LIB_CTX *c, const char *from_name, const char *from,
                    const char *to_name, const char *to, const char *label)
{
    EVP_PKEY *sk = keygen(c, from_name, from), *vk = NULL;
    unsigned char pub[4096], *sig = NULL;
    size_t publen = 0, slen = 0;

    if (sk == NULL || !getpub(sk, pub, sizeof(pub), &publen)
        || !sign(c, sk, from, &sig, &slen)
        || (vk = pub_from_raw(c, to_name, to, pub, publen)) == NULL
        || !verify(c, vk, to, sig, slen)) {
        fprintf(stderr, "FAIL: %s\n", label);
        ERR_print_errors_fp(stderr);
        fails++;
    } else {
        printf("  ok  %s (pub=%zu sig=%zu)\n", label, publen, slen);
    }
    OPENSSL_free(sig);
    EVP_PKEY_free(sk);
    EVP_PKEY_free(vk);
}

int main(void)
{
    OSSL_LIB_CTX *c = OSSL_LIB_CTX_new();
    const char *OURS = "provider=mldsanative", *OQS = "provider=oqsprovider";
    struct { const char *ours; const char *oqs; } lv[] = {
        { "ML-DSA-44", "mldsa44" },
        { "ML-DSA-65", "mldsa65" },
        { "ML-DSA-87", "mldsa87" },
    };
    size_t i;

    if (!OSSL_PROVIDER_load(c, "default")
        || !OSSL_PROVIDER_load(c, "mldsanative")
        || !OSSL_PROVIDER_load(c, "oqsprovider")) {
        fprintf(stderr, "provider load failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("mldsa-native-provider <-> minimal oqs-provider interop:\n");
    for (i = 0; i < 3; i++) {
        char l1[64], l2[64];
        snprintf(l1, sizeof(l1), "%s sign -> %s verify", lv[i].ours, lv[i].oqs);
        snprintf(l2, sizeof(l2), "%s sign -> %s verify", lv[i].oqs, lv[i].ours);
        one_way(c, lv[i].ours, OURS, lv[i].oqs, OQS, l1);
        one_way(c, lv[i].oqs, OQS, lv[i].ours, OURS, l2);
    }
    OSSL_LIB_CTX_free(c);
    printf(fails ? "%d FAILURE(S)\n" : "ALL INTEROP PASSED\n", fails);
    return fails ? 1 : 0;
}
