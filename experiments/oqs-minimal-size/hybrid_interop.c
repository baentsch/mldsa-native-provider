/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hybrid interop between two independent stacks, modelled as two separate
 * library contexts (two parties), so there is no provider ambiguity:
 *
 *   ctxA "ours"  = default + mldsanative + hybrid-provider
 *                  (hybrid composes ECDSA/RSA from default with ML-DSA from
 *                   mldsanative -- the only ML-DSA provider in ctxA)
 *   ctxB "oqs"   = default + oqs-provider
 *
 * For each ML-DSA concatenation hybrid (p256_mldsa44 / rsa3072_mldsa44 /
 * p384_mldsa65 / p521_mldsa87): sign in one stack, export the public key as
 * SubjectPublicKeyInfo DER, import into the other stack, verify. Both ways.
 *
 * Run on OpenSSL < 3.5 (oqs-provider serves ML-DSA/hybrids there; on 3.5 it
 * cedes plain ML-DSA to the default provider). Set OPENSSL_MODULES to a dir
 * holding mldsanative.so, hybrid.so and oqsprovider.so.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/err.h>

static int fails = 0;
static const char MSG[] = "hybrid stack interop message";

static OSSL_LIB_CTX *mkctx(const char *const *provs)
{
    OSSL_LIB_CTX *c = OSSL_LIB_CTX_new();
    const char *m = getenv("OPENSSL_MODULES");
    size_t i;
    if (c == NULL)
        return NULL;
    if (m != NULL)
        OSSL_PROVIDER_set_default_search_path(c, m);
    for (i = 0; provs[i] != NULL; i++)
        if (OSSL_PROVIDER_load(c, provs[i]) == NULL) {
            fprintf(stderr, "load %s failed\n", provs[i]);
            ERR_print_errors_fp(stderr);
            OSSL_LIB_CTX_free(c);
            return NULL;
        }
    return c;
}

static EVP_PKEY *keygen(OSSL_LIB_CTX *c, const char *name)
{
    EVP_PKEY_CTX *x = EVP_PKEY_CTX_new_from_name(c, name, NULL);
    EVP_PKEY *k = NULL;
    if (x && EVP_PKEY_keygen_init(x) > 0)
        EVP_PKEY_keygen(x, &k);
    EVP_PKEY_CTX_free(x);
    return k;
}

static int pub_to_spki(EVP_PKEY *k, unsigned char **der, size_t *derlen)
{
    OSSL_ENCODER_CTX *e = OSSL_ENCODER_CTX_new_for_pkey(
        k, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", NULL);
    int ok = e && OSSL_ENCODER_CTX_get_num_encoders(e) > 0
        && OSSL_ENCODER_to_data(e, der, derlen);
    OSSL_ENCODER_CTX_free(e);
    return ok;
}

static EVP_PKEY *spki_to_pub(OSSL_LIB_CTX *c, const char *name,
                             const unsigned char *der, size_t derlen)
{
    EVP_PKEY *k = NULL;
    const unsigned char *p = der;
    size_t plen = derlen;
    OSSL_DECODER_CTX *d = OSSL_DECODER_CTX_new_for_pkey(
        &k, "DER", "SubjectPublicKeyInfo", name, EVP_PKEY_PUBLIC_KEY, c, NULL);
    if (d != NULL)
        (void)OSSL_DECODER_from_data(d, &p, &plen);
    OSSL_DECODER_CTX_free(d);
    return k;
}

static int sign(OSSL_LIB_CTX *c, EVP_PKEY *k, unsigned char **s, size_t *sl)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = 0;
    *s = NULL;
    if (m && EVP_DigestSignInit_ex(m, NULL, NULL, c, NULL, k, NULL) > 0
        && EVP_DigestSign(m, NULL, sl, (const unsigned char *)MSG, sizeof(MSG) - 1) > 0
        && (*s = OPENSSL_malloc(*sl)) != NULL
        && EVP_DigestSign(m, *s, sl, (const unsigned char *)MSG, sizeof(MSG) - 1) > 0)
        ok = 1;
    EVP_MD_CTX_free(m);
    return ok;
}

static int verify(OSSL_LIB_CTX *c, EVP_PKEY *k, const unsigned char *s, size_t sl)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = m && EVP_DigestVerifyInit_ex(m, NULL, NULL, c, NULL, k, NULL) > 0
        && EVP_DigestVerify(m, s, sl, (const unsigned char *)MSG, sizeof(MSG) - 1) > 0;
    EVP_MD_CTX_free(m);
    return ok;
}

static void one_way(OSSL_LIB_CTX *from, OSSL_LIB_CTX *to, const char *alg,
                    const char *label)
{
    EVP_PKEY *sk = keygen(from, alg), *vk = NULL;
    unsigned char *der = NULL, *sig = NULL;
    size_t derlen = 0, slen = 0;

    if (sk == NULL || !pub_to_spki(sk, &der, &derlen) || !sign(from, sk, &sig, &slen)
        || (vk = spki_to_pub(to, alg, der, derlen)) == NULL
        || !verify(to, vk, sig, slen)) {
        fprintf(stderr, "FAIL: %s\n", label);
        ERR_print_errors_fp(stderr);
        fails++;
    } else {
        printf("  ok  %s (spki=%zu sig=%zu)\n", label, derlen, slen);
    }
    OPENSSL_free(sig);
    OPENSSL_free(der);
    EVP_PKEY_free(sk);
    EVP_PKEY_free(vk);
}

int main(void)
{
    const char *ours_provs[] = { "default", "mldsanative", "hybrid", NULL };
    const char *oqs_provs[]  = { "default", "oqsprovider", NULL };
    OSSL_LIB_CTX *ours = mkctx(ours_provs), *oqs = mkctx(oqs_provs);
    const char *algs[] = { "p256_mldsa44", "rsa3072_mldsa44",
                           "p384_mldsa65", "p521_mldsa87" };
    size_t i;

    if (ours == NULL || oqs == NULL)
        return 1;
    printf("(mldsanative+hybrid-provider) <-> oqs-provider hybrid interop:\n");
    for (i = 0; i < 4; i++) {
        char l1[80], l2[80];
        snprintf(l1, sizeof(l1), "ours %s -> oqs verify", algs[i]);
        snprintf(l2, sizeof(l2), "oqs  %s -> ours verify", algs[i]);
        one_way(ours, oqs, algs[i], l1);
        one_way(oqs, ours, algs[i], l2);
    }
    OSSL_LIB_CTX_free(ours);
    OSSL_LIB_CTX_free(oqs);
    printf(fails ? "%d FAILURE(S)\n" : "ALL HYBRID INTEROP PASSED\n", fails);
    return fails ? 1 : 0;
}
