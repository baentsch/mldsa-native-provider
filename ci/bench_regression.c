/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Performance-regression guard: this provider vs a minimal oqs-provider, on the
 * SAME machine, for plain ML-DSA-44/65/87. Both wrap the identical mldsa-native
 * core, so on the optimized platforms (x86_64 AVX2, AArch64 NEON) this provider
 * should be within a small factor of oqs-provider. If it is markedly slower it
 * almost always means our native backend silently regressed to portable C (as
 * happened once when the build stopped passing -mavx2). This program turns that
 * into a non-zero exit so a CI job can fail on it.
 *
 * It measures the CRYPTO, not EVP plumbing: keygen and sign are timed with a
 * REUSED EVP_PKEY_CTX, so per-call fetch/allocation overhead (which is equal for
 * both providers and would otherwise mask a 4x backend difference) is excluded.
 *
 * Two library contexts model the two stacks with no name ambiguity:
 *   ours = default + mldsanative   (names "ML-DSA-44/65/87")
 *   oqs  = default + oqsprovider   (names "mldsa44/65/87")
 * Run below OpenSSL 3.5, where oqs-provider actually serves ML-DSA (it cedes to
 * the default provider on 3.5+). Point OPENSSL_MODULES at a dir holding
 * mldsanative.so and oqsprovider.so.
 *
 * Env:
 *   MLDSA_BENCH_MAX_SLOWDOWN  allowed oqs/ours speed ratio before failing
 *                             (default 1.5). e.g. 1.5 => fail if oqs is >1.5x
 *                             faster than us on keygen or sign, any level.
 *   MLDSA_BENCH_SECONDS       seconds per measurement (default 0.5).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

static const unsigned char MSG[] = "mldsa regression-guard message";

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double g_seconds = 0.5;

static OSSL_LIB_CTX *mkctx(const char *extra)
{
    OSSL_LIB_CTX *c = OSSL_LIB_CTX_new();
    const char *m = getenv("OPENSSL_MODULES");

    if (c == NULL)
        return NULL;
    if (m != NULL)
        OSSL_PROVIDER_set_default_search_path(c, m);
    if (OSSL_PROVIDER_load(c, "default") == NULL
        || OSSL_PROVIDER_load(c, extra) == NULL) {
        fprintf(stderr, "provider load failed (default + %s)\n", extra);
        ERR_print_errors_fp(stderr);
        OSSL_LIB_CTX_free(c);
        return NULL;
    }
    return c;
}

/* keygen ops/sec, reusing one EVP_PKEY_CTX. */
static double bench_keygen(OSSL_LIB_CTX *c, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(c, alg, NULL);
    long n = 0;
    double t0, t1;

    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0) {
        EVP_PKEY_CTX_free(g);
        return 0.0;
    }
    t0 = now_s();
    do {
        EVP_PKEY *k = NULL;
        if (EVP_PKEY_keygen(g, &k) <= 0) { EVP_PKEY_CTX_free(g); return 0.0; }
        EVP_PKEY_free(k);
        n++;
    } while ((t1 = now_s()) - t0 < g_seconds);
    EVP_PKEY_CTX_free(g);
    return (double)n / (t1 - t0);
}

/* sign ops/sec, reusing one signing EVP_PKEY_CTX (pure ML-DSA sign). */
static double bench_sign(OSSL_LIB_CTX *c, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(c, alg, NULL);
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *sc = NULL;
    unsigned char sig[8192];
    size_t sl;
    long n = 0;
    double t0, t1, r = 0.0;

    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 || EVP_PKEY_keygen(g, &k) <= 0)
        goto end;
    sc = EVP_PKEY_CTX_new_from_pkey(c, k, NULL);
    if (sc == NULL || EVP_PKEY_sign_init(sc) <= 0)
        goto end;                        /* provider lacks one-shot sign API */
    sl = sizeof sig;
    if (EVP_PKEY_sign(sc, sig, &sl, MSG, sizeof MSG - 1) <= 0)
        goto end;
    t0 = now_s();
    do {
        sl = sizeof sig;
        if (EVP_PKEY_sign(sc, sig, &sl, MSG, sizeof MSG - 1) <= 0) { r = 0.0; goto end; }
        n++;
    } while ((t1 = now_s()) - t0 < g_seconds);
    r = (double)n / (t1 - t0);
 end:
    EVP_PKEY_CTX_free(sc);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(g);
    return r;
}

int main(void)
{
    OSSL_LIB_CTX *ours = mkctx("mldsanative");
    OSSL_LIB_CTX *oqs = mkctx("oqsprovider");
    struct { const char *ours; const char *oqs; } lv[] = {
        { "ML-DSA-44", "mldsa44" },
        { "ML-DSA-65", "mldsa65" },
        { "ML-DSA-87", "mldsa87" },
    };
    const char *e;
    double max_slowdown = (e = getenv("MLDSA_BENCH_MAX_SLOWDOWN")) ? atof(e) : 1.5;
    int i, failed = 0, measured = 0;

    if ((e = getenv("MLDSA_BENCH_SECONDS")) != NULL && atof(e) > 0)
        g_seconds = atof(e);
    if (ours == NULL || oqs == NULL)
        return 2;
    if (max_slowdown < 1.0)
        max_slowdown = 1.5;

    printf("ML-DSA performance vs oqs-provider (same mldsa-native core; "
           "fail if oqs > %.2fx faster):\n", max_slowdown);
    printf("  %-10s %-22s %-22s %-8s\n", "level", "ours (k ops/s)",
           "oqs (k ops/s)", "verdict");

    for (i = 0; i < 3; i++) {
        struct { const char *name; double (*fn)(OSSL_LIB_CTX *, const char *); }
            ops[] = { { "keygen", bench_keygen }, { "sign", bench_sign } };
        int j;

        for (j = 0; j < 2; j++) {
            double a = ops[j].fn(ours, lv[i].ours);
            double b = ops[j].fn(oqs, lv[i].oqs);
            const char *verdict;

            if (a <= 0.0 || b <= 0.0) {
                /* Can't measure this op on one side (e.g. no one-shot sign):
                 * skip rather than fail spuriously. */
                printf("  %-4s %-5s %-22s %-22s %s\n", lv[i].ours, ops[j].name,
                       a > 0 ? "ok" : "n/a", b > 0 ? "ok" : "n/a", "SKIP");
                continue;
            }
            measured++;
            if (b / a > max_slowdown) { verdict = "FAIL"; failed++; }
            else                        verdict = "ok";
            printf("  %-4s %-5s %-22.1f %-22.1f %.2fx  %s\n",
                   lv[i].ours, ops[j].name, a / 1e3, b / 1e3, b / a, verdict);
        }
    }

    OSSL_LIB_CTX_free(ours);
    OSSL_LIB_CTX_free(oqs);

    if (measured == 0) {
        fprintf(stderr, "no operations could be measured\n");
        return 2;
    }
    if (failed) {
        fprintf(stderr, "\nREGRESSION: %d operation(s) more than %.2fx slower "
                "than oqs-provider -- is the native backend active?\n",
                failed, max_slowdown);
        return 1;
    }
    printf("\nOK: within %.2fx of oqs-provider on all measured operations.\n",
           max_slowdown);
    return 0;
}
