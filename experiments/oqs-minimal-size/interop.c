/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Interop + micro-benchmark between two independent provider stacks that each
 * deliver ML-DSA (and the four ML-DSA concatenation hybrids), modelled as two
 * separate OpenSSL library contexts ("parties") so there is never any provider
 * ambiguity and no property queries are needed:
 *
 *   Party A ("ours") = default + mldsanative + hybrid-provider
 *                      (ML-DSA from mldsanative; ECDSA/RSA halves of a hybrid
 *                       from the default provider; hybrid-provider only glues)
 *   Party B ("oqs")  = default + oqs-provider
 *                      (ML-DSA and the hybrids from oqs-provider)
 *
 * One table drives both plain and hybrid cases. Each row names the algorithm as
 * each party spells it (they differ for plain ML-DSA -- "ML-DSA-44" vs "mldsa44"
 * -- and coincide for the hybrids) and the public-key transport used to move a
 * key from one party to the other:
 *
 *   RAW  -- the raw public key bytes via OSSL_PKEY_PARAM_PUB_KEY. This only works
 *           when both parties agree on the raw byte layout; they do for plain
 *           ML-DSA, so plain rows use RAW to demonstrate interop at that
 *           (stronger) level.
 *   SPKI -- a SubjectPublicKeyInfo DER blob via OSSL_ENCODER/OSSL_DECODER. The
 *           two hybrid implementations do NOT share a raw-parameter layout, so
 *           hybrid rows exchange keys at the wire format, which is byte-compatible.
 *
 * For every row: keygen + sign in party A, carry the public key to party B,
 * verify; then the same in the other direction. A --benchmark pass additionally
 * times each party's own sign and verify throughput for that algorithm.
 *
 * Runs on OpenSSL < 3.5 (e.g. 3.4.x): there the default provider has no ML-DSA
 * and oqs-provider does not cede it, so both external stacks actually serve it.
 * Point OPENSSL_MODULES at a directory holding mldsanative.so, hybrid.so and
 * oqsprovider.so.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/err.h>

enum { XPORT_RAW, XPORT_SPKI };

static const char MSG[] = "mldsa interop + benchmark message";
static int fails = 0;

/* ------------------------------------------------------------------ */
/* library contexts (one per party)                                    */
/* ------------------------------------------------------------------ */

static OSSL_LIB_CTX *mkctx(const char *const *provs)
{
    OSSL_LIB_CTX *c = OSSL_LIB_CTX_new();
    const char *m = getenv("OPENSSL_MODULES");
    size_t i;

    if (c == NULL)
        return NULL;
    if (m != NULL)
        OSSL_PROVIDER_set_default_search_path(c, m);
    for (i = 0; provs[i] != NULL; i++) {
        if (OSSL_PROVIDER_load(c, provs[i]) == NULL) {
            fprintf(stderr, "load %s failed\n", provs[i]);
            ERR_print_errors_fp(stderr);
            OSSL_LIB_CTX_free(c);
            return NULL;
        }
    }
    return c;
}

/* ------------------------------------------------------------------ */
/* key + signature primitives                                          */
/* ------------------------------------------------------------------ */

static EVP_PKEY *keygen(OSSL_LIB_CTX *c, const char *name)
{
    EVP_PKEY_CTX *x = EVP_PKEY_CTX_new_from_name(c, name, NULL);
    EVP_PKEY *k = NULL;

    if (x != NULL && EVP_PKEY_keygen_init(x) > 0)
        EVP_PKEY_keygen(x, &k);
    EVP_PKEY_CTX_free(x);
    return k;
}

/* Export the public key in the requested transport; *out is malloc'd. */
static int pub_export(EVP_PKEY *k, int xport, unsigned char **out, size_t *outlen)
{
    if (xport == XPORT_RAW) {
        size_t n = 0;
        if (EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY,
                                            NULL, 0, &n) <= 0
            || (*out = OPENSSL_malloc(n)) == NULL)
            return 0;
        if (EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY,
                                            *out, n, outlen) <= 0) {
            OPENSSL_free(*out);
            *out = NULL;
            return 0;
        }
        return 1;
    } else {
        OSSL_ENCODER_CTX *e = OSSL_ENCODER_CTX_new_for_pkey(
            k, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", NULL);
        int ok = e != NULL && OSSL_ENCODER_CTX_get_num_encoders(e) > 0
            && OSSL_ENCODER_to_data(e, out, outlen);
        OSSL_ENCODER_CTX_free(e);
        return ok;
    }
}

/* Rebuild a public-key EVP_PKEY in party |c| from transported bytes. */
static EVP_PKEY *pub_import(OSSL_LIB_CTX *c, const char *name, int xport,
                           const unsigned char *in, size_t inlen)
{
    if (xport == XPORT_RAW) {
        EVP_PKEY_CTX *x = EVP_PKEY_CTX_new_from_name(c, name, NULL);
        EVP_PKEY *k = NULL;
        OSSL_PARAM pr[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                              (void *)in, inlen),
            OSSL_PARAM_construct_end()
        };
        if (x != NULL && EVP_PKEY_fromdata_init(x) > 0)
            EVP_PKEY_fromdata(x, &k, EVP_PKEY_PUBLIC_KEY, pr);
        EVP_PKEY_CTX_free(x);
        return k;
    } else {
        EVP_PKEY *k = NULL;
        const unsigned char *p = in;
        size_t plen = inlen;
        OSSL_DECODER_CTX *d = OSSL_DECODER_CTX_new_for_pkey(
            &k, "DER", "SubjectPublicKeyInfo", name, EVP_PKEY_PUBLIC_KEY, c, NULL);
        if (d != NULL)
            (void)OSSL_DECODER_from_data(d, &p, &plen);
        OSSL_DECODER_CTX_free(d);
        return k;
    }
}

static int sign(OSSL_LIB_CTX *c, EVP_PKEY *k, unsigned char **sig, size_t *slen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = 0;

    *sig = NULL;
    if (m != NULL
        && EVP_DigestSignInit_ex(m, NULL, NULL, c, NULL, k, NULL) > 0
        && EVP_DigestSign(m, NULL, slen, (const unsigned char *)MSG,
                          sizeof(MSG) - 1) > 0
        && (*sig = OPENSSL_malloc(*slen)) != NULL
        && EVP_DigestSign(m, *sig, slen, (const unsigned char *)MSG,
                          sizeof(MSG) - 1) > 0)
        ok = 1;
    EVP_MD_CTX_free(m);
    return ok;
}

static int verify(OSSL_LIB_CTX *c, EVP_PKEY *k,
                  const unsigned char *sig, size_t slen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = m != NULL
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, c, NULL, k, NULL) > 0
        && EVP_DigestVerify(m, sig, slen, (const unsigned char *)MSG,
                            sizeof(MSG) - 1) > 0;
    EVP_MD_CTX_free(m);
    return ok;
}

/* ------------------------------------------------------------------ */
/* the driving table                                                   */
/* ------------------------------------------------------------------ */

struct row {
    const char *kind;    /* "plain" or "hybrid" -- display only            */
    const char *name_a;  /* algorithm name as party A spells it            */
    const char *name_b;  /* algorithm name as party B spells it            */
    int xport;           /* XPORT_RAW or XPORT_SPKI                        */
};

static const struct row rows[] = {
    { "plain",  "ML-DSA-44", "mldsa44", XPORT_RAW  },
    { "plain",  "ML-DSA-65", "mldsa65", XPORT_RAW  },
    { "plain",  "ML-DSA-87", "mldsa87", XPORT_RAW  },
    { "hybrid", "p256_mldsa44",    "p256_mldsa44",    XPORT_SPKI },
    { "hybrid", "rsa3072_mldsa44", "rsa3072_mldsa44", XPORT_SPKI },
    { "hybrid", "p384_mldsa65",    "p384_mldsa65",    XPORT_SPKI },
    { "hybrid", "p521_mldsa87",    "p521_mldsa87",    XPORT_SPKI },
};
#define NROWS ((int)(sizeof(rows) / sizeof(rows[0])))

/* ------------------------------------------------------------------ */
/* interop: sign in |from|, verify in |to|                             */
/* ------------------------------------------------------------------ */

static void interop_one(OSSL_LIB_CTX *from, const char *from_name,
                        OSSL_LIB_CTX *to, const char *to_name,
                        int xport, const char *label)
{
    EVP_PKEY *sk = keygen(from, from_name), *vk = NULL;
    unsigned char *pub = NULL, *sig = NULL;
    size_t publen = 0, slen = 0;

    if (sk == NULL
        || !pub_export(sk, xport, &pub, &publen)
        || !sign(from, sk, &sig, &slen)
        || (vk = pub_import(to, to_name, xport, pub, publen)) == NULL
        || !verify(to, vk, sig, slen)) {
        fprintf(stderr, "  FAIL  %s\n", label);
        ERR_print_errors_fp(stderr);
        fails++;
    } else {
        printf("  ok    %-34s (%s=%zu sig=%zu)\n", label,
               xport == XPORT_RAW ? "pub" : "spki", publen, slen);
    }
    OPENSSL_free(pub);
    OPENSSL_free(sig);
    EVP_PKEY_free(sk);
    EVP_PKEY_free(vk);
}

/* ------------------------------------------------------------------ */
/* benchmark: each party's own sign/verify throughput                  */
/* ------------------------------------------------------------------ */

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Run |op| back-to-back for at least MIN_S seconds; return ops/second. */
#define MIN_S 0.30
static double rate(int (*op)(void *), void *arg)
{
    double t0, t1;
    long n = 0;

    /* warm up once (JIT-free C, but primes caches / lazy fetches) */
    if (!op(arg))
        return 0.0;
    t0 = now_s();
    do {
        if (!op(arg)) return 0.0;
        n++;
    } while ((t1 = now_s()) - t0 < MIN_S);
    return (double)n / (t1 - t0);
}

struct signarg { OSSL_LIB_CTX *c; EVP_PKEY *k; };
static int op_sign(void *a)
{
    struct signarg *s = a;
    unsigned char *sig = NULL;
    size_t slen = 0;
    int ok = sign(s->c, s->k, &sig, &slen);
    OPENSSL_free(sig);
    return ok;
}

struct verarg { OSSL_LIB_CTX *c; EVP_PKEY *k; const unsigned char *sig; size_t slen; };
static int op_verify(void *a)
{
    struct verarg *v = a;
    return verify(v->c, v->k, v->sig, v->slen);
}

/* Benchmark one algorithm in one party. Returns 0 on setup failure. */
static int bench_party(OSSL_LIB_CTX *c, const char *name,
                       double *sign_ops, double *verify_ops)
{
    EVP_PKEY *k = keygen(c, name);
    unsigned char *sig = NULL;
    size_t slen = 0;
    struct signarg sa;
    struct verarg va;

    if (k == NULL || !sign(c, k, &sig, &slen)) {
        EVP_PKEY_free(k);
        OPENSSL_free(sig);
        return 0;
    }
    sa.c = c; sa.k = k;
    va.c = c; va.k = k; va.sig = sig; va.slen = slen;
    *sign_ops = rate(op_sign, &sa);
    *verify_ops = rate(op_verify, &va);
    EVP_PKEY_free(k);
    OPENSSL_free(sig);
    return 1;
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *ours_provs[] = { "default", "mldsanative", "hybrid", NULL };
    const char *oqs_provs[]  = { "default", "oqsprovider", NULL };
    OSSL_LIB_CTX *ours = mkctx(ours_provs), *oqs = mkctx(oqs_provs);
    int do_bench = (argc > 1 && strcmp(argv[1], "--benchmark") == 0);
    int i;

    if (ours == NULL || oqs == NULL)
        return 1;

    printf("Interop: (default+mldsanative+hybrid) <-> (default+oqsprovider)\n");
    for (i = 0; i < NROWS; i++) {
        const struct row *r = &rows[i];
        char la[80], lb[80];

        snprintf(la, sizeof(la), "%-6s ours %s -> oqs verify", r->kind, r->name_a);
        snprintf(lb, sizeof(lb), "%-6s oqs  %s -> ours verify", r->kind, r->name_b);
        interop_one(ours, r->name_a, oqs, r->name_b, r->xport, la);
        interop_one(oqs, r->name_b, ours, r->name_a, r->xport, lb);
    }
    printf(fails ? "  %d INTEROP FAILURE(S)\n" : "  ALL INTEROP PASSED\n", fails);

    if (do_bench) {
        printf("\nBenchmark (sign / verify, thousands of ops per second; "
               "higher is better):\n");
        printf("  %-16s %-28s %-28s\n", "algorithm",
               "ours (mldsanative/hybrid)", "oqs-provider");
        for (i = 0; i < NROWS; i++) {
            const struct row *r = &rows[i];
            double as = 0, av = 0, bs = 0, bv = 0;
            int oka = bench_party(ours, r->name_a, &as, &av);
            int okb = bench_party(oqs, r->name_b, &bs, &bv);

            printf("  %-16s ", r->name_a);
            if (oka) printf("sign %7.1f  verify %7.1f    ", as / 1e3, av / 1e3);
            else     printf("%-28s", "(unavailable)");
            if (okb) printf("sign %7.1f  verify %7.1f\n", bs / 1e3, bv / 1e3);
            else     printf("%s\n", "(unavailable)");
        }
        printf("  (same ML-DSA core both sides -- liboqs's ML-DSA *is* "
               "mldsa-native; this measures packaging/backend, not the algorithm)\n");
    }

    OSSL_LIB_CTX_free(ours);
    OSSL_LIB_CTX_free(oqs);
    return fails ? 1 : 0;
}
