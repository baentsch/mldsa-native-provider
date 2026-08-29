/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * In-process TLS 1.3 handshake using an ML-DSA server certificate, driven by
 * this provider's TLS-SIGALG capability. Server and client run in one library
 * context (default + mldsanative) over a BIO pair; a successful handshake means
 * libssl negotiated the ML-DSA signature scheme, the server produced a
 * CertificateVerify with ML-DSA, and the client verified it -- all via this
 * provider.
 *
 * This provider only advertises the ML-DSA TLS-SIGALG capability on OpenSSL
 * < 3.5 (on 3.5+ the default provider does it), so the test self-skips (exit 77)
 * on 3.5+ and also if the local libssl cannot initialise an SSL_CTX.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

static int skip(const char *why) { printf("SKIP: %s\n", why); return 77; }

static int make_mldsa_cert(OSSL_LIB_CTX *ctx, const char *alg,
                           EVP_PKEY **pkey_out, X509 **cert_out)
{
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(ctx, alg, NULL);
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    X509_NAME *name;
    int ok = 0;

    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
        || EVP_PKEY_keygen(gctx, &pkey) <= 0)
        goto end;
    if ((cert = X509_new_ex(ctx, NULL)) == NULL)
        goto end;
    if (!X509_set_version(cert, X509_VERSION_3)
        || !ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
        || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L) == NULL
        || !X509_set_pubkey(cert, pkey))
        goto end;
    name = X509_get_subject_name(cert);
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)"localhost", -1, -1, 0)
        || !X509_set_issuer_name(cert, name))
        goto end;
    /* ML-DSA is a pure signature: no external digest (md == NULL). */
    if (!X509_sign(cert, pkey, NULL))
        goto end;
    *pkey_out = pkey; pkey = NULL;
    *cert_out = cert; cert = NULL;
    ok = 1;
 end:
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return ok;
}

static int handshake(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *s = NULL, *c = NULL;
    BIO *sbio = NULL, *cbio = NULL;
    int ret = 0, i;

    if (!make_mldsa_cert(ctx, alg, &pkey, &cert)) {
        fprintf(stderr, "cert gen failed for %s\n", alg);
        ERR_print_errors_fp(stderr);
        goto end;
    }
    sctx = SSL_CTX_new_ex(ctx, NULL, TLS_server_method());
    cctx = SSL_CTX_new_ex(ctx, NULL, TLS_client_method());
    if (sctx == NULL || cctx == NULL) {
        ret = -1;   /* SSL_CTX init unavailable in this environment */
        goto end;
    }
    SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    if (SSL_CTX_use_certificate(sctx, cert) <= 0
        || SSL_CTX_use_PrivateKey(sctx, pkey) <= 0) {
        fprintf(stderr, "server cert/key install failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    s = SSL_new(sctx);
    c = SSL_new(cctx);
    if (s == NULL || c == NULL)
        goto end;
    if (BIO_new_bio_pair(&sbio, 0, &cbio, 0) != 1)
        goto end;
    SSL_set_bio(s, sbio, sbio);
    SSL_set_bio(c, cbio, cbio);
    SSL_set_accept_state(s);
    SSL_set_connect_state(c);

    for (i = 0; i < 20; i++) {
        int cs = SSL_do_handshake(c);
        int ss = SSL_do_handshake(s);
        if (SSL_is_init_finished(c) && SSL_is_init_finished(s)) {
            ret = 1;
            break;
        }
        (void)cs; (void)ss;
    }
    if (ret != 1) {
        fprintf(stderr, "handshake did not finish for %s\n", alg);
        ERR_print_errors_fp(stderr);
    }
 end:
    SSL_free(s);
    SSL_free(c);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return ret;
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    const char *algs[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
    int i, fails = 0, ran = 0;

    if (OpenSSL_version_num() >= 0x30500000L)
        return skip("OpenSSL >= 3.5: ML-DSA TLS-SIGALG comes from the default "
                    "provider; this provider's capability is inactive there");

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL)
        return 1;
    OSSL_PROVIDER_set_default_search_path(ctx, getenv("OPENSSL_MODULES"));
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
        || OSSL_PROVIDER_load(ctx, "mldsanative") == NULL) {
        fprintf(stderr, "provider load failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("ML-DSA TLS 1.3 handshake via mldsanative TLS-SIGALG capability:\n");
    for (i = 0; i < 3; i++) {
        int r = handshake(ctx, algs[i]);
        if (r == -1) {
            OSSL_LIB_CTX_free(ctx);
            return skip("libssl cannot initialise SSL_CTX in this environment");
        }
        if (r == 1) { printf("  ok  %s TLS handshake\n", algs[i]); ran++; }
        else { printf("  FAIL %s\n", algs[i]); fails++; }
    }
    OSSL_LIB_CTX_free(ctx);
    if (fails == 0 && ran > 0) { printf("ALL TLS HANDSHAKES PASSED\n"); return 0; }
    return fails ? 1 : skip("no handshakes ran");
}
