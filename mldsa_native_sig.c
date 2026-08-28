/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ML-DSA signature operation for the mldsa-native provider.
 *
 * Only "pure" ML-DSA (FIPS 204) is implemented: the message representative is
 * M' = 0x00 || len(ctx) || ctx || M, matching the OpenSSL default provider's
 * default behaviour. Signing is randomized by default (or deterministic when
 * OSSL_SIGNATURE_PARAM_DETERMINISTIC is set), verification is deterministic;
 * signatures therefore cross-verify with the default provider.
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>

#include "mldsa_native_prov.h"

typedef struct prov_mldsa_sigctx_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    MLDSA_KEY *key;            /* not owned */
    int operation;

    uint8_t *context_string;
    size_t context_string_len;

    int deterministic;        /* 0 = randomized (default) */
    int msg_encoding;         /* 1 = pure (default) */

    int have_test_entropy;    /* KAT: inject a fixed signing rnd */
    uint8_t test_entropy[MLDSA_RND_LEN];

    /* Accumulator for the EVP_DigestSign/Verify streaming interface. */
    uint8_t *mem;
    size_t mem_len;
    size_t mem_size;

    uint8_t *aid;
    size_t aid_len;
} PROV_MLDSA_SIGCTX;

static void mldsa_sig_freectx(void *vctx);

static void *mldsa_sig_newctx(void *provctx, const char *propq)
{
    PROV_MLDSA_SIGCTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;
    ctx->libctx = PROV_MLDSA_LIBCTX(provctx);
    ctx->msg_encoding = 1;
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

static void mldsa_sig_freectx(void *vctx)
{
    PROV_MLDSA_SIGCTX *ctx = vctx;

    if (ctx == NULL)
        return;
    OPENSSL_free(ctx->propq);
    OPENSSL_free(ctx->context_string);
    OPENSSL_free(ctx->mem);
    OPENSSL_free(ctx->aid);
    OPENSSL_free(ctx);
}

static void *mldsa_sig_dupctx(void *vctx)
{
    PROV_MLDSA_SIGCTX *src = vctx;
    PROV_MLDSA_SIGCTX *dst;

    if (src == NULL)
        return NULL;
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;
    dst->libctx = src->libctx;
    dst->key = src->key;
    dst->operation = src->operation;
    dst->deterministic = src->deterministic;
    dst->msg_encoding = src->msg_encoding;
    if (src->propq != NULL && (dst->propq = OPENSSL_strdup(src->propq)) == NULL)
        goto err;
    if (src->context_string != NULL && src->context_string_len > 0) {
        dst->context_string = OPENSSL_memdup(src->context_string,
                                             src->context_string_len);
        if (dst->context_string == NULL)
            goto err;
        dst->context_string_len = src->context_string_len;
    }
    if (src->mem != NULL && src->mem_len > 0) {
        dst->mem = OPENSSL_memdup(src->mem, src->mem_len);
        if (dst->mem == NULL)
            goto err;
        dst->mem_len = dst->mem_size = src->mem_len;
    }
    if (src->aid != NULL && src->aid_len > 0) {
        dst->aid = OPENSSL_memdup(src->aid, src->aid_len);
        if (dst->aid == NULL)
            goto err;
        dst->aid_len = src->aid_len;
    }
    return dst;
 err:
    mldsa_sig_freectx(dst);
    return NULL;
}

/* Build the cached DER AlgorithmIdentifier for this key's OID (params absent). */
static int mldsa_sig_build_aid(PROV_MLDSA_SIGCTX *ctx)
{
    X509_ALGOR *alg = NULL;
    ASN1_OBJECT *obj;
    unsigned char *der = NULL;
    int derlen;

    if (ctx->aid != NULL || ctx->key == NULL)
        return ctx->aid != NULL;
    obj = OBJ_txt2obj(ctx->key->params->oid, 1);
    if (obj == NULL)
        return 0;
    alg = X509_ALGOR_new();
    if (alg == NULL) {
        ASN1_OBJECT_free(obj);
        return 0;
    }
    if (!X509_ALGOR_set0(alg, obj, V_ASN1_UNDEF, NULL)) {
        ASN1_OBJECT_free(obj);
        X509_ALGOR_free(alg);
        return 0;
    }
    derlen = i2d_X509_ALGOR(alg, &der);
    X509_ALGOR_free(alg);
    if (derlen <= 0)
        return 0;
    ctx->aid = der;
    ctx->aid_len = (size_t)derlen;
    return 1;
}

static int mldsa_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int mldsa_sig_signverify_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[], int operation)
{
    PROV_MLDSA_SIGCTX *ctx = vctx;

    if (ctx == NULL)
        return 0;
    if (vkey != NULL)
        ctx->key = vkey;
    if (ctx->key == NULL)
        return 0;
    ctx->operation = operation;
    ctx->mem_len = 0;
    return mldsa_sig_set_ctx_params(ctx, params);
}

static int mldsa_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return mldsa_sig_signverify_init(vctx, vkey, params, EVP_PKEY_OP_SIGN);
}

static int mldsa_sig_verify_init(void *vctx, void *vkey,
                                 const OSSL_PARAM params[])
{
    return mldsa_sig_signverify_init(vctx, vkey, params, EVP_PKEY_OP_VERIFY);
}

static int mldsa_do_sign(PROV_MLDSA_SIGCTX *ctx, unsigned char *sig,
                         size_t *siglen, size_t sigsize,
                         const unsigned char *tbs, size_t tbslen)
{
    const MLDSA_PARAMS *mp = ctx->key->params;

    if (sig == NULL) {
        *siglen = mp->sig_len;
        return 1;
    }
    if (sigsize < mp->sig_len) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (!ctx->key->has_priv) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    if (ctx->deterministic || ctx->have_test_entropy) {
        uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];
        uint8_t rnd[MLDSA_RND_LEN];
        size_t prelen;

        /* Deterministic uses rnd = 0; a supplied test entropy overrides it. */
        memset(rnd, 0, sizeof(rnd));
        if (ctx->have_test_entropy)
            memcpy(rnd, ctx->test_entropy, sizeof(rnd));
        prelen = mp->prep_prefix(pre, NULL, 0, ctx->context_string,
                                 ctx->context_string_len, MLD_PREHASH_NONE);
        if (prelen == 0) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
        if (mp->sign_internal(sig, tbs, tbslen, pre, prelen, rnd,
                              ctx->key->priv, 0) != 0) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        if (mp->sign(sig, tbs, tbslen, ctx->context_string,
                     ctx->context_string_len, ctx->key->priv) != 0) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    *siglen = mp->sig_len;
    return 1;
}

static int mldsa_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                          size_t sigsize, const unsigned char *tbs,
                          size_t tbslen)
{
    PROV_MLDSA_SIGCTX *ctx = vctx;

    if (ctx == NULL || ctx->key == NULL)
        return 0;
    return mldsa_do_sign(ctx, sig, siglen, sigsize, tbs, tbslen);
}

static int mldsa_do_verify(PROV_MLDSA_SIGCTX *ctx, const unsigned char *sig,
                           size_t siglen, const unsigned char *tbs,
                           size_t tbslen)
{
    const MLDSA_PARAMS *mp = ctx->key->params;

    if (!ctx->key->has_pub) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (siglen != mp->sig_len)
        return 0;
    return mp->verify(sig, tbs, tbslen, ctx->context_string,
                      ctx->context_string_len, ctx->key->pub) == 0;
}

static int mldsa_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                            const unsigned char *tbs, size_t tbslen)
{
    PROV_MLDSA_SIGCTX *ctx = vctx;

    if (ctx == NULL || ctx->key == NULL)
        return 0;
    return mldsa_do_verify(ctx, sig, siglen, tbs, tbslen);
}

/* ---------- streaming (EVP_DigestSign/Verify) ---------- */

static int mldsa_sig_digest_signverify_init(void *vctx, const char *mdname,
                                            void *vkey,
                                            const OSSL_PARAM params[],
                                            int operation)
{
    PROV_MLDSA_SIGCTX *ctx = vctx;

    if (mdname != NULL && mdname[0] != '\0') {
        /* Pure ML-DSA does not take an external digest. */
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    return mldsa_sig_signverify_init(ctx, vkey, params, operation);
}

static int mldsa_sig_digest_sign_init(void *vctx, const char *mdname,
                                      void *vkey, const OSSL_PARAM params[])
{
    return mldsa_sig_digest_signverify_init(vctx, mdname, vkey, params,
                                            EVP_PKEY_OP_SIGN);
}

static int mldsa_sig_digest_verify_init(void *vctx, const char *mdname,
                                        void *vkey, const OSSL_PARAM params[])
{
    return mldsa_sig_digest_signverify_init(vctx, mdname, vkey, params,
                                            EVP_PKEY_OP_VERIFY);
}

static int mldsa_sig_digest_signverify_update(void *vctx,
                                              const unsigned char *data,
                                              size_t datalen)
{
    PROV_MLDSA_SIGCTX *ctx = vctx;
    size_t need;

    if (ctx == NULL)
        return 0;
    if (datalen == 0)
        return 1;
    need = ctx->mem_len + datalen;
    if (need < ctx->mem_len)
        return 0;
    if (need > ctx->mem_size) {
        size_t newsize = ctx->mem_size == 0 ? 256 : ctx->mem_size;
        uint8_t *tmp;

        while (newsize < need)
            newsize *= 2;
        tmp = OPENSSL_realloc(ctx->mem, newsize);
        if (tmp == NULL)
            return 0;
        ctx->mem = tmp;
        ctx->mem_size = newsize;
    }
    memcpy(ctx->mem + ctx->mem_len, data, datalen);
    ctx->mem_len = need;
    return 1;
}

static int mldsa_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                       size_t *siglen, size_t sigsize)
{
    PROV_MLDSA_SIGCTX *ctx = vctx;

    if (ctx == NULL || ctx->key == NULL)
        return 0;
    return mldsa_do_sign(ctx, sig, siglen, sigsize, ctx->mem, ctx->mem_len);
}

static int mldsa_sig_digest_verify_final(void *vctx, const unsigned char *sig,
                                         size_t siglen)
{
    PROV_MLDSA_SIGCTX *ctx = vctx;

    if (ctx == NULL || ctx->key == NULL)
        return 0;
    return mldsa_do_verify(ctx, sig, siglen, ctx->mem, ctx->mem_len);
}

/* ---------- ctx params ---------- */

static int mldsa_sig_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    PROV_MLDSA_SIGCTX *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL) {
        if (!mldsa_sig_build_aid(ctx)
            || !OSSL_PARAM_set_octet_string(p, ctx->aid, ctx->aid_len))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *mldsa_sig_gettable_ctx_params(void *vctx,
                                                       void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END
    };
    (void)vctx;
    (void)provctx;
    return gettable;
}

static int mldsa_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_MLDSA_SIGCTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        void *data = NULL;
        size_t datalen = 0;

        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (p->data_size > 255) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
        if (p->data_size > 0
            && (data = OPENSSL_memdup(p->data, p->data_size)) == NULL)
            return 0;
        OPENSSL_free(ctx->context_string);
        ctx->context_string = data;
        ctx->context_string_len = datalen = p->data_size;
        (void)datalen;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->deterministic))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->msg_encoding))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || p->data_size != MLDSA_RND_LEN)
            return 0;
        memcpy(ctx->test_entropy, p->data, MLDSA_RND_LEN);
        ctx->have_test_entropy = 1;
    }
    return 1;
}

static const OSSL_PARAM *mldsa_sig_settable_ctx_params(void *vctx,
                                                       void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, NULL),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)vctx;
    (void)provctx;
    return settable;
}

const OSSL_DISPATCH mldsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))mldsa_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))mldsa_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))mldsa_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))mldsa_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))mldsa_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))mldsa_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))mldsa_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))mldsa_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))mldsa_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))mldsa_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))mldsa_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))mldsa_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))mldsa_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
      (void (*)(void))mldsa_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))mldsa_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
      (void (*)(void))mldsa_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))mldsa_sig_settable_ctx_params },
    { 0, NULL }
};
