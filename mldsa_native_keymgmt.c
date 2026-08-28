/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ML-DSA key management for the mldsa-native provider.
 */

#include <string.h>
#include <strings.h>

#include <openssl/crypto.h>
#include <openssl/param_build.h>

#include "mldsa_native_prov.h"

/* ------------------------------------------------------------------ */
/* Key object helpers                                                  */
/* ------------------------------------------------------------------ */

MLDSA_KEY *mldsa_key_new(OSSL_LIB_CTX *libctx, const char *propq,
                         const MLDSA_PARAMS *params)
{
    MLDSA_KEY *key = OPENSSL_zalloc(sizeof(*key));

    if (key == NULL)
        return NULL;
    key->libctx = libctx;
    key->params = params;
    if (propq != NULL && (key->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(key);
        return NULL;
    }
    return key;
}

void mldsa_key_free(MLDSA_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_free(key->pub);
    if (key->priv != NULL)
        OPENSSL_clear_free(key->priv, key->params->sk_len);
    OPENSSL_cleanse(key->seed, sizeof(key->seed));
    OPENSSL_free(key->propq);
    OPENSSL_free(key);
}

static int mldsa_key_alloc_pub(MLDSA_KEY *key)
{
    if (key->pub == NULL)
        key->pub = OPENSSL_malloc(key->params->pk_len);
    return key->pub != NULL;
}

int mldsa_key_alloc_priv(MLDSA_KEY *key)
{
    if (key->priv == NULL)
        key->priv = OPENSSL_malloc(key->params->sk_len);
    return key->priv != NULL;
}

int mldsa_key_from_seed(MLDSA_KEY *key)
{
    if (!key->has_seed)
        return 0;
    if (!mldsa_key_alloc_pub(key) || !mldsa_key_alloc_priv(key))
        return 0;
    if (key->params->keypair_internal(key->pub, key->priv, key->seed) != 0)
        return 0;
    key->has_pub = 1;
    key->has_priv = 1;
    return 1;
}

int mldsa_key_pub_from_priv(MLDSA_KEY *key)
{
    if (!key->has_priv)
        return 0;
    if (!mldsa_key_alloc_pub(key))
        return 0;
    if (key->params->pk_from_sk(key->pub, key->priv) != 0)
        return 0;
    key->has_pub = 1;
    return 1;
}

MLDSA_KEY *mldsa_key_dup(const MLDSA_KEY *src)
{
    MLDSA_KEY *dst;

    if (src == NULL)
        return NULL;
    dst = mldsa_key_new(src->libctx, src->propq, src->params);
    if (dst == NULL)
        return NULL;
    if (src->has_pub) {
        if (!mldsa_key_alloc_pub(dst))
            goto err;
        memcpy(dst->pub, src->pub, src->params->pk_len);
        dst->has_pub = 1;
    }
    if (src->has_priv) {
        if (!mldsa_key_alloc_priv(dst))
            goto err;
        memcpy(dst->priv, src->priv, src->params->sk_len);
        dst->has_priv = 1;
    }
    if (src->has_seed) {
        memcpy(dst->seed, src->seed, sizeof(dst->seed));
        dst->has_seed = 1;
    }
    return dst;
 err:
    mldsa_key_free(dst);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* keymgmt dispatch                                                    */
/* ------------------------------------------------------------------ */

static void mldsa_keymgmt_free(void *keydata)
{
    mldsa_key_free(keydata);
}

static int mldsa_has(const void *keydata, int selection)
{
    const MLDSA_KEY *key = keydata;

    if (key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && !key->has_pub)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && !key->has_priv && !key->has_seed)
        return 0;
    return 1;
}

static int mldsa_match(const void *keydata1, const void *keydata2,
                       int selection)
{
    const MLDSA_KEY *k1 = keydata1;
    const MLDSA_KEY *k2 = keydata2;

    if (k1 == NULL || k2 == NULL || k1->params != k2->params)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!k1->has_pub || !k2->has_pub
            || memcmp(k1->pub, k2->pub, k1->params->pk_len) != 0)
            return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (k1->has_priv && k2->has_priv) {
            if (memcmp(k1->priv, k2->priv, k1->params->sk_len) != 0)
                return 0;
        } else if (k1->has_seed && k2->has_seed) {
            if (memcmp(k1->seed, k2->seed, sizeof(k1->seed)) != 0)
                return 0;
        } else {
            return 0;
        }
    }
    return 1;
}

static int mldsa_validate(const void *keydata, int selection)
{
    const MLDSA_KEY *key = keydata;

    if (key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && !key->has_pub)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && !key->has_priv && !key->has_seed)
        return 0;
    return 1;
}

static int mldsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    MLDSA_KEY *key = keydata;
    const OSSL_PARAM *p;

    if (key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || p->data_size != MLDSA_SEED_LEN)
            return 0;
        memcpy(key->seed, p->data, MLDSA_SEED_LEN);
        key->has_seed = 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || p->data_size != key->params->sk_len)
            return 0;
        if (!mldsa_key_alloc_priv(key))
            return 0;
        memcpy(key->priv, p->data, key->params->sk_len);
        key->has_priv = 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || p->data_size != key->params->pk_len)
            return 0;
        if (!mldsa_key_alloc_pub(key))
            return 0;
        memcpy(key->pub, p->data, key->params->pk_len);
        key->has_pub = 1;
    }

    /* Fill in whatever is derivable. */
    if (key->has_seed && (!key->has_priv || !key->has_pub)) {
        if (!mldsa_key_from_seed(key))
            return 0;
    } else if (key->has_priv && !key->has_pub) {
        if (!mldsa_key_pub_from_priv(key))
            return 0;
    }
    return key->has_pub;
}

static int mldsa_export(void *keydata, int selection,
                        OSSL_CALLBACK *param_cb, void *cbarg)
{
    MLDSA_KEY *key = keydata;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_pub) {
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                              key->pub, key->params->pk_len))
            goto err;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (key->has_seed
            && !OSSL_PARAM_BLD_push_octet_string(bld,
                                                 OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                 key->seed, MLDSA_SEED_LEN))
            goto err;
        if (key->has_priv
            && !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                                 key->priv,
                                                 key->params->sk_len))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;
    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
 err:
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

/* import/export negotiate the same octet-string params. */
static const OSSL_PARAM mldsa_key_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mldsa_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return mldsa_key_types;
    return NULL;
}

static const OSSL_PARAM mldsa_gettable[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mldsa_gettable_params(void *provctx)
{
    (void)provctx;
    return mldsa_gettable;
}

static int mldsa_get_params(void *keydata, OSSL_PARAM params[])
{
    MLDSA_KEY *key = keydata;
    OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, (int)(key->params->pk_len * 8)))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, key->params->security_bits))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, (int)key->params->sig_len))
        return 0;
    /* ML-DSA does its own hashing: empty mandatory digest. */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ""))
        return 0;

    /* Raw public key: both PUB_KEY and ENCODED_PUBLIC_KEY are the raw bytes. */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (!key->has_pub
            || !OSSL_PARAM_set_octet_string(p, key->pub, key->params->pk_len))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        if (!key->has_pub
            || !OSSL_PARAM_set_octet_string(p, key->pub, key->params->pk_len))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        if (!key->has_priv
            || !OSSL_PARAM_set_octet_string(p, key->priv, key->params->sk_len))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
    if (p != NULL) {
        if (!key->has_seed
            || !OSSL_PARAM_set_octet_string(p, key->seed, MLDSA_SEED_LEN))
            return 0;
    }
    return 1;
}

/* ---------------- key generation ---------------- */

typedef struct mldsa_gen_ctx_st {
    OSSL_LIB_CTX *libctx;
    const MLDSA_PARAMS *params;
    int selection;
    char *propq;
} MLDSA_GEN_CTX;

static void *mldsa_gen_init_lvl(void *provctx, int selection,
                                const OSSL_PARAM params[],
                                const MLDSA_PARAMS *mp)
{
    MLDSA_GEN_CTX *gctx;

    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;
    gctx->libctx = PROV_MLDSA_LIBCTX(provctx);
    gctx->params = mp;
    gctx->selection = selection;

    if (params != NULL) {
        const OSSL_PARAM *p =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
        if (p != NULL && p->data_type == OSSL_PARAM_UTF8_STRING) {
            gctx->propq = OPENSSL_strdup(p->data);
            if (gctx->propq == NULL) {
                OPENSSL_free(gctx);
                return NULL;
            }
        }
    }
    return gctx;
}

static int mldsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    MLDSA_GEN_CTX *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *mldsa_gen_settable_params(void *genctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    (void)genctx;
    (void)provctx;
    return settable;
}

static void *mldsa_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    MLDSA_GEN_CTX *gctx = genctx;
    MLDSA_KEY *key;

    (void)cb;
    (void)cbarg;
    if (gctx == NULL)
        return NULL;
    key = mldsa_key_new(gctx->libctx, gctx->propq, gctx->params);
    if (key == NULL)
        return NULL;

    /* Public-key-only generation makes no sense; always make a full key. */
    if (randombytes(key->seed, MLDSA_SEED_LEN) != 0) {
        mldsa_key_free(key);
        return NULL;
    }
    key->has_seed = 1;
    if (!mldsa_key_from_seed(key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        mldsa_key_free(key);
        return NULL;
    }
    return key;
}

static void mldsa_gen_cleanup(void *genctx)
{
    MLDSA_GEN_CTX *gctx = genctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static void *mldsa_load(const void *reference, size_t reference_sz)
{
    MLDSA_KEY *key = NULL;

    if (reference_sz == sizeof(key)) {
        key = *(MLDSA_KEY **)reference;
        *(MLDSA_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static void *mldsa_dup(const void *keydata_from, int selection)
{
    (void)selection;
    return mldsa_key_dup(keydata_from);
}

/*
 * Per-level new/gen_init trampolines and dispatch tables. Only "new" and
 * "gen_init" differ between the three parameter sets.
 */
#define MAKE_KEYMGMT(LVL)                                                      \
    static void *mldsa##LVL##_new(void *provctx)                              \
    {                                                                         \
        return mldsa_key_new(PROV_MLDSA_LIBCTX(provctx), NULL,                \
                             &mldsa_params_##LVL);                            \
    }                                                                         \
    static void *mldsa##LVL##_gen_init(void *provctx, int selection,          \
                                       const OSSL_PARAM params[])             \
    {                                                                         \
        return mldsa_gen_init_lvl(provctx, selection, params,                 \
                                  &mldsa_params_##LVL);                       \
    }                                                                         \
    const OSSL_DISPATCH mldsa##LVL##_keymgmt_functions[] = {                  \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))mldsa##LVL##_new },          \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))mldsa_keymgmt_free },       \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))mldsa_has },                 \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))mldsa_match },             \
        { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))mldsa_validate },       \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))mldsa_import },           \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))mldsa_imexport_types },\
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))mldsa_export },           \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))mldsa_imexport_types },\
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))mldsa_get_params },   \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                  \
          (void (*)(void))mldsa_gettable_params },                           \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))mldsa##LVL##_gen_init },\
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                   \
          (void (*)(void))mldsa_gen_set_params },                            \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                              \
          (void (*)(void))mldsa_gen_settable_params },                       \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))mldsa_gen },                 \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))mldsa_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))mldsa_load },               \
        { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))mldsa_dup },                 \
        { 0, NULL }                                                          \
    }

MAKE_KEYMGMT(44);
MAKE_KEYMGMT(65);
MAKE_KEYMGMT(87);
