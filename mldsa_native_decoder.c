/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ML-DSA key decoders (SubjectPublicKeyInfo + PKCS#8 PrivateKeyInfo, DER).
 * PEM inputs are handled by OpenSSL's built-in pem2der decoder, which then
 * feeds our DER decoders. Private-key parsing accepts the seed-priv "both"
 * SEQUENCE (default), a bare 32-byte seed, and a bare expanded key.
 */

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "mldsa_native_prov.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    const MLDSA_PARAMS *params;
    int is_priv;
} MLDSA_DEC_CTX;

static void mldsa_dec_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

/*
 * OSSL_FUNC_decoder_does_selection is called with the *provider* context, not a
 * per-decoder instance context (see collect_decoder() in
 * crypto/encode_decode/decoder_pkey.c). It therefore cannot consult ctx->is_priv
 * to tell the SPKI decoder from the PKCS#8 one -- each structure needs its own
 * function reporting the fixed selection it can produce. Getting this wrong
 * makes the decoder framework silently skip our decoders (no key ever loads).
 */
static int mldsa_dec_does_selection_pub(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int mldsa_dec_does_selection_priv(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

/* Read the entire core BIO into a malloc'd buffer. */
static int read_all(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *cin,
                    unsigned char **out, long *outlen)
{
    BIO *in = BIO_new_from_core_bio(libctx, cin);
    unsigned char *buf = NULL, *tmp;
    size_t cap = 4096, len = 0;
    int n, ok = 0;

    if (in == NULL)
        return 0;
    buf = OPENSSL_malloc(cap);
    if (buf == NULL)
        goto end;
    for (;;) {
        if (len == cap) {
            if (cap > (size_t)1 << 24)      /* 16 MiB sanity cap */
                goto end;
            tmp = OPENSSL_realloc(buf, cap * 2);
            if (tmp == NULL)
                goto end;
            buf = tmp;
            cap *= 2;
        }
        n = BIO_read(in, buf + len, (int)(cap - len));
        if (n <= 0)
            break;
        len += (size_t)n;
    }
    *out = buf;
    *outlen = (long)len;
    buf = NULL;
    ok = 1;
 end:
    OPENSSL_free(buf);
    BIO_free(in);
    return ok;
}

static int oid_matches(const ASN1_OBJECT *obj, const MLDSA_PARAMS *mp)
{
    char buf[80];

    if (OBJ_obj2txt(buf, sizeof(buf), obj, 1) <= 0)
        return 0;
    return strcmp(buf, mp->oid) == 0;
}

/*
 * Parse the SubjectPublicKeyInfo by hand rather than via d2i_X509_PUBKEY.
 *
 * On OpenSSL 3.x the X509_PUBKEY ASN.1 template carries an "ex" d2i callback
 * (x509_pubkey_ex_d2i_ex) that eagerly runs the OSSL_DECODER machinery to build
 * an EVP_PKEY. Calling d2i_X509_PUBKEY from inside our own decoder would re-enter
 * that machinery for the same keytype+structure, invoking this decoder again and
 * recursing without bound (stack overflow). Manual parsing avoids the re-entry.
 *
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *       algorithm         SEQUENCE { OBJECT IDENTIFIER, ... },
 *       subjectPublicKey  BIT STRING }   -- 0 unused bits, then the raw key
 */
static MLDSA_KEY *decode_spki(MLDSA_DEC_CTX *ctx, const unsigned char *der,
                              long derlen)
{
    const unsigned char *p = der, *end = der + derlen, *alg_end;
    ASN1_OBJECT *obj = NULL;
    MLDSA_KEY *key = NULL;
    long len;
    int tag, xclass, hdr;

    /* outer SEQUENCE */
    hdr = ASN1_get_object(&p, &len, &tag, &xclass, end - p);
    if ((hdr & 0x80) || tag != V_ASN1_SEQUENCE || xclass != V_ASN1_UNIVERSAL)
        return NULL;
    end = p + len;                       /* confine to the SPKI contents */

    /* algorithm SEQUENCE */
    hdr = ASN1_get_object(&p, &len, &tag, &xclass, end - p);
    if ((hdr & 0x80) || tag != V_ASN1_SEQUENCE || xclass != V_ASN1_UNIVERSAL)
        return NULL;
    alg_end = p + len;
    obj = d2i_ASN1_OBJECT(NULL, &p, alg_end - p);
    if (obj == NULL)
        return NULL;
    p = alg_end;                         /* skip any AlgorithmIdentifier params */

    /* subjectPublicKey BIT STRING */
    hdr = ASN1_get_object(&p, &len, &tag, &xclass, end - p);
    if ((hdr & 0x80) || tag != V_ASN1_BIT_STRING || xclass != V_ASN1_UNIVERSAL
        || len < 1 || *p != 0x00)        /* first octet = unused-bit count = 0 */
        goto end;
    p++;
    len--;

    if (!oid_matches(obj, ctx->params) || (size_t)len != ctx->params->pk_len)
        goto end;
    key = mldsa_key_new(ctx->libctx, NULL, ctx->params);
    if (key == NULL)
        goto end;
    key->pub = OPENSSL_memdup(p, (size_t)len);
    if (key->pub == NULL) {
        mldsa_key_free(key);
        key = NULL;
        goto end;
    }
    key->has_pub = 1;
 end:
    ASN1_OBJECT_free(obj);
    return key;
}

static MLDSA_KEY *decode_pki(MLDSA_DEC_CTX *ctx, const unsigned char *der,
                             long derlen)
{
    const unsigned char *p = der;
    PKCS8_PRIV_KEY_INFO *p8;
    const ASN1_OBJECT *obj = NULL;
    const unsigned char *pk = NULL;
    int pklen = 0;
    const X509_ALGOR *palg = NULL;
    MLDSA_KEY *key = NULL;
    const MLDSA_PARAMS *mp = ctx->params;

    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, derlen);
    if (p8 == NULL)
        return NULL;
    if (!PKCS8_pkey_get0(&obj, &pk, &pklen, &palg, p8))
        goto end;
    if (!oid_matches(obj, mp))
        goto end;

    key = mldsa_key_new(ctx->libctx, NULL, mp);
    if (key == NULL)
        goto end;

    /*
     * The privateKey OCTET STRING content is the DER of the ML-DSA private-key
     * CHOICE (draft-ietf-lamps-dilithium-certificates):
     *   both        SEQUENCE { OCTET STRING seed(32), OCTET STRING expandedKey }
     *   seed        [0] OCTET STRING (32)            (context tag 0x80)
     *   expandedKey OCTET STRING (sk_len)            (0x04 wrapper)
     * plus tolerated bare (unwrapped) seed / expandedKey.
     */
    {
        const unsigned char *q = pk;
        long len;
        int tag, xclass, hdr;

        hdr = ASN1_get_object(&q, &len, &tag, &xclass, pklen);
        if (!(hdr & 0x80)) {
            if (xclass == V_ASN1_CONTEXT_SPECIFIC && tag == 0
                && len == MLDSA_SEED_LEN) {
                /* seed [0] */
                memcpy(key->seed, q, MLDSA_SEED_LEN);
                key->has_seed = 1;
            } else if (xclass == V_ASN1_UNIVERSAL && tag == V_ASN1_SEQUENCE) {
                /* both */
                ASN1_OCTET_STRING *o_seed =
                    d2i_ASN1_OCTET_STRING(NULL, &q, (pk + pklen) - q);
                ASN1_OCTET_STRING *o_priv =
                    d2i_ASN1_OCTET_STRING(NULL, &q, (pk + pklen) - q);

                if (o_seed != NULL
                    && ASN1_STRING_length(o_seed) == MLDSA_SEED_LEN) {
                    memcpy(key->seed, ASN1_STRING_get0_data(o_seed),
                           MLDSA_SEED_LEN);
                    key->has_seed = 1;
                }
                if (o_priv != NULL
                    && (size_t)ASN1_STRING_length(o_priv) == mp->sk_len
                    && mldsa_key_alloc_priv(key)) {
                    memcpy(key->priv, ASN1_STRING_get0_data(o_priv),
                           mp->sk_len);
                    key->has_priv = 1;
                }
                ASN1_OCTET_STRING_free(o_seed);
                ASN1_OCTET_STRING_free(o_priv);
            } else if (xclass == V_ASN1_UNIVERSAL
                       && tag == V_ASN1_OCTET_STRING) {
                /* expandedKey (or a seed) wrapped in an OCTET STRING */
                if ((size_t)len == mp->sk_len && mldsa_key_alloc_priv(key)) {
                    memcpy(key->priv, q, mp->sk_len);
                    key->has_priv = 1;
                } else if (len == MLDSA_SEED_LEN) {
                    memcpy(key->seed, q, MLDSA_SEED_LEN);
                    key->has_seed = 1;
                }
            }
        }
        /* Bare (unwrapped) fallbacks. */
        if (!key->has_seed && !key->has_priv) {
            if ((size_t)pklen == MLDSA_SEED_LEN) {
                memcpy(key->seed, pk, MLDSA_SEED_LEN);
                key->has_seed = 1;
            } else if ((size_t)pklen == mp->sk_len
                       && mldsa_key_alloc_priv(key)) {
                memcpy(key->priv, pk, mp->sk_len);
                key->has_priv = 1;
            }
        }
    }

    /* Derive whatever is missing. */
    if (key->has_seed && (!key->has_priv || !key->has_pub)) {
        if (!mldsa_key_from_seed(key))
            goto fail;
    } else if (key->has_priv && !key->has_pub) {
        if (!mldsa_key_pub_from_priv(key))
            goto fail;
    }
    if (!key->has_pub)
        goto fail;
    goto end;
 fail:
    mldsa_key_free(key);
    key = NULL;
 end:
    PKCS8_PRIV_KEY_INFO_free(p8);
    return key;
}

static int mldsa_dec_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                            OSSL_CALLBACK *data_cb, void *data_cbarg,
                            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    MLDSA_DEC_CTX *ctx = vctx;
    unsigned char *der = NULL;
    long derlen = 0;
    MLDSA_KEY *key = NULL;
    int ok = 1;                 /* 1 = no fatal error (may produce nothing) */

    (void)pw_cb;
    (void)pw_cbarg;
    (void)selection;

    if (!read_all(ctx->libctx, cin, &der, &derlen))
        return 0;
    if (derlen <= 0) {
        OPENSSL_free(der);
        return 1;
    }

    key = ctx->is_priv ? decode_pki(ctx, der, derlen)
                       : decode_spki(ctx, der, derlen);
    OPENSSL_free(der);
    if (key == NULL)
        return 1;               /* not ours: let another decoder try */

    {
        int object_type = OSSL_OBJECT_PKEY;
        OSSL_PARAM params[4];

        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE,
                                             &object_type);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char *)ctx->params->name, 0);
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();
        ok = data_cb(params, data_cbarg);
    }
    /* If load consumed the reference, key is NULL; otherwise free it. */
    mldsa_key_free(key);
    return ok;
}

#define MAKE_DECODERS(LVL)                                                    \
    static void *mldsa##LVL##_spki_dec_newctx(void *provctx)                 \
    {                                                                        \
        MLDSA_DEC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));                    \
        if (ctx != NULL) {                                                   \
            ctx->libctx = PROV_MLDSA_LIBCTX(provctx);                        \
            ctx->params = &mldsa_params_##LVL;                              \
            ctx->is_priv = 0;                                               \
        }                                                                    \
        return ctx;                                                          \
    }                                                                        \
    static void *mldsa##LVL##_pki_dec_newctx(void *provctx)                  \
    {                                                                        \
        MLDSA_DEC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));                    \
        if (ctx != NULL) {                                                   \
            ctx->libctx = PROV_MLDSA_LIBCTX(provctx);                        \
            ctx->params = &mldsa_params_##LVL;                              \
            ctx->is_priv = 1;                                               \
        }                                                                    \
        return ctx;                                                          \
    }                                                                        \
    const OSSL_DISPATCH mldsa##LVL##_spki_der_to_key_decoder_functions[] = {  \
        { OSSL_FUNC_DECODER_NEWCTX,                                           \
          (void (*)(void))mldsa##LVL##_spki_dec_newctx },                    \
        { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))mldsa_dec_freectx },     \
        { OSSL_FUNC_DECODER_DOES_SELECTION,                                   \
          (void (*)(void))mldsa_dec_does_selection_pub },                    \
        { OSSL_FUNC_DECODER_DECODE, (void (*)(void))mldsa_dec_decode },       \
        { 0, NULL }                                                          \
    };                                                                       \
    const OSSL_DISPATCH mldsa##LVL##_pki_der_to_key_decoder_functions[] = {   \
        { OSSL_FUNC_DECODER_NEWCTX,                                           \
          (void (*)(void))mldsa##LVL##_pki_dec_newctx },                     \
        { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))mldsa_dec_freectx },     \
        { OSSL_FUNC_DECODER_DOES_SELECTION,                                   \
          (void (*)(void))mldsa_dec_does_selection_priv },                        \
        { OSSL_FUNC_DECODER_DECODE, (void (*)(void))mldsa_dec_decode },       \
        { 0, NULL }                                                          \
    }

MAKE_DECODERS(44);
MAKE_DECODERS(65);
MAKE_DECODERS(87);
