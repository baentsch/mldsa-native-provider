/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ML-DSA key encoders (SubjectPublicKeyInfo + PKCS#8 PrivateKeyInfo, DER+PEM).
 *
 * The byte layout matches the OpenSSL default provider:
 *   - SPKI: BIT STRING carries the raw public key; AlgId params absent.
 *   - PKCS#8: privateKey OCTET STRING wraps
 *       SEQUENCE { OCTET STRING seed(32), OCTET STRING expandedKey } ("both").
 */

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

#include "mldsa_native_prov.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
} MLDSA_ENC_CTX;

static void *mldsa_enc_newctx(void *provctx)
{
    MLDSA_ENC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->libctx = PROV_MLDSA_LIBCTX(provctx);
    return ctx;
}

static void mldsa_enc_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

/* Build SubjectPublicKeyInfo DER for key. Returns len, *der malloc'd. */
static int mldsa_encode_spki(const MLDSA_KEY *key, unsigned char **der)
{
    ASN1_OBJECT *obj;
    X509_PUBKEY *xpk;
    unsigned char *penc;
    int derlen = -1;

    if (!key->has_pub)
        return -1;
    obj = OBJ_txt2obj(key->params->oid, 1);
    if (obj == NULL)
        return -1;
    xpk = X509_PUBKEY_new();
    penc = OPENSSL_memdup(key->pub, key->params->pk_len);
    if (xpk == NULL || penc == NULL) {
        ASN1_OBJECT_free(obj);
        OPENSSL_free(penc);
        X509_PUBKEY_free(xpk);
        return -1;
    }
    /* Takes ownership of obj and penc. */
    if (!X509_PUBKEY_set0_param(xpk, obj, V_ASN1_UNDEF, NULL, penc,
                                (int)key->params->pk_len)) {
        X509_PUBKEY_free(xpk);
        return -1;
    }
    derlen = i2d_X509_PUBKEY(xpk, der);
    X509_PUBKEY_free(xpk);
    return derlen;
}

/* DER-encode SEQUENCE { OCTET STRING a, OCTET STRING b }. */
static int mldsa_encode_both_seq(const uint8_t *a, size_t alen,
                                 const uint8_t *b, size_t blen,
                                 unsigned char **out)
{
    ASN1_OCTET_STRING *oa = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING *ob = ASN1_OCTET_STRING_new();
    unsigned char *da = NULL, *db = NULL, *seq = NULL, *p;
    int la = -1, lb = -1, total = -1;

    if (oa == NULL || ob == NULL)
        goto err;
    if (!ASN1_OCTET_STRING_set(oa, a, (int)alen)
        || !ASN1_OCTET_STRING_set(ob, b, (int)blen))
        goto err;
    la = i2d_ASN1_OCTET_STRING(oa, &da);
    lb = i2d_ASN1_OCTET_STRING(ob, &db);
    if (la <= 0 || lb <= 0)
        goto err;

    total = ASN1_object_size(1, la + lb, V_ASN1_SEQUENCE);
    if (total <= 0)
        goto err;
    seq = OPENSSL_malloc((size_t)total);
    if (seq == NULL) {
        total = -1;
        goto err;
    }
    p = seq;
    ASN1_put_object(&p, 1, la + lb, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    memcpy(p, da, (size_t)la);
    memcpy(p + la, db, (size_t)lb);
    *out = seq;
 err:
    OPENSSL_free(da);
    OPENSSL_free(db);
    ASN1_OCTET_STRING_free(oa);
    ASN1_OCTET_STRING_free(ob);
    return total;
}

/* Build PKCS#8 PrivateKeyInfo DER (seed-priv "both" form). */
static int mldsa_encode_pki(const MLDSA_KEY *key, unsigned char **der)
{
    PKCS8_PRIV_KEY_INFO *p8;
    ASN1_OBJECT *obj;
    unsigned char *inner = NULL;
    int innerlen, derlen = -1;

    if (!key->has_priv || !key->has_seed)
        return -1;
    innerlen = mldsa_encode_both_seq(key->seed, MLDSA_SEED_LEN,
                                     key->priv, key->params->sk_len, &inner);
    if (innerlen <= 0)
        return -1;
    obj = OBJ_txt2obj(key->params->oid, 1);
    p8 = PKCS8_PRIV_KEY_INFO_new();
    if (obj == NULL || p8 == NULL) {
        ASN1_OBJECT_free(obj);
        PKCS8_PRIV_KEY_INFO_free(p8);
        OPENSSL_free(inner);
        return -1;
    }
    /* Takes ownership of obj and inner. */
    if (!PKCS8_pkey_set0(p8, obj, 0, V_ASN1_UNDEF, NULL, inner, innerlen)) {
        PKCS8_PRIV_KEY_INFO_free(p8);
        OPENSSL_free(inner);
        return -1;
    }
    derlen = i2d_PKCS8_PRIV_KEY_INFO(p8, der);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return derlen;
}

static int mldsa_do_encode(MLDSA_ENC_CTX *ctx, OSSL_CORE_BIO *cout,
                           const MLDSA_KEY *key, int is_priv, int is_pem)
{
    BIO *out;
    unsigned char *der = NULL;
    int derlen;
    int ret = 0;

    if (key == NULL)
        return 0;
    derlen = is_priv ? mldsa_encode_pki(key, &der)
                     : mldsa_encode_spki(key, &der);
    if (derlen <= 0)
        return 0;

    out = BIO_new_from_core_bio(ctx->libctx, cout);
    if (out == NULL)
        goto end;
    if (is_pem) {
        ret = PEM_write_bio(out, is_priv ? "PRIVATE KEY" : "PUBLIC KEY", "",
                            der, (long)derlen) > 0;
    } else {
        ret = BIO_write(out, der, derlen) == derlen;
    }
    BIO_free(out);
 end:
    OPENSSL_clear_free(der, (size_t)derlen);
    return ret;
}

static int mldsa_enc_spki_does_selection(void *ctx, int selection)
{
    (void)ctx;
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int mldsa_enc_pki_does_selection(void *ctx, int selection)
{
    (void)ctx;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

#define MAKE_ENCODE_FN(KIND, IS_PRIV, IS_PEM)                                  \
    static int mldsa_encode_##KIND(void *vctx, OSSL_CORE_BIO *cout,           \
                                   const void *key,                          \
                                   const OSSL_PARAM key_abstract[],          \
                                   int selection, OSSL_PASSPHRASE_CALLBACK *cb,\
                                   void *cbarg)                              \
    {                                                                        \
        (void)selection;                                                     \
        (void)cb;                                                            \
        (void)cbarg;                                                         \
        if (key_abstract != NULL)                                            \
            return 0;                                                        \
        return mldsa_do_encode((MLDSA_ENC_CTX *)vctx, cout,                  \
                               (const MLDSA_KEY *)key, IS_PRIV, IS_PEM);     \
    }

MAKE_ENCODE_FN(spki_der, 0, 0)
MAKE_ENCODE_FN(spki_pem, 0, 1)
MAKE_ENCODE_FN(pki_der, 1, 0)
MAKE_ENCODE_FN(pki_pem, 1, 1)

#define ENC_TABLE(NAME, DOES, ENCFN)                                          \
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))mldsa_enc_newctx },           \
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))mldsa_enc_freectx },         \
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))DOES },               \
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))ENCFN },                      \
    { 0, NULL }

/* All levels share the encode functions (the key object carries params). */
#define MAKE_ENCODERS(LVL)                                                    \
    const OSSL_DISPATCH mldsa##LVL##_to_spki_der_encoder_functions[] = {      \
        ENC_TABLE(0, mldsa_enc_spki_does_selection, mldsa_encode_spki_der) }; \
    const OSSL_DISPATCH mldsa##LVL##_to_spki_pem_encoder_functions[] = {      \
        ENC_TABLE(0, mldsa_enc_spki_does_selection, mldsa_encode_spki_pem) }; \
    const OSSL_DISPATCH mldsa##LVL##_to_pki_der_encoder_functions[] = {       \
        ENC_TABLE(0, mldsa_enc_pki_does_selection, mldsa_encode_pki_der) };   \
    const OSSL_DISPATCH mldsa##LVL##_to_pki_pem_encoder_functions[] = {       \
        ENC_TABLE(0, mldsa_enc_pki_does_selection, mldsa_encode_pki_pem) }

MAKE_ENCODERS(44);
MAKE_ENCODERS(65);
MAKE_ENCODERS(87);
