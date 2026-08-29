/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Provider entry point, algorithm tables and parameter-set descriptions for
 * the mldsa-native ML-DSA provider.
 */

#include <string.h>

#include <openssl/provider.h>
#include <openssl/rand.h>

#include "mldsa_native_prov.h"

/*
 * randombytes() is the entropy hook required by mldsa-native's randomized
 * API (keypair / signature). We back it with OpenSSL's DRBG. This is entropy,
 * not a crypto-primitive delegation: all ML-DSA arithmetic stays in
 * mldsa-native.
 */
int randombytes(uint8_t *out, size_t outlen);
int randombytes(uint8_t *out, size_t outlen)
{
    if (RAND_bytes(out, (int)outlen) <= 0)
        return MLD_ERR_RNG_FAIL;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Parameter-set table                                                 */
/* ------------------------------------------------------------------ */

const MLDSA_PARAMS mldsa_params_44 = {
    44, "ML-DSA-44", "2.16.840.1.101.3.4.3.17",
    MLDSA44_PUBLICKEYBYTES, MLDSA44_SECRETKEYBYTES, MLDSA44_BYTES,
    128, 2,
    mldsa44_keypair_internal, mldsa44_pk_from_sk,
    mldsa44_signature, mldsa44_verify, mldsa44_signature_internal,
    mldsa44_prepare_domain_separation_prefix
};

const MLDSA_PARAMS mldsa_params_65 = {
    65, "ML-DSA-65", "2.16.840.1.101.3.4.3.18",
    MLDSA65_PUBLICKEYBYTES, MLDSA65_SECRETKEYBYTES, MLDSA65_BYTES,
    192, 3,
    mldsa65_keypair_internal, mldsa65_pk_from_sk,
    mldsa65_signature, mldsa65_verify, mldsa65_signature_internal,
    mldsa65_prepare_domain_separation_prefix
};

const MLDSA_PARAMS mldsa_params_87 = {
    87, "ML-DSA-87", "2.16.840.1.101.3.4.3.19",
    MLDSA87_PUBLICKEYBYTES, MLDSA87_SECRETKEYBYTES, MLDSA87_BYTES,
    256, 5,
    mldsa87_keypair_internal, mldsa87_pk_from_sk,
    mldsa87_signature, mldsa87_verify, mldsa87_signature_internal,
    mldsa87_prepare_domain_separation_prefix
};

const MLDSA_PARAMS *mldsa_params_by_level(int level)
{
    switch (level) {
    case 44: return &mldsa_params_44;
    case 65: return &mldsa_params_65;
    case 87: return &mldsa_params_87;
    default: return NULL;
    }
}

const MLDSA_PARAMS *mldsa_params_by_name(const char *name)
{
    if (name == NULL)
        return NULL;
    if (strcasecmp(name, "ML-DSA-44") == 0 || strcasecmp(name, "MLDSA44") == 0
        || strcmp(name, "2.16.840.1.101.3.4.3.17") == 0
        || strcasecmp(name, "id-ml-dsa-44") == 0)
        return &mldsa_params_44;
    if (strcasecmp(name, "ML-DSA-65") == 0 || strcasecmp(name, "MLDSA65") == 0
        || strcmp(name, "2.16.840.1.101.3.4.3.18") == 0
        || strcasecmp(name, "id-ml-dsa-65") == 0)
        return &mldsa_params_65;
    if (strcasecmp(name, "ML-DSA-87") == 0 || strcasecmp(name, "MLDSA87") == 0
        || strcmp(name, "2.16.840.1.101.3.4.3.19") == 0
        || strcasecmp(name, "id-ml-dsa-87") == 0)
        return &mldsa_params_87;
    return NULL;
}

const MLDSA_PARAMS *mldsa_params_by_oid(const char *oid)
{
    if (oid == NULL)
        return NULL;
    if (strcmp(oid, mldsa_params_44.oid) == 0) return &mldsa_params_44;
    if (strcmp(oid, mldsa_params_65.oid) == 0) return &mldsa_params_65;
    if (strcmp(oid, mldsa_params_87.oid) == 0) return &mldsa_params_87;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Algorithm tables                                                    */
/* ------------------------------------------------------------------ */

/* Each name string lists display name : OID alias so fetch-by-OID works. */
#define ALGNAMES_44 "ML-DSA-44:MLDSA44:id-ml-dsa-44:2.16.840.1.101.3.4.3.17"
#define ALGNAMES_65 "ML-DSA-65:MLDSA65:id-ml-dsa-65:2.16.840.1.101.3.4.3.18"
#define ALGNAMES_87 "ML-DSA-87:MLDSA87:id-ml-dsa-87:2.16.840.1.101.3.4.3.19"

static const OSSL_ALGORITHM mldsa_keymgmt[] = {
    { ALGNAMES_44, MLDSANATIVE_PROPS, mldsa44_keymgmt_functions,
      "mldsa-native ML-DSA-44 keymgmt" },
    { ALGNAMES_65, MLDSANATIVE_PROPS, mldsa65_keymgmt_functions,
      "mldsa-native ML-DSA-65 keymgmt" },
    { ALGNAMES_87, MLDSANATIVE_PROPS, mldsa87_keymgmt_functions,
      "mldsa-native ML-DSA-87 keymgmt" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM mldsa_signature[] = {
    { ALGNAMES_44, MLDSANATIVE_PROPS, mldsa_signature_functions,
      "mldsa-native ML-DSA-44 signature" },
    { ALGNAMES_65, MLDSANATIVE_PROPS, mldsa_signature_functions,
      "mldsa-native ML-DSA-65 signature" },
    { ALGNAMES_87, MLDSANATIVE_PROPS, mldsa_signature_functions,
      "mldsa-native ML-DSA-87 signature" },
    { NULL, NULL, NULL, NULL }
};

/* Encoders: structure + output selected via the properties string. */
static const OSSL_ALGORITHM mldsa_encoder[] = {
    { "ML-DSA-44", MLDSANATIVE_PROPS ",output=der,structure=SubjectPublicKeyInfo",
      mldsa44_to_spki_der_encoder_functions, "ML-DSA-44 SPKI DER encoder" },
    { "ML-DSA-44", MLDSANATIVE_PROPS ",output=pem,structure=SubjectPublicKeyInfo",
      mldsa44_to_spki_pem_encoder_functions, "ML-DSA-44 SPKI PEM encoder" },
    { "ML-DSA-44", MLDSANATIVE_PROPS ",output=der,structure=PrivateKeyInfo",
      mldsa44_to_pki_der_encoder_functions, "ML-DSA-44 PKCS8 DER encoder" },
    { "ML-DSA-44", MLDSANATIVE_PROPS ",output=pem,structure=PrivateKeyInfo",
      mldsa44_to_pki_pem_encoder_functions, "ML-DSA-44 PKCS8 PEM encoder" },
    { "ML-DSA-65", MLDSANATIVE_PROPS ",output=der,structure=SubjectPublicKeyInfo",
      mldsa65_to_spki_der_encoder_functions, "ML-DSA-65 SPKI DER encoder" },
    { "ML-DSA-65", MLDSANATIVE_PROPS ",output=pem,structure=SubjectPublicKeyInfo",
      mldsa65_to_spki_pem_encoder_functions, "ML-DSA-65 SPKI PEM encoder" },
    { "ML-DSA-65", MLDSANATIVE_PROPS ",output=der,structure=PrivateKeyInfo",
      mldsa65_to_pki_der_encoder_functions, "ML-DSA-65 PKCS8 DER encoder" },
    { "ML-DSA-65", MLDSANATIVE_PROPS ",output=pem,structure=PrivateKeyInfo",
      mldsa65_to_pki_pem_encoder_functions, "ML-DSA-65 PKCS8 PEM encoder" },
    { "ML-DSA-87", MLDSANATIVE_PROPS ",output=der,structure=SubjectPublicKeyInfo",
      mldsa87_to_spki_der_encoder_functions, "ML-DSA-87 SPKI DER encoder" },
    { "ML-DSA-87", MLDSANATIVE_PROPS ",output=pem,structure=SubjectPublicKeyInfo",
      mldsa87_to_spki_pem_encoder_functions, "ML-DSA-87 SPKI PEM encoder" },
    { "ML-DSA-87", MLDSANATIVE_PROPS ",output=der,structure=PrivateKeyInfo",
      mldsa87_to_pki_der_encoder_functions, "ML-DSA-87 PKCS8 DER encoder" },
    { "ML-DSA-87", MLDSANATIVE_PROPS ",output=pem,structure=PrivateKeyInfo",
      mldsa87_to_pki_pem_encoder_functions, "ML-DSA-87 PKCS8 PEM encoder" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM mldsa_decoder[] = {
    { "ML-DSA-44", MLDSANATIVE_PROPS ",input=der,structure=SubjectPublicKeyInfo",
      mldsa44_spki_der_to_key_decoder_functions, "ML-DSA-44 SPKI DER decoder" },
    { "ML-DSA-44", MLDSANATIVE_PROPS ",input=der,structure=PrivateKeyInfo",
      mldsa44_pki_der_to_key_decoder_functions, "ML-DSA-44 PKCS8 DER decoder" },
    { "ML-DSA-65", MLDSANATIVE_PROPS ",input=der,structure=SubjectPublicKeyInfo",
      mldsa65_spki_der_to_key_decoder_functions, "ML-DSA-65 SPKI DER decoder" },
    { "ML-DSA-65", MLDSANATIVE_PROPS ",input=der,structure=PrivateKeyInfo",
      mldsa65_pki_der_to_key_decoder_functions, "ML-DSA-65 PKCS8 DER decoder" },
    { "ML-DSA-87", MLDSANATIVE_PROPS ",input=der,structure=SubjectPublicKeyInfo",
      mldsa87_spki_der_to_key_decoder_functions, "ML-DSA-87 SPKI DER decoder" },
    { "ML-DSA-87", MLDSANATIVE_PROPS ",input=der,structure=PrivateKeyInfo",
      mldsa87_pki_der_to_key_decoder_functions, "ML-DSA-87 PKCS8 DER decoder" },
    { NULL, NULL, NULL, NULL }
};

/* ------------------------------------------------------------------ */
/* Provider core interface                                             */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM mldsa_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mldsa_gettable_params(void *provctx)
{
    (void)provctx;
    return mldsa_param_types;
}

static int mldsa_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, MLDSANATIVE_PROV_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, MLDSANATIVE_PROV_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, MLDSANATIVE_PROV_VERSION
                                              " [" MLDSANATIVE_BACKEND_STR "]"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM *mldsa_query(void *provctx, int operation_id,
                                         int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return mldsa_keymgmt;
    case OSSL_OP_SIGNATURE:
        return mldsa_signature;
    case OSSL_OP_ENCODER:
        return mldsa_encoder;
    case OSSL_OP_DECODER:
        return mldsa_decoder;
    default:
        return NULL;
    }
}

static void mldsa_teardown(void *provctx)
{
    PROV_MLDSA_CTX *ctx = provctx;

    if (ctx == NULL)
        return;
    OSSL_LIB_CTX_free(ctx->libctx);
    OPENSSL_free(ctx);
}

static const OSSL_DISPATCH mldsa_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))mldsa_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))mldsa_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))mldsa_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))mldsa_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx);
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    PROV_MLDSA_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return 0;
    ctx->handle = handle;
    /* Child libctx so RAND_bytes_ex and any core services resolve. */
    ctx->libctx = OSSL_LIB_CTX_new_child(handle, in);
    if (ctx->libctx == NULL) {
        OPENSSL_free(ctx);
        return 0;
    }
    *provctx = ctx;
    *out = mldsa_dispatch_table;
    return 1;
}
